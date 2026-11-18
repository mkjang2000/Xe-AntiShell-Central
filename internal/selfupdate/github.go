package selfupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/githubrelease"
)

const githubRepository = "mkjang2000/Xe-AntiShell-Central"
const githubAPI = "https://api.github.com/repos/" + githubRepository + "/releases"

var errTarget = errors.New("no signed central RPM for the requested tag and platform")

type Release struct {
	Tag      string `json:"tag"`
	Artifact string `json:"artifact"`
}

type githubAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
type githubRelease struct {
	Tag        string        `json:"tag_name"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

func (r githubRelease) target(major string) (Release, int64, bool) {
	name, err := rpmName(r.Tag, major)
	if err != nil || r.Draft || r.Prerelease {
		return Release{}, 0, false
	}
	var rpmSize, manifestSize int64
	for _, asset := range r.Assets {
		switch asset.Name {
		case name:
			if rpmSize != 0 || asset.Size < 1 || asset.Size > MaxRPMBytes {
				return Release{}, 0, false
			}
			rpmSize = asset.Size
		case name + ".manifest.json":
			if manifestSize != 0 || asset.Size < 1 || asset.Size > MaxManifestBytes {
				return Release{}, 0, false
			}
			manifestSize = asset.Size
		}
	}
	return Release{Tag: r.Tag, Artifact: name}, rpmSize, rpmSize > 0 && manifestSize > 0
}

func LocalOSMajor() (string, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", errTarget
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	return parseOSRelease(string(data))
}
func parseOSRelease(data string) (string, error) {
	var id, like, major string
	for _, line := range strings.Split(data, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "\"'")
		switch key {
		case "ID":
			id = value
		case "ID_LIKE":
			like = value
		case "VERSION_ID":
			major, _, _ = strings.Cut(value, ".")
		}
	}
	compatible := false
	for _, family := range strings.Fields(id + " " + like) {
		switch family {
		case "rhel", "centos", "rocky", "almalinux", "ol":
			compatible = true
		}
	}
	if !compatible || (major != "9" && major != "10") {
		return "", errTarget
	}
	return major, nil
}

var publicClient = githubrelease.NewHTTPClient()

func ListReleases(ctx context.Context) ([]Release, error) {
	major, err := LocalOSMajor()
	if err != nil {
		return nil, err
	}
	return listReleases(ctx, publicClient, major)
}

func listReleases(ctx context.Context, client *http.Client, major string) ([]Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var rows []githubRelease
	if err := githubrelease.JSON(ctx, client, githubAPI+"?per_page=30", 2<<20, &rows); err != nil {
		return nil, err
	}
	out := []Release{}
	for _, row := range rows {
		if r, _, ok := row.target(major); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func GithubDownload(ctx context.Context, tag string) (SignedManifest, io.ReadCloser, error) {
	major, err := LocalOSMajor()
	if err != nil {
		return SignedManifest{}, nil, err
	}
	return download(ctx, publicClient, tag, major, DecodeManifest)
}

var centralRPMName = regexp.MustCompile(`^xe-antishell-central-([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)\.el(9|10)\.x86_64\.rpm$`)

// GithubManifestForRPM fetches the signed sidecar for an uploaded RPM, without
// fetching the package itself. The input is only a canonical local asset name.
func GithubManifestForRPM(ctx context.Context, artifactName string) (SignedManifest, error) {
	major, err := LocalOSMajor()
	if err != nil {
		return SignedManifest{}, err
	}
	return githubManifestForRPM(ctx, publicClient, artifactName, major, DecodeManifest)
}
func githubManifestForRPM(ctx context.Context, client *http.Client, name, major string, decode func([]byte) (SignedManifest, error)) (SignedManifest, error) {
	if len(name) > 160 {
		return SignedManifest{}, errTarget
	}
	parts := centralRPMName.FindStringSubmatch(name)
	if len(parts) != 4 || parts[3] != major {
		return SignedManifest{}, errTarget
	}
	tag := "v" + parts[1] + "-r" + parts[2]
	canonical, err := rpmName(tag, major)
	if err != nil || canonical != name {
		return SignedManifest{}, errTarget
	}
	return downloadManifest(ctx, client, tag, major, decode)
}

func downloadManifest(ctx context.Context, client *http.Client, tag, major string, decode func([]byte) (SignedManifest, error)) (SignedManifest, error) {
	var empty SignedManifest
	if !releaseTag.MatchString(tag) {
		return empty, errTarget
	}
	var row githubRelease
	if err := githubrelease.JSON(ctx, client, githubAPI+"/tags/"+tag, 2<<20, &row); err != nil {
		return empty, err
	}
	r, rpmSize, ok := row.target(major)
	if !ok || r.Tag != tag {
		return empty, errTarget
	}
	url := "https://github.com/" + githubRepository + "/releases/download/" + tag + "/" + r.Artifact
	response, err := githubrelease.Get(ctx, client, url+".manifest.json")
	if err != nil {
		return empty, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxManifestBytes+1))
	if err != nil || len(body) > MaxManifestBytes {
		return empty, errManifest
	}
	signed, err := decode(body)
	if err != nil {
		return empty, err
	}
	m := signed.Manifest
	if m.Tag != tag || m.ArtifactName != r.Artifact || m.OSMajor != major || m.Size != rpmSize {
		return empty, errTarget
	}
	return signed, nil
}

func download(ctx context.Context, client *http.Client, tag, major string, decode func([]byte) (SignedManifest, error)) (SignedManifest, io.ReadCloser, error) {
	var empty SignedManifest
	signed, err := downloadManifest(ctx, client, tag, major, decode)
	if err != nil {
		return empty, nil, err
	}
	m := signed.Manifest
	url := "https://github.com/" + githubRepository + "/releases/download/" + tag + "/" + m.ArtifactName
	rpm, err := githubrelease.Get(ctx, client, url)
	if err != nil {
		return empty, nil, err
	}
	if rpm.ContentLength >= 0 && rpm.ContentLength != m.Size {
		rpm.Body.Close()
		return empty, nil, errRPM
	}
	return signed, struct {
		io.Reader
		io.Closer
	}{io.LimitReader(rpm.Body, m.Size+1), rpm.Body}, nil
}
