package central

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/githubrelease"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

var updateGitHubTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
var updateGitHubManifestName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,220}\.rpm\.manifest\.json$`)

type updateGitHubAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}
type updateGitHubRelease struct {
	TagName     string              `json:"tag_name"`
	Name        string              `json:"name"`
	PublishedAt time.Time           `json:"published_at"`
	Draft       bool                `json:"draft"`
	Prerelease  bool                `json:"prerelease"`
	Assets      []updateGitHubAsset `json:"assets"`
}
type updateGitHubItem struct {
	Tag            string              `json:"tag"`
	Name           string              `json:"name"`
	PublishedAt    time.Time           `json:"published_at"`
	Prerelease     bool                `json:"prerelease"`
	ManifestAssets []updateGitHubAsset `json:"manifest_assets"`
}
type updateGitHubCatalog struct {
	Repository string             `json:"repository"`
	FetchedAt  time.Time          `json:"fetched_at"`
	Items      []updateGitHubItem `json:"items"`
}

func (c *updateGitHubClient) catalog(ctx context.Context) (updateGitHubCatalog, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cached.FetchedAt.IsZero() && c.now().Sub(c.cached.FetchedAt) < 5*time.Minute {
		return c.cached, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var releases []updateGitHubRelease
	if err := c.json(ctx, updateGitHubAPI+"?per_page=20", 2<<20, &releases); err != nil {
		return updateGitHubCatalog{}, err
	}
	catalog := updateGitHubCatalog{Repository: updateGitHubRepository, FetchedAt: c.now().UTC(), Items: []updateGitHubItem{}}
	for _, release := range releases {
		if len(catalog.Items) >= 20 {
			break
		}
		if release.Draft || !updateGitHubTag.MatchString(release.TagName) || len(release.TagName) > 128 || len(release.Name) > 256 {
			continue
		}
		item := updateGitHubItem{Tag: release.TagName, Name: release.Name, PublishedAt: release.PublishedAt, Prerelease: release.Prerelease, ManifestAssets: []updateGitHubAsset{}}
		for _, asset := range release.Assets {
			if len(item.ManifestAssets) >= 32 {
				break
			}
			if updateGitHubManifestName.MatchString(asset.Name) && asset.Size > 0 && asset.Size <= managed.MaxReleaseManifestBytes {
				item.ManifestAssets = append(item.ManifestAssets, asset)
			}
		}
		if len(item.ManifestAssets) > 0 {
			slices.SortFunc(item.ManifestAssets, func(a, b updateGitHubAsset) int {
				return cmp.Or(compareRPMComponent(a.Name, b.Name), strings.Compare(a.Name, b.Name), cmp.Compare(a.Size, b.Size))
			})
			catalog.Items = append(catalog.Items, item)
		}
	}
	slices.SortFunc(catalog.Items, func(a, b updateGitHubItem) int {
		return cmp.Or(githubrelease.ComparePackageTags(b.Tag, a.Tag), b.PublishedAt.Compare(a.PublishedAt), strings.Compare(a.Tag, b.Tag))
	})
	c.cached = catalog
	return catalog, nil
}

func updateGitHubAssetURL(tag, name string) string {
	return "https://github.com/" + updateGitHubRepository + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(name)
}

func (s *Server) importUpdateGitHub(ctx context.Context, tag, name, actor string) (ConsoleUpdateRelease, bool, error) {
	if !updateGitHubTag.MatchString(tag) || len(tag) > 128 || !updateGitHubManifestName.MatchString(name) {
		return ConsoleUpdateRelease{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var release updateGitHubRelease
	if err := s.updateGitHub.json(ctx, updateGitHubAPI+"/tags/"+url.PathEscape(tag), 2<<20, &release); err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	if release.Draft || release.TagName != tag {
		return ConsoleUpdateRelease{}, false, ErrInvalid
	}
	found := false
	for _, asset := range release.Assets {
		if asset.Name == name && asset.Size > 0 && asset.Size <= managed.MaxReleaseManifestBytes {
			if found {
				return ConsoleUpdateRelease{}, false, ErrInvalid
			}
			found = true
		}
	}
	if !found {
		return ConsoleUpdateRelease{}, false, ErrNotFound
	}
	var publisher managed.SignedReleaseManifest
	var manifestBody json.RawMessage
	if err := s.updateGitHub.json(ctx, updateGitHubAssetURL(tag, name), managed.MaxReleaseManifestBytes, &manifestBody); err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	if managed.DecodeStrict(manifestBody, managed.MaxReleaseManifestBytes, &publisher) != nil {
		return ConsoleUpdateRelease{}, false, ErrInvalid
	}
	if err := s.verifyUpdatePublisher(publisher); err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	found = false
	for _, asset := range release.Assets {
		if asset.Name == publisher.Manifest.ArtifactName && asset.Size == publisher.Manifest.Size {
			if found {
				return ConsoleUpdateRelease{}, false, ErrInvalid
			}
			found = true
		}
	}
	if !found || name != publisher.Manifest.ArtifactName+".manifest.json" {
		return ConsoleUpdateRelease{}, false, ErrInvalid
	}
	response, err := s.updateGitHub.get(ctx, updateGitHubAssetURL(tag, publisher.Manifest.ArtifactName))
	if err != nil {
		return ConsoleUpdateRelease{}, false, err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != publisher.Manifest.Size {
		return ConsoleUpdateRelease{}, false, ErrInvalid
	}
	return s.publishUpdateRelease(ctx, response.Body, actor, publisher)
}

func (s *Server) consoleUpdateGitHubReleases(w http.ResponseWriter, r *http.Request) {
	if _, ok := updateConsoleActor(w, r); !ok {
		return
	}
	catalog, err := s.updateGitHub.catalog(r.Context())
	if err != nil {
		respond(w, http.StatusBadGateway, map[string]string{"error": "공개 GitHub 릴리스 정보를 확인하지 못했습니다. 잠시 후 다시 시도하세요"})
		return
	}
	respond(w, http.StatusOK, catalog)
}
func (s *Server) consoleImportUpdateGitHub(w http.ResponseWriter, r *http.Request) {
	actor, ok := updateConsoleActor(w, r)
	if !ok {
		return
	}
	var request struct {
		Tag           string `json:"tag"`
		ManifestAsset string `json:"manifest_asset"`
	}
	if !consoleDecode(w, r, 4096, &request) {
		return
	}
	select {
	case s.updateBlobs.upload <- struct{}{}:
		defer func() { <-s.updateBlobs.upload }()
	default:
		respond(w, http.StatusTooManyRequests, map[string]string{"error": "다른 릴리스 등록이 진행 중입니다"})
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.consoleError(w, "GitHub transfer deadline", err)
		return
	}
	release, duplicate, err := s.importUpdateGitHub(r.Context(), request.Tag, request.ManifestAsset, actor)
	if err != nil {
		if errors.Is(err, errUpdateGitHub) {
			respond(w, http.StatusBadGateway, map[string]string{"error": "공개 GitHub 릴리스를 가져오지 못했습니다. 잠시 후 다시 시도하세요"})
			return
		}
		s.consoleError(w, "GitHub release import", err)
		return
	}
	status := http.StatusCreated
	if duplicate {
		status = http.StatusOK
	}
	respond(w, status, map[string]any{"release": release, "duplicate": duplicate})
}
