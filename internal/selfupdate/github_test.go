package selfupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func assetResponse(body []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}
}

func TestGitHubReleaseDiscoveryAndDownload(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureManifest()
	payload := []byte("test bytes; simulate the RPM response")
	digest := sha256.Sum256(payload)
	m.SHA256 = hex.EncodeToString(digest[:])
	m.Size = int64(len(payload))
	s, err := SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(s)
	row := githubRelease{Tag: m.Tag, Assets: []githubAsset{{m.ArtifactName, m.Size}, {m.ArtifactName + ".manifest.json", int64(len(envelope))}}}
	url := "https://github.com/" + githubRepository + "/releases/download/" + m.Tag + "/" + m.ArtifactName
	var rpmReads int
	client := &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("credentials forwarded")
		}
		switch r.URL.String() {
		case githubAPI + "?per_page=30":
			draft := row
			draft.Draft = true
			old := row
			old.Assets = old.Assets[:1]
			alpha := row
			alpha.Prerelease = true
			a, _ := json.Marshal([]githubRelease{draft, old, alpha, row})
			return assetResponse(a), nil
		case githubAPI + "/tags/" + m.Tag:
			a, _ := json.Marshal(row)
			return assetResponse(a), nil
		case url + ".manifest.json":
			return assetResponse(envelope), nil
		case url:
			rpmReads++
			return assetResponse(payload), nil
		default:
			return nil, fmt.Errorf("unexpected URL")
		}
	})}
	releases, err := listReleases(ctx, client, "9")
	if err != nil || len(releases) != 1 || releases[0].Tag != m.Tag || releases[0].Artifact != m.ArtifactName {
		t.Fatalf("unexpected catalog %#v %v", releases, err)
	}
	if releases, err = listReleases(ctx, client, "10"); err != nil || len(releases) != 0 {
		t.Fatalf("wrong platform catalog: %v %v", releases, err)
	}
	if _, _, err := download(ctx, client, m.Tag, "9", DecodeManifest); err == nil || rpmReads != 0 {
		t.Fatal("untrusted manifest fetched package")
	}
	decode := func(data []byte) (SignedManifest, error) {
		var signed SignedManifest
		if err := json.Unmarshal(data, &signed); err != nil {
			return signed, err
		}
		return signed, verifyManifest(signed, map[string]ed25519.PublicKey{s.KeyID: pub})
	}
	gotManifest, err := githubManifestForRPM(ctx, client, m.ArtifactName, "9", decode)
	if err != nil || gotManifest != s || rpmReads != 0 {
		t.Fatalf("expected metadata and signature only: %v", err)
	}
	for _, bad := range []string{"../../" + m.ArtifactName, "xe-antishell-central-0.1.0-20.el10.x86_64.rpm", "xe-antishell-central-0.1.0-020.el9.x86_64.rpm", "xe-antishell-0.1.0-20.el9.x86_64.rpm"} {
		noNetwork := &http.Client{Transport: releaseTransport(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid candidate reached network")
			return nil, fmt.Errorf("network called")
		})}
		if _, err := githubManifestForRPM(ctx, noNetwork, bad, "9", decode); err == nil {
			t.Fatal("bad name accepted")
		}
	}
	got, body, err := download(ctx, client, m.Tag, "9", decode)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(body)
	body.Close()
	if err != nil || !bytes.Equal(actual, payload) || got != s || rpmReads != 1 {
		t.Fatal("download changed data")
	}
	row.Assets = append(row.Assets, row.Assets[0])
	if _, _, err = download(ctx, client, m.Tag, "9", decode); err == nil || rpmReads != 1 {
		t.Fatal("ambiguous asset accepted")
	}
}
