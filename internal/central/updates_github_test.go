package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type updateRoundTrip func(*http.Request) (*http.Response, error)

func (f updateRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func updateHTTPResponse(body []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func TestUpdateGitHubHTTPSAndPublicDNSGuards(t *testing.T) {
	for _, raw := range []string{"http://github.com/a", "https://api.github.com.evil.test/a", "https://127.0.0.1/a", "https://github.com:8443/a", "https://user:password@github.com/a", "https://github.com/a#fragment"} {
		if _, err := updateGitHubURL(raw); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.64.0.1", "192.0.2.8", "198.18.0.1", "::1", "fd00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:0a00:0001::1", "2001::1"} {
		if updatePublicIP(netip.MustParseAddr(address)) {
			t.Fatal("nonpublic outbound address accepted")
		}
	}
	for _, address := range []string{"8.8.8.8", "2606:4700::1111", "2001:4860:4860::8888"} {
		if !updatePublicIP(netip.MustParseAddr(address)) {
			t.Fatal("public IPv4/IPv6 was rejected")
		}
	}
	for _, addresses := range [][]netip.Addr{{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}} {
		called := false
		dialer := updatePublicDialer{lookup: func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }, dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }}
		if _, err := dialer.DialContext(context.Background(), "tcp", "api.github.com:443"); err == nil || called {
			t.Fatal("private or mixed DNS reached dial")
		}
	}
	dialed := ""
	dialer := updatePublicDialer{lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = address
		return nil, nil
	}}
	if _, err := dialer.DialContext(context.Background(), "tcp", "api.github.com:443"); err != nil || dialed != "8.8.8.8:443" {
		t.Fatal("resolved address was not pinned")
	}
}

func TestUpdateGitHubRedirectsBoundedAndErrorsNeverEchoURLs(t *testing.T) {
	for _, destination := range []string{"http://169.254.169.254/SYNTHETIC_TOKEN", "https://github.com.evil.test/SYNTHETIC_TOKEN", "https://objects.githubusercontent.com/loop"} {
		client := newUpdateGitHubClient()
		calls := 0
		client.http.Transport = updateRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{destination}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})
		if _, err := client.get(context.Background(), updateGitHubAPI); err == nil || strings.Contains(err.Error(), "SYNTHETIC_TOKEN") || calls > 4 {
			t.Fatal("redirect restriction or safe error failed")
		}
	}
}

func TestUpdateGitHubCatalogIsFixedFilteredAndCached(t *testing.T) {
	client := newUpdateGitHubClient()
	calls := 0
	data, _ := json.Marshal([]updateGitHubRelease{
		{TagName: "v0.1.0", Name: "published", PublishedAt: time.Now(), Assets: []updateGitHubAsset{{Name: "xe-antishell.rpm.manifest.json", Size: 512}, {Name: "not-a-manifest.txt", Size: 12}}},
		{TagName: "draft", Draft: true, Assets: []updateGitHubAsset{{Name: "hidden.rpm.manifest.json", Size: 10}}},
		{TagName: "../../escape", Assets: []updateGitHubAsset{{Name: "invalid.rpm.manifest.json", Size: 10}}},
	})
	client.http.Transport = updateRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != updateGitHubAPI+"?per_page=20" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("catalog URL or credentials changed")
		}
		return updateHTTPResponse(data), nil
	})
	for i := 0; i < 2; i++ {
		catalog, err := client.catalog(context.Background())
		if err != nil || catalog.Repository != updateGitHubRepository || len(catalog.Items) != 1 || len(catalog.Items[0].ManifestAssets) != 1 {
			t.Fatal("catalog filtering failed")
		}
	}
	if calls != 1 {
		t.Fatal("catalog cache was bypassed")
	}
}

func TestUpdateGitHubImportRequiresPublisherBeforeFetchingRPM(t *testing.T) {
	f := updateFixture(t)
	pack := updatePackage(24)
	body, _ := json.Marshal(pack)
	publisher := f.signedUpdateBody(t, body, pack)
	manifest, _ := json.Marshal(publisher)
	tag := "agent/v0.1.0"
	name := publisher.Manifest.ArtifactName + ".manifest.json"
	metadata, _ := json.Marshal(updateGitHubRelease{TagName: tag, Assets: []updateGitHubAsset{{Name: name, Size: int64(len(manifest))}, {Name: publisher.Manifest.ArtifactName, Size: int64(len(body))}}})
	rpmReads := 0
	f.server.updateGitHub.http.Transport = updateRoundTrip(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case updateGitHubAPI + "/tags/agent%2Fv0.1.0":
			return updateHTTPResponse(metadata), nil
		case updateGitHubAssetURL(tag, name):
			return updateHTTPResponse(manifest), nil
		case updateGitHubAssetURL(tag, publisher.Manifest.ArtifactName):
			rpmReads++
			return updateHTTPResponse(body), nil
		}
		return nil, errors.New("unexpected synthetic URL")
	})
	release, duplicate, err := f.server.importUpdateGitHub(context.Background(), tag, name, "admin")
	if err != nil || duplicate || !release.PublisherVerified || release.Publisher.KeyID != publisher.KeyID || rpmReads != 1 {
		t.Fatalf("valid GitHub import: %v", err)
	}
	if _, duplicate, err = f.server.importUpdateGitHub(context.Background(), tag, name, "admin"); err != nil || !duplicate {
		t.Fatal("import retry not idempotent")
	}
	publisher.Signature = "invalid"
	manifest, _ = json.Marshal(publisher)
	before := rpmReads
	if _, _, err = f.server.importUpdateGitHub(context.Background(), tag, name, "admin"); err == nil || rpmReads != before {
		t.Fatal("unverified publisher reached RPM download")
	}
}
