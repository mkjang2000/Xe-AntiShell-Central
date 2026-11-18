package central

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	contract "github.com/mkjang2000/Xe-AntiShell/protocol/integrity"
	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestPackageFileHeaderPinsExactlySevenRegularFiles(t *testing.T) {
	hash := strings.Repeat("b", 64)
	header := "8\n"
	for id, path := range contract.Targets() {
		if id != contract.ConfigID {
			header += path + "\t33261\t" + hash + "\n"
		}
	}
	rows, err := parseRPMFileBaselines(header)
	if err != nil || len(rows) != 7 {
		t.Fatal(rows, err)
	}
	for _, bad := range []string{strings.Replace(header, "8\n", "1\n", 1), strings.Replace(header, "33261", "41471", 1), strings.Replace(header, hash, "", 1), header + "/usr/sbin/sentineld\t33261\t" + hash + "\n", strings.Replace(header, "/usr/bin/sentinel\t", "/unexpected\t", 1)} {
		if _, err := parseRPMFileBaselines(bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid file header")
		}
	}
}

// The optional artifact fixture runs against an actual public release and its
// built-in publisher signature without altering the installed RPM database.
func TestPublisherSignedRPMFileBaselines(t *testing.T) {
	rpm := os.Getenv("XEAS_INTEGRITY_TEST_RPM")
	if rpm == "" {
		t.Skip("set XEAS_INTEGRITY_TEST_RPM to the public RPM beside its .manifest.json")
	}
	raw, err := os.ReadFile(rpm + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var signed managed.SignedReleaseManifest
	if err = json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	m, err := managed.VerifyReleaseManifest(signed, managed.BuiltinReleasePublisherKeys())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(rpm)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := rpmFileBaselines(context.Background(), f, m)
	if err != nil || len(rows) != 7 {
		t.Fatalf("extract: %v, %v", rows, err)
	}
	unit, err := os.ReadFile(os.Getenv("XEAS_INTEGRITY_TEST_UNIT"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(unit)
	if rows["sentineld-unit"] != hex.EncodeToString(sum[:]) {
		t.Fatal("unit digest differs from committed source")
	}
	m.SHA256 = strings.Repeat("0", 64)
	if _, err = rpmFileBaselines(context.Background(), f, m); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid RPM digest accepted")
	}
}

func TestSignedReleaseImportMaterializesBaselines(t *testing.T) {
	path := os.Getenv("XEAS_INTEGRITY_TEST_RPM")
	if path == "" {
		t.Skip("set signed RPM fixture")
	}
	f := setup(t)
	raw, err := os.ReadFile(path + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest managed.SignedReleaseManifest
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("invalid signed manifest")
	}
	rpm, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	release, _, err := f.server.publishUpdateRelease(ctx, bytes.NewReader(rpm), "fixture", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.db.QueryRow("SELECT files_json FROM integrity_package_files WHERE release_id=?", release.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var expected map[string]string
	if json.Unmarshal(raw, &expected) != nil || len(expected) != 7 {
		t.Fatal("incomplete package baseline")
	}
	if _, err = f.store.db.Exec("DELETE FROM integrity_package_files"); err != nil {
		t.Fatal(err)
	}
	files, err := f.server.packageBaselines(ctx, release)
	if err != nil || files["sentineld"] != expected["sentineld"] {
		t.Fatal(files, err)
	}
}
