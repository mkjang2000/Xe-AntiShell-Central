package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixtureManifest() Manifest {
	return Manifest{SchemaVersion: "1", Tag: "v0.1.0-r20", ArtifactName: "xe-antishell-central-0.1.0-20.el9.x86_64.rpm", OSMajor: "9", Size: 123, SHA256: strings.Repeat("a", 64)}
}

func TestCentralPublisherSignatureIsProductAndTargetBound(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureManifest()
	s, err := SignManifest(m, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]ed25519.PublicKey{s.KeyID: pub}
	if err := verifyManifest(s, trust); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(s); err == nil {
		t.Fatal("test publisher became a system trust anchor")
	}
	mods := []func(*SignedManifest){
		func(copy *SignedManifest) {
			copy.Manifest.ArtifactName = strings.ReplaceAll(copy.Manifest.ArtifactName, "-central", "")
		},
		func(copy *SignedManifest) { copy.Manifest.Tag = "v0.1.0-r19" },
		func(copy *SignedManifest) { copy.Manifest.SHA256 = strings.Repeat("0", 64) },
		func(copy *SignedManifest) { copy.Manifest.Size++ },
		func(copy *SignedManifest) { copy.Manifest.OSMajor = "10" },
		func(copy *SignedManifest) { copy.Manifest.SchemaVersion = "2" },
		func(copy *SignedManifest) { copy.Signature += "\n" },
		func(copy *SignedManifest) { copy.KeyID = "local" },
		func(copy *SignedManifest) {
			b, _ := json.Marshal(m)
			copy.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))
		},
	}
	for i, mod := range mods {
		copy := s
		mod(&copy)
		if verifyManifest(copy, trust) == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
	for _, tag := range []string{"", "v1.2.3", "alpha/v1.2.3-r1", "v1.02.3-r4", "v1.2.3-r0", "v1.2.3-r01", "v1.2.3-r4.el9", "v1.2.3-r4/../r1"} {
		if _, err := rpmName(tag, "9"); err == nil {
			t.Errorf("invalid tag %q", tag)
		}
	}
}

func TestManifestDecodeAndBounds(t *testing.T) {
	for _, raw := range []string{"{}", "{}", strings.Repeat("x", MaxManifestBytes+1), `{"manifest":{},"extra":1}`, `{}{}`} {
		if _, err := DecodeManifest([]byte(raw)); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	for _, size := range []int64{0, MaxRPMBytes + 1, -1} {
		m := fixtureManifest()
		m.Size = size
		if m.validate() == nil {
			t.Errorf("accepted size %d", size)
		}
	}
	m := fixtureManifest()
	m.Size = MaxRPMBytes
	if err := m.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestInspectPublishedCentralRPM(t *testing.T) {
	path := os.Getenv("XEAS_CENTRAL_ARTIFACT_TEST_RPM")
	tag := os.Getenv("XEAS_CENTRAL_ARTIFACT_TEST_TAG")
	if path == "" || tag == "" {
		t.Skip("set RPM and tag to test a real publisher candidate")
	}
	m, err := PrepareManifest(context.Background(), path, tag)
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := openPackage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := inspectPackage(context.Background(), f, m, true); err != nil {
		t.Fatal(err)
	}
	wrong := m
	wrong.Tag = "v42.0.0-r99"
	if _, err := inspectPackage(context.Background(), f, wrong, true); err == nil {
		t.Fatal("wrong package header accepted")
	}
	wrong = m
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err := inspectPackage(context.Background(), f, wrong, true); err == nil {
		t.Fatal("changed package accepted")
	}
}

func TestPlatformAndForeignPackages(t *testing.T) {
	for data, major := range map[string]string{
		"ID=rocky\nVERSION_ID=\"9.6\"":                              "9",
		"ID=almalinux\nVERSION_ID=10":                               "10",
		"ID=my-rhel-derived\nID_LIKE=\"rhel fedora\"\nVERSION_ID=9": "9",
		"ID=fedora\nVERSION_ID=10":                                  "",
		"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=9":                   "",
		"ID=rocky\nVERSION_ID=8":                                    "",
	} {
		got, err := parseOSRelease(data)
		if got != major || (err != nil) != (major == "") {
			t.Errorf("%q: got %q, %v", data, got, err)
		}
	}
}
