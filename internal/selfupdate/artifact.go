// Package selfupdate authenticates and applies Xe-AntiShell Central releases.
package selfupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

const (
	MaxRPMBytes      = 64 << 20
	MaxManifestBytes = 16 << 10
	signatureDomain  = "xe-antishell-central/release-manifest/v1\x00"
)

var (
	releaseTag    = regexp.MustCompile(`^v((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8}))-r([1-9][0-9]{0,8})$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errManifest   = errors.New("invalid central release manifest")
)

type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Tag           string `json:"tag"`
	ArtifactName  string `json:"artifact_name"`
	OSMajor       string `json:"os_major"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	KeyID     string   `json:"key_id"`
	Signature string   `json:"signature"`
}

func rpmName(tag, major string) (string, error) {
	fields := releaseTag.FindStringSubmatch(tag)
	if len(fields) != 3 || (major != "9" && major != "10") {
		return "", errManifest
	}
	return "xe-antishell-central-" + fields[1] + "-" + fields[2] + ".el" + major + ".x86_64.rpm", nil
}

func (m Manifest) validate() error {
	name, err := rpmName(m.Tag, m.OSMajor)
	if err != nil || m.SchemaVersion != "1" || m.ArtifactName != name || !digestPattern.MatchString(m.SHA256) || m.Size < 1 || m.Size > MaxRPMBytes {
		return errManifest
	}
	return nil
}

func signedBytes(id string, manifest Manifest) ([]byte, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append([]byte(signatureDomain+id+"\x00"), body...), nil
}

func SignManifest(m Manifest, key ed25519.PrivateKey) (SignedManifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedManifest{}, errors.New("invalid Ed25519 publisher key")
	}
	hash := sha256.Sum256(key.Public().(ed25519.PublicKey))
	id := "release-" + hex.EncodeToString(hash[:8])
	body, err := signedBytes(id, m)
	if err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Manifest: m, KeyID: id, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))}, nil
}

func VerifyManifest(s SignedManifest) error {
	return verifyManifest(s, managed.BuiltinReleasePublisherKeys())
}

func verifyManifest(s SignedManifest, keys map[string]ed25519.PublicKey) error {
	key := keys[s.KeyID]
	sig, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if len(key) != ed25519.PublicKeySize || err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != s.Signature {
		return errors.New("untrusted central release publisher or signature")
	}
	body, err := signedBytes(s.KeyID, s.Manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, sig) {
		return errors.New("central release signature verification failed")
	}
	return nil
}

// DecodeManifest accepts only a complete, bounded publisher envelope.
func DecodeManifest(raw []byte) (SignedManifest, error) {
	var s SignedManifest
	if managed.DecodeStrict(raw, MaxManifestBytes, &s) != nil {
		return SignedManifest{}, errManifest
	}
	if err := VerifyManifest(s); err != nil {
		return SignedManifest{}, err
	}
	return s, nil
}
