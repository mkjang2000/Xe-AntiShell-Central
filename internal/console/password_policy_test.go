package console

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestNewPasswordPolicyLengthsAndClasses(t *testing.T) {
	cases := []struct {
		name, value string
		valid       bool
	}{
		{"empty", "", false},
		{"seven", "Ab1!xyz", false},
		{"eight", "Abc123!x", true},
		{"nine", "Abcd123!x", true},
		{"nine needs upper", "abcde12!x", false},
		{"ten without upper", "abcdef12!x", true},
		{"ten with upper", "Abcdef12!x", true},
		{"lower required", "ABCDEF12!X", false},
		{"digit required", "abcdefghi!", false},
		{"punctuation required", "abcdef1234", false},
		{"space is not punctuation", "Abc123 x", false},
		{"spaces additional", "Ab1! xy ", true},
		{"emoji not ASCII punctuation", "Abc123😀x", false},
		{"Unicode eight", "가Ab1!😀😃😄", true},
		{"Unicode is not bytes", "가a1!b", false},
		{"Unicode ten no upper", "가나다라마바a1!x", true},
		{"newlines additional", "abc1!\nxyzz", true},
		{"max ascii bytes", "a1!" + strings.Repeat("x", 1021), true},
		{"over ascii bytes", "a1!" + strings.Repeat("x", 1022), false},
		{"max Unicode bytes", "a1!x" + strings.Repeat("가", 340), true},
		{"over Unicode bytes", "a1!xx" + strings.Repeat("가", 340), false},
		{"invalid UTF8", "Abc12!xy" + string([]byte{0xff}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNewPassword(tc.value)
			if (err == nil) != tc.valid {
				t.Fatalf("policy result mismatch; valid=%v error=%v", tc.valid, err)
			}
			if err != nil && !errors.Is(err, ErrPasswordPolicy) {
				t.Fatal("policy error lost safe category")
			}
		})
	}
	for r := rune(0x21); r <= 0x7e; r++ {
		punctuation := r >= '!' && r <= '/' || r >= ':' && r <= '@' || r >= '[' && r <= '`' || r >= '{' && r <= '~'
		err := ValidateNewPassword("Abc123xx" + string(r))
		if (err == nil) != punctuation {
			t.Fatalf("ASCII classification mismatch for U+%04X", r)
		}
	}
}

func TestGeneratedInitialPasswordsKeepEntropyAndPolicy(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 24; i++ {
		value, err := GeneratePassword()
		if err != nil || len(value) != 35 || ValidateNewPassword(value) != nil || seen[value] {
			t.Fatal("generated password is not random and policy compliant")
		}
		randomPart, err := base64.RawURLEncoding.DecodeString(value[:32])
		if err != nil || len(randomPart) != 24 {
			t.Fatal("initial password lost the original random-byte budget")
		}
		seen[value] = true
	}
	file := filepath.Join(t.TempDir(), "password.txt")
	if err := WriteInitialPassword(file, "Abc123!x"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "Abc123!x\n" {
		t.Fatal("short initial password was not stored exactly")
	}
	if err := WriteInitialPassword(filepath.Join(t.TempDir(), "newline"), "abc1!\nxyzz"); err == nil {
		t.Fatal("initial file lost its one-line format guard")
	}
}

// Simulate a credential created by an older release. Verification must not
// enforce a password-creation policy against a persisted valid hash.
func legacyPasswordCredentials(t *testing.T, username, password string) Credentials {
	t.Helper()
	parameters := Argon2Parameters{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}
	salt := make([]byte, 16)
	key := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return Credentials{Version: credentialsVersion, Username: username, Parameters: parameters,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Hash:       base64.RawURLEncoding.EncodeToString(argon2.IDKey([]byte(password), salt, parameters.Time, parameters.Memory, parameters.Threads, parameters.KeyLen)),
		SessionKey: base64.RawURLEncoding.EncodeToString(key)}
}

func TestLegacyPasswordHashAndSessionRemainValid(t *testing.T) {
	old := "legacy-password-fixture"
	if ValidateNewPassword(old) == nil {
		t.Fatal("fixture should fail new composition rules")
	}
	credentials := legacyPasswordCredentials(t, "legacy", old)
	file := filepath.Join(t.TempDir(), "auth.json")
	if err := WriteCredentials(file, credentials); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCredentials(file)
	if err != nil || !loaded.Verify("legacy", old) || loaded.Verify("legacy", "wrong") {
		t.Fatal("new creation policy blocked a legacy password")
	}
	now := time.Now()
	session, err := loaded.NewSession(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if username, err := loaded.VerifySession(session, now); err != nil || username != "legacy" {
		t.Fatal("legacy credential session was invalidated")
	}
}
