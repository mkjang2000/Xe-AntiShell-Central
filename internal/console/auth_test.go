package console

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCredentials(t *testing.T) Credentials {
	t.Helper()
	credentials, err := GenerateCredentials("admin", "correct-horse-battery-staple1!", Argon2Parameters{
		Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	return credentials
}

func TestCredentialsAndSessions(t *testing.T) {
	c := testCredentials(t)
	if !c.Verify("admin", "correct-horse-battery-staple1!") ||
		c.Verify("admin", "wrong-password-value") || c.Verify("other", "correct-horse-battery-staple1!") {
		t.Fatal("credential verification did not distinguish correct and incorrect inputs")
	}
	now := time.Unix(1_700_000_000, 0)
	token, err := c.NewSession(now, sessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if username, err := c.VerifySession(token, now.Add(7*time.Hour)); err != nil || username != "admin" {
		t.Fatalf("valid session: username=%q err=%v", username, err)
	}
	for _, invalid := range []string{"x" + token[1:], token + ".extra", strings.Repeat("x", 2049), ""} {
		if _, err := c.VerifySession(invalid, now); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("invalid session was accepted: %v", err)
		}
	}
	// Raw base64 has unused low bits in its last character. An alternate
	// spelling that decodes to the same signature must still be rejected.
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	alias := token[:len(token)-1] + string(alphabet[last+1])
	if _, err := c.VerifySession(alias, now); !errors.Is(err, ErrInvalidSession) {
		t.Fatal("noncanonical session signature was accepted")
	}
	if _, err := c.VerifySession(token, now.Add(sessionLifetime)); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expired session was accepted: %v", err)
	}
	if _, err := c.NewSession(now, 25*time.Hour); err == nil {
		t.Fatal("overlong session lifetime was accepted")
	}
}

func TestCredentialFilesArePrivateAndExclusive(t *testing.T) {
	c := testCredentials(t)
	filename := filepath.Join(t.TempDir(), "panel-auth.json")
	if err := WriteCredentials(filename, c); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode: info=%v err=%v", info, err)
	}
	loaded, err := LoadCredentials(filename)
	if err != nil || loaded != c {
		t.Fatalf("credential round trip: %v", err)
	}
	if err := WriteCredentials(filename, c); err == nil {
		t.Fatal("existing credential file was overwritten")
	}
	if err := os.Chmod(filename, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(filename); err == nil {
		t.Fatal("group-readable credential file was accepted")
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "auth-link.json")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(link); err == nil {
		t.Fatal("symlink credential file was accepted")
	}
	encoded, _ := json.Marshal(c)
	for _, suffix := range []string{"{}", strings.Repeat(" ", 16*1024)} {
		if err := os.WriteFile(filename, append(encoded, []byte(suffix)...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredentials(filename); err == nil {
			t.Fatal("trailing or oversized credential data was accepted")
		}
	}
}

func TestInitialPasswordFilesAndValidation(t *testing.T) {
	password, err := GeneratePassword()
	if err != nil || len(password) < 16 {
		t.Fatalf("password generation: length=%d err=%v", len(password), err)
	}
	filename := filepath.Join(t.TempDir(), "panel-password.txt")
	if err := WriteInitialPassword(filename, password); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filename)
	data, _ := os.ReadFile(filename)
	if info.Mode().Perm() != 0o600 || string(data) != password+"\n" {
		t.Fatal("initial password was not stored privately and exactly")
	}
	if WriteInitialPassword(filename, password) == nil || WriteInitialPassword("relative.txt", password) == nil {
		t.Fatal("unsafe initial password output was accepted")
	}
	if WriteInitialPassword(filepath.Join(t.TempDir(), "bad"), "short") == nil {
		t.Fatal("short initial password was accepted")
	}
	c := testCredentials(t)
	c.Parameters.Memory = 1024 * 1024
	if c.Validate() == nil || c.Verify("admin", password) {
		t.Fatal("unsafe Argon2 parameters were accepted")
	}
}
