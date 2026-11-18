// Copyright (c) 2026 mkjang2000 and Xe-AntiShell contributors
// SPDX-License-Identifier: MIT

package console

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const credentialsVersion = 1

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidSession     = errors.New("invalid session")
)

type Argon2Parameters struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_length"`
}

type Credentials struct {
	Version    int              `json:"version"`
	Username   string           `json:"username"`
	Parameters Argon2Parameters `json:"argon2id"`
	Salt       string           `json:"salt"`
	Hash       string           `json:"password_hash"`
	SessionKey string           `json:"session_key"`
}

func DefaultArgon2Parameters() Argon2Parameters {
	return Argon2Parameters{Time: 3, Memory: 64 * 1024, Threads: 2, KeyLen: 32}
}

func GenerateCredentials(username, password string, parameters Argon2Parameters) (Credentials, error) {
	if err := validateUsername(username); err != nil {
		return Credentials{}, err
	}
	if err := ValidateNewPassword(password); err != nil {
		return Credentials{}, err
	}
	if err := validateArgon2Parameters(parameters); err != nil {
		return Credentials{}, err
	}
	salt, err := randomBytes(16)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate password salt: %w", err)
	}
	sessionKey, err := randomBytes(32)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate session key: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, parameters.Time, parameters.Memory, parameters.Threads, parameters.KeyLen)
	return Credentials{
		Version:    credentialsVersion,
		Username:   username,
		Parameters: parameters,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Hash:       base64.RawURLEncoding.EncodeToString(hash),
		SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey),
	}, nil
}

func GeneratePassword() (string, error) {
	value, err := randomBytes(24)
	if err != nil {
		return "", fmt.Errorf("generate initial password: %w", err)
	}
	// Keep all 192 random bits and guarantee the required character classes.
	return base64.RawURLEncoding.EncodeToString(value) + "a1!", nil
}

func LoadCredentials(path string) (Credentials, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("stat auth file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Credentials{}, errors.New("auth file is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Credentials{}, fmt.Errorf("auth file permissions %04o allow group or other access", info.Mode().Perm())
	}
	file, err := os.Open(path)
	if err != nil {
		return Credentials{}, fmt.Errorf("read auth file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return Credentials{}, errors.New("auth file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	if err != nil {
		return Credentials{}, fmt.Errorf("read auth file: %w", err)
	}
	if len(data) > 16*1024 {
		return Credentials{}, errors.New("auth file is too large")
	}
	var credentials Credentials
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return Credentials{}, fmt.Errorf("decode auth file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Credentials{}, errors.New("auth file contains trailing data")
	}
	if err := credentials.Validate(); err != nil {
		return Credentials{}, err
	}
	return credentials, nil
}

func WriteCredentials(path string, credentials Credentials) error {
	if err := credentials.Validate(); err != nil {
		return err
	}
	if err := validateOutputPath(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	data = append(data, '\n')
	return writeExclusive(path, data)
}

func WriteInitialPassword(path, password string) error {
	if err := validateOutputPath(path); err != nil {
		return err
	}
	if strings.ContainsAny(password, "\r\n") {
		return errors.New("initial password must not contain newlines")
	}
	if err := ValidateNewPassword(password); err != nil {
		return err
	}
	return writeExclusive(path, []byte(password+"\n"))
}

func (c Credentials) Validate() error {
	if c.Version != credentialsVersion {
		return fmt.Errorf("unsupported auth file version %d", c.Version)
	}
	if err := validateUsername(c.Username); err != nil {
		return err
	}
	if err := validateArgon2Parameters(c.Parameters); err != nil {
		return err
	}
	salt, err := base64.RawURLEncoding.DecodeString(c.Salt)
	if err != nil || len(salt) != 16 {
		return errors.New("invalid password salt")
	}
	hash, err := base64.RawURLEncoding.DecodeString(c.Hash)
	if err != nil || len(hash) != int(c.Parameters.KeyLen) {
		return errors.New("invalid password hash")
	}
	key, err := base64.RawURLEncoding.DecodeString(c.SessionKey)
	if err != nil || len(key) < 32 || len(key) > 64 {
		return errors.New("invalid session key")
	}
	return nil
}

func (c Credentials) Verify(username, password string) bool {
	if len(username) > 128 || len(password) > 1024 || c.Validate() != nil {
		return false
	}
	salt, _ := base64.RawURLEncoding.DecodeString(c.Salt)
	expected, _ := base64.RawURLEncoding.DecodeString(c.Hash)
	actual := argon2.IDKey([]byte(password), salt, c.Parameters.Time, c.Parameters.Memory, c.Parameters.Threads, c.Parameters.KeyLen)
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(c.Username))
	hashMatch := subtle.ConstantTimeCompare(actual, expected)
	return usernameMatch&hashMatch == 1
}

type sessionPayload struct {
	Username string `json:"u"`
	Expires  int64  `json:"e"`
	Nonce    string `json:"n"`
}

func (c Credentials) NewSession(now time.Time, lifetime time.Duration) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if lifetime <= 0 || lifetime > 24*time.Hour {
		return "", errors.New("invalid session lifetime")
	}
	nonce, err := randomBytes(16)
	if err != nil {
		return "", fmt.Errorf("generate session nonce: %w", err)
	}
	payload := sessionPayload{Username: c.Username, Expires: now.Add(lifetime).Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(encoded)
	signature := c.sign(payloadPart)
	return payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (c Credentials) VerifySession(token string, now time.Time) (string, error) {
	if len(token) > 2048 {
		return "", ErrInvalidSession
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", ErrInvalidSession
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || base64.RawURLEncoding.EncodeToString(provided) != parts[1] || !hmac.Equal(provided, c.sign(parts[0])) {
		return "", ErrInvalidSession
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payloadBytes) != parts[0] || len(payloadBytes) > 1024 {
		return "", ErrInvalidSession
	}
	var payload sessionPayload
	if json.Unmarshal(payloadBytes, &payload) != nil || payload.Username != c.Username || payload.Nonce == "" || payload.Expires <= now.Unix() {
		return "", ErrInvalidSession
	}
	return payload.Username, nil
}

func (c Credentials) sign(payload string) []byte {
	key, _ := base64.RawURLEncoding.DecodeString(c.SessionKey)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func validateUsername(value string) error {
	if value == "" || len(value) > 64 {
		return errors.New("username must be between 1 and 64 bytes")
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return errors.New("username contains unsupported characters")
		}
	}
	return nil
}

func validateArgon2Parameters(parameters Argon2Parameters) error {
	if parameters.Time < 1 || parameters.Time > 10 || parameters.Memory < 8*1024 || parameters.Memory > 256*1024 || parameters.Threads < 1 || parameters.Threads > 8 || parameters.KeyLen < 16 || parameters.KeyLen > 64 {
		return errors.New("argon2id parameters are outside allowed bounds")
	}
	return nil
}

func validateOutputPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("output path must be a clean absolute path")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("stat output directory: %w", err)
	}
	if !parent.IsDir() {
		return errors.New("output parent is not a directory")
	}
	return nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	written := false
	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	written = true
	return nil
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	_, err := rand.Read(value)
	return value, err
}
