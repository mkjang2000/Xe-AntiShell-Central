package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/console"
)

func TestPanelInitializationPreservesStateAndNeverPrintsPassword(t *testing.T) {
	var stdout, stderr bytes.Buffer
	directory := filepath.Join(t.TempDir(), "central")
	if err := run([]string{"init", "--state-dir", directory}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(directory, "policy-key"))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	args := []string{"init-panel", "--state-dir", directory}
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(filepath.Join(directory, "panel-initial-password"))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(string(password))
	if len(secret) < 24 || strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("password absent or disclosed")
	}
	authPath := filepath.Join(directory, "panel-auth.json")
	credentials, err := console.LoadCredentials(authPath)
	if err != nil || !credentials.Verify("admin", secret) {
		t.Fatalf("initial login credentials: %v", err)
	}
	before, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(args, &stdout, &stderr); err == nil {
		t.Fatal("existing administrator credentials overwritten")
	}
	after, _ := os.ReadFile(authPath)
	keyAfter, _ := os.ReadFile(filepath.Join(directory, "policy-key"))
	if !bytes.Equal(before, after) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("credentials or signing state changed")
	}
	for _, name := range []string{"panel-auth.json", "panel-initial-password"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private permissions: %s %v", name, err)
		}
	}
}

func TestPanelPasswordOutputConflictLeavesAuthUninitialized(t *testing.T) {
	var stdout, stderr bytes.Buffer
	directory := filepath.Join(t.TempDir(), "central")
	if err := run([]string{"init", "--state-dir", directory}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(directory, "existing-password-file")
	if err := os.WriteFile(passwordPath, []byte("keep this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init-panel", "--state-dir", directory, "--password-file", passwordPath}, &stdout, &stderr); err == nil {
		t.Fatal("existing output accepted")
	}
	if _, err := os.Lstat(filepath.Join(directory, "panel-auth.json")); !os.IsNotExist(err) {
		t.Fatal("partial initialization left credentials")
	}
	data, err := os.ReadFile(passwordPath)
	if err != nil || string(data) != "keep this file" {
		t.Fatal("existing output changed")
	}
}

func TestPanelRejectsPartialTLSBeforeOpeningListeners(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"serve", "--panel-tls-cert", "/not-opened.pem"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "provided together") {
		t.Fatalf("partial console TLS configuration accepted: %v", err)
	}
}

func TestPanelRejectsInvalidProxyOptionsBeforeLoadingState(t *testing.T) {
	for _, args := range [][]string{
		{"--panel-public-origin", "http://console.example"},
		{"--panel-public-origin", "https://console.example/login"},
		{"--panel-public-origin", "https://console.example", "--panel-trusted-proxies", "not-a-network"},
		{"--panel-public-origin", "https://console.example", "--panel-trusted-proxies", ""},
		{"--panel-trusted-proxies", "127.0.0.1/32"},
	} {
		var stdout, stderr bytes.Buffer
		full := append([]string{"serve", "--state-dir", "/does-not-exist-console-state"}, args...)
		err := run(full, &stdout, &stderr)
		if err == nil || strings.Contains(err.Error(), "does-not-exist-console-state") {
			t.Fatalf("invalid proxy options did not fail before loading state: %v", err)
		}
	}
}
