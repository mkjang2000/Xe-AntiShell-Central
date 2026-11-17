package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeRejectsInvalidEnrollmentURLBeforeLoadingState(t *testing.T) {
	for _, raw := range []string{"http://localhost:9443", "https://localhost:9443/path", "https://user:private@localhost", "https://localhost?query", "https://localhost#fragment", "https://localhost:0"} {
		var stdout, stderr bytes.Buffer
		err := run([]string{"serve", "--state-dir", "/does-not-exist-enrollment-state", "--enrollment-url", raw}, &stdout, &stderr)
		if err == nil || strings.Contains(err.Error(), "does-not-exist-enrollment-state") || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid enrollment URL did not fail safely before loading state: %v", err)
		}
	}
}

func TestServeChecksEnrollmentCertificateBeforeOpeningListeners(t *testing.T) {
	var stdout, stderr bytes.Buffer
	directory := filepath.Join(t.TempDir(), "central")
	if err := run([]string{"init", "--state-dir", directory}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"serve", "--state-dir", directory, "--enrollment-url", "https://wrong.example:9443", "--listen", "invalid-listener"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Fatalf("invalid certificate name was not checked before opening listeners: %v", err)
	}
	err = run([]string{"serve", "--state-dir", directory, "--enrollment-url", "https://localhost:9443", "--listen", "invalid-listener"}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error(), "hostname") {
		t.Fatalf("valid enrollment configuration did not reach listener validation: %v", err)
	}
}
