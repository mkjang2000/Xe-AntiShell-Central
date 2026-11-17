package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializationAndTokenNeverPrintSecret(t *testing.T) {
	var stdout, stderr bytes.Buffer
	directory := filepath.Join(t.TempDir(), "central")
	if err := run([]string{"init", "--state-dir", directory}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	operator, err := os.ReadFile(filepath.Join(directory, "operator-token"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), strings.TrimSpace(string(operator))) {
		t.Fatal("operator credential printed")
	}
	path := filepath.Join(t.TempDir(), "enrollment-token")
	stdout.Reset()
	if err = run([]string{"enrollment-token", "--state-dir", directory, "--agent-id", "agent-a", "--output-file", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(token))) < 32 || strings.Contains(stdout.String(), strings.TrimSpace(string(token))) {
		t.Fatal("enrollment credential absent or printed")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token permissions: %v %v", info, err)
	}
	if err = run([]string{"init", "--state-dir", directory}, &stdout, &stderr); err == nil {
		t.Fatal("initialization overwrote existing state")
	}
}

func TestRejectsIncompleteAndExtraArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{"version", "extra"}, {"init", "extra"}, {"enrollment-token", "--agent-id", "agent-a"}, {"serve", "extra"}} {
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("accepted invalid args %v", args)
		}
	}
}
