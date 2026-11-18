package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/selfupdate"
)

func TestUpdateCLIRejectsAmbiguousOrIncompleteSources(t *testing.T) {
	for _, args := range [][]string{
		{"update", "apply"}, {"update", "apply", "--tag", "v0.1.0-r20", "--rpm", "/local.rpm"},
		{"update", "apply", "--manifest", "/local.json"}, {"update", "apply", "--rpm", "/incorrect-name.rpm", "--manifest", "/missing/manifest.json"},
		{"update", "bootstrap", "--tag", "v0.1.0-r20"}, {"update", "status", "extra"},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	var help bytes.Buffer
	if err := run([]string{"update", "--help"}, io.Discard, &help); err != nil || !strings.Contains(help.String(), "--manifest") {
		t.Fatal(err, help.String())
	}
}

func TestUpdateCLIReportsOnlyMatchingTerminalJob(t *testing.T) {
	const digest = "expected-digest"
	for _, tc := range []struct {
		state, hash string
		ok          bool
	}{
		{"succeeded", digest, true}, {"failed", digest, false}, {"interrupted", digest, false}, {"succeeded", "other-digest", false},
	} {
		s, err := awaitCentralUpdate(context.Background(), digest, selfupdate.Status{State: tc.state, SHA256: tc.hash})
		if (err == nil) != tc.ok || s.State != tc.state {
			t.Errorf("state %s digest %s: %v", tc.state, tc.hash, err)
		}
	}
}
