package central

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/selfupdate"
)

func TestCentralUpdateRequiresAuthenticatedAccountAndConfirmation(t *testing.T) {
	f := updateFixture(t)
	for _, path := range []string{"status", "releases", "github", "upload"} {
		method := http.MethodPost
		if path == "status" || path == "releases" {
			method = http.MethodGet
		}
		r := httptest.NewRequest(method, centralUpdateBase+path, nil)
		w := httptest.NewRecorder()
		f.server.ConsoleHandler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("business route %s without an account: %d", path, w.Code)
		}
	}
	client := updateAuthenticatedConsole(t, f)
	for _, tc := range []struct {
		route, media, body, confirm, header, filename string
		length                                        int64
		want                                          int
	}{
		{route: "github", media: "application/json", body: `{"tag":"v0.1.0-r20"}`, want: 400},
		{route: "github", media: "application/json", body: `{"tag":"v0.1.0-r20","confirm":true,"url":"other"}`, want: 400},
		{route: "upload", media: "application/x-rpm", want: 400},
		{route: "upload", media: "application/json", confirm: "true", want: 415},
		{route: "upload", media: "application/x-rpm", confirm: "true", length: selfupdate.MaxRPMBytes + 1, want: 413},
		{route: "upload", media: "application/x-rpm", confirm: "true", header: base64.RawURLEncoding.EncodeToString([]byte(`{"manifest":{}}`)), want: 400},
		{route: "upload", media: "application/x-rpm", confirm: "true", filename: "../../unrelated", want: 400},
		{route: "upload", media: "application/x-rpm", confirm: "true", filename: "xe-antishell-central-0.1.0-20.el9.x86_64.rpm", header: "invalid", want: 400},
	} {
		r := httptest.NewRequest("POST", "http://localhost:9089"+centralUpdateBase+tc.route, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.media)
		r.Header.Set("X-Xeas-Central-Confirm", tc.confirm)
		if tc.header != "" {
			r.Header.Set("X-Xeas-Central-Manifest", tc.header)
		}
		if tc.filename != "" {
			r.Header.Set("X-Xeas-Central-Artifact", tc.filename)
		}
		if tc.length > 0 {
			r.ContentLength = tc.length
		}
		if w := client(r); w.Code != tc.want {
			t.Errorf("%s %s: got %d want %d", tc.route, tc.media, w.Code, tc.want)
		}
	}
}

func TestCentralUpdateExplainsWorkerRejection(t *testing.T) {
	w := httptest.NewRecorder()
	selfUpdateError(w, &selfupdate.ClientError{StatusCode: http.StatusConflict, Message: "insufficient free space for a full central state backup"})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "insufficient free space") {
		t.Fatal("operator cannot see the worker's specific reason for rejecting an update")
	}
}
