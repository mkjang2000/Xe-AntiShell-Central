package console

import (
	"net/http"
	"testing"
)

func TestFindingReviewAccessUsesSessionAndCSRF(t *testing.T) {
	s, _ := testServer(t)
	defer s.Close()
	admin := testSession(t, s)
	_, operator := accountFixture(t, s, "analyst", RoleOperator)
	_, viewer := accountFixture(t, s, "reader", RoleViewer)
	for _, cookie := range []*http.Cookie{admin, operator, viewer} {
		if w := accountRequest(t, s, cookie, "GET", "/api/finding-reviews", nil, false); w.Code != 200 {
			t.Fatalf("read %d", w.Code)
		}
	}
	for _, tc := range []struct {
		cookie *http.Cookie
		csrf   bool
		code   int
	}{{admin, true, 200}, {operator, true, 200}, {viewer, true, 403}, {operator, false, 403}} {
		if w := accountRequest(t, s, tc.cookie, "POST", "/api/finding-reviews", map[string]string{}, tc.csrf); w.Code != tc.code {
			t.Fatalf("write %d want %d", w.Code, tc.code)
		}
	}
}
