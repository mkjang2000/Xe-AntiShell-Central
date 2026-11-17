package central

import (
	"encoding/base64"
	"net/http"
	"sort"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func (s *Server) verifyUpdatePublisher(publisher managed.SignedReleaseManifest) error {
	if _, err := managed.VerifyReleaseManifest(publisher, s.updatePublishers); err != nil {
		return ErrInvalid
	}
	return nil
}

func (s *Server) readUpdatePublisherHeader(r *http.Request) (managed.SignedReleaseManifest, error) {
	var publisher managed.SignedReleaseManifest
	values := r.Header.Values("X-XEAS-Release-Manifest")
	if len(values) != 1 || len(values[0]) > base64.RawURLEncoding.EncodedLen(managed.MaxReleaseManifestBytes) {
		return publisher, ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(values[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != values[0] || managed.DecodeStrict(body, managed.MaxReleaseManifestBytes, &publisher) != nil {
		return publisher, ErrInvalid
	}
	return publisher, s.verifyUpdatePublisher(publisher)
}

func (s *Server) updatePublisherIDs() []string {
	ids := make([]string, 0, len(s.updatePublishers))
	for id := range s.updatePublishers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
