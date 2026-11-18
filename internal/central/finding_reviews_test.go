package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

func TestFindingReviewsSelectImmutableItemAndEvidence(t *testing.T) {
	ctx := context.Background()
	f := setup(t)
	enrolled, _, _ := f.enroll(t, "agent-a")
	now := time.Unix(21000, 0).UTC()
	bundle := compactBundleFixture("event-1", `[{"finding_id":"one","rule_id":"rule-a","evidence_event_ids":["event-1"]},{"finding_id":"two","rule_id":"rule-b","policy_revision":17,"summary":"positive write","evidence_event_ids":["event-1"]}]`)
	standalone := managed.Record{Sequence: 2, Kind: "finding", ID: "event-1", Payload: json.RawMessage(`{"finding_id":"event-1","rule_id":"standalone","created_at":"2026-01-01T00:00:00Z","evidence_event_ids":["event-1"]}`)}
	other := compactBundleFixture("uncited", "null")
	other.Sequence = 3
	batch := managed.Batch{EnrollmentID: enrolled.EnrollmentID, SpoolID: "review-test", Records: []managed.Record{bundle, standalone, other}}
	if _, err := f.store.Ingest(ctx, "agent-a", batch, now); err != nil {
		t.Fatal(err)
	}
	client := updateConsoleClient(t, f)
	history := client("GET", "/api/history?view=detections", nil, "")
	var records []HistoryRecord
	if err := json.Unmarshal(history.Body.Bytes(), &records); err != nil || len(records) != 3 {
		t.Fatalf("history %d %s", history.Code, history.Body.String())
	}
	target := reviewTarget{Agent: "agent-a", Record: "event-1", findingLocation: findingLocation{"event_bundle", 2}}
	found := false
	for _, record := range records {
		if bytes.Contains(record.Payload, []byte(`"finding_id":"two"`)) {
			found = record.Location != nil && *record.Location == target.findingLocation
		}
	}
	if !found {
		t.Fatalf("source location for the second finding is missing: %+v", records)
	}
	var zero int64
	input := reviewInput{Target: target, Expected: &zero, Request: "decision-a", Verdict: "normal", Reason: "승인된 배포"}
	post := func(in reviewInput, code int) findingReview {
		t.Helper()
		body, _ := json.Marshal(in)
		w := client("POST", "/api/finding-reviews", body, "application/json")
		if w.Code != code {
			t.Fatalf("write received %d expected %d %s", w.Code, code, w.Body.String())
		}
		var r findingReview
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		return r
	}
	forged, _ := json.Marshal(input)
	forged = append(forged[:len(forged)-1], []byte(`,"actor":"other"}`)...)
	if w := client("POST", "/api/finding-reviews", forged, "application/json"); w.Code != http.StatusBadRequest {
		t.Fatalf("forged actor accepted: %d", w.Code)
	}
	first := post(input, http.StatusCreated)
	if first.Actor != "admin" || first.Version != 1 || first.At.IsZero() || first.At.Location() != time.UTC {
		t.Fatalf("review metadata %+v", first)
	}
	if got := post(input, http.StatusOK); got != first {
		t.Fatal("replay changed metadata")
	}
	conflict := input
	conflict.Reason = "changed"
	post(conflict, http.StatusConflict)
	conflict = input
	conflict.Target.Item = 1
	post(conflict, http.StatusConflict)
	next := input
	next.Request = "decision-b"
	next.Verdict = "suspicious"
	post(next, http.StatusConflict)
	next.Expected = &first.Version
	post(next, http.StatusCreated)
	if got := post(input, http.StatusOK); got != first {
		t.Fatal("old replay overwrote a new review")
	}
	wrong := input
	wrong.Request = "missing"
	wrong.Target.Item = 3
	post(wrong, http.StatusNotFound)
	wrong.Target.Item = 0
	post(wrong, http.StatusBadRequest)
	old, err := f.store.listReviews(ctx, reviewTarget{"agent-a", "event-1", findingLocation{"finding", 1}}, 0, 5)
	if err != nil || old.Latest != 0 || bytes.Contains(old.Finding, []byte("policy_revision")) {
		t.Fatalf("legacy source %+v %v", old, err)
	}
	if _, err = f.store.Ingest(ctx, "agent-a", batch, now); err != nil {
		t.Fatal(err)
	}
	if n, _, err := f.store.pruneObservationHistory(ctx, now.Add(2*time.Hour), 10); err != nil || n != 1 {
		t.Fatalf("expiry %d %v", n, err)
	}
	q := url.Values{"agent_id": {"agent-a"}, "record_id": {"event-1"}, "source": {"event_bundle"}, "item": {"2"}}
	get := func(extra string, code int) []byte {
		t.Helper()
		w := client("GET", "/api/finding-reviews?"+q.Encode()+extra, nil, "")
		if w.Code != code {
			t.Fatalf("read %d %s", w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	var page reviewPage
	if err := json.Unmarshal(get("", 200), &page); err != nil || page.Latest != 2 || len(page.Items) != 2 || page.Items[1] != first || !bytes.Contains(page.Finding, []byte(`"policy_revision":17`)) || !bytes.Contains(page.Finding, []byte(`"rule_id":"rule-b"`)) {
		t.Fatalf("post retention page: %+v %v", page, err)
	}
	evidence := get("&evidence_id=event-1", 200)
	if !bytes.Contains(evidence, []byte(`"event_id":"event-1"`)) || bytes.Contains(evidence, []byte("private-argument")) {
		t.Fatal("missing minimal evidence")
	}
	get("&evidence_id=uncited", 400)
	var audits int
	if err := f.store.db.QueryRow("SELECT count(*) FROM audit WHERE kind='finding.reviewed'").Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audits=%d: %v", audits, err)
	}
	if bytes.Contains(page.Finding, []byte("승인된")) {
		t.Fatal("modified source finding")
	}
}

func TestConcurrentReclassificationAndPagination(t *testing.T) {
	f := setup(t)
	now := time.Now()
	ctx := context.Background()
	addHistoryRecord(t, f, "agent-a", "finding", "review-me", now, map[string]string{"finding_id": "review-me", "rule_id": "rule"})
	target := reviewTarget{"agent-a", "review-me", findingLocation{"finding", 1}}
	var v int64
	results := make(chan error, 2)
	for _, who := range []string{"operator-a", "operator-b"} {
		go func(actor string) {
			_, _, err := f.store.appendReview(ctx, reviewInput{target, &v, "same-request", "deferred", "조사 중"}, actor, now)
			results <- err
		}(who)
	}
	ok, conflicts := 0, 0
	for range []int{0, 1} {
		err := <-results
		if err == nil {
			ok++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("ok %d conflicts %d", ok, conflicts)
	}
	for i := int64(1); i < 24; i++ {
		_, _, err := f.store.appendReview(ctx, reviewInput{target, &i, "next-" + strconv.FormatInt(i, 10), "normal", "재확인"}, "analyst", now)
		if err != nil {
			t.Fatal(err)
		}
	}
	a, err := f.store.listReviews(ctx, target, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.store.listReviews(ctx, target, a.Next, 20)
	if err != nil || a.Latest != 24 || a.Next != 5 || len(b.Items) != 4 || b.Next != 0 {
		t.Fatalf("pages %+v %+v %v", a, b, err)
	}
	newest := int64(24)
	for _, r := range append(a.Items, b.Items...) {
		if r.Version != newest {
			t.Fatalf("order %d vs %d", r.Version, newest)
		}
		newest--
	}
}
