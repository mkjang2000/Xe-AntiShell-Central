package central

import (
	"context"
	"testing"
	"time"
)

func addDetectionRecords(t *testing.T, f *fixture, now time.Time) {
	t.Helper()
	finding := map[string]any{"rule_id": "web-shell", "severity": "high"}
	event := map[string]any{"event_id": "exec", "event_type": "process.exec"}
	bundle := func(findings ...any) map[string]any {
		return map[string]any{"event": event, "findings": append([]any{}, findings...)}
	}
	// A bundle counts once even when one event matched several rules.
	addHistoryRecord(t, f, "agent-a", "event_bundle", "two-rules", now.Add(-time.Hour), bundle(finding, finding))
	addHistoryRecord(t, f, "agent-a", "event_bundle", "latest", now.Add(-2*time.Minute), bundle(finding))
	addHistoryRecord(t, f, "agent-a", "finding", "standalone", now.Add(-23*time.Hour), finding)
	addHistoryRecord(t, f, "agent-a", "event_bundle", "window-start", now.Add(-consoleDetectionWindow), bundle(finding))
	// Neither older detections, bundles without findings nor plain events count.
	addHistoryRecord(t, f, "agent-a", "event_bundle", "old", now.Add(-consoleDetectionWindow-time.Nanosecond), bundle(finding))
	addHistoryRecord(t, f, "agent-a", "event_bundle", "quiet", now.Add(-time.Minute), bundle())
	addHistoryRecord(t, f, "agent-b", "event", "exec", now.Add(-time.Minute), event)
}

func TestConsoleStateCountsRecentDetectionsPerAgent(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.server.now = func() time.Time { return now }
	f.enroll(t, "agent-a")
	f.enroll(t, "agent-b")
	addDetectionRecords(t, f, now)
	var state struct {
		Agents []struct {
			ID    string     `json:"agent_id"`
			Count *int64     `json:"detections_24h"`
			Last  *time.Time `json:"last_detection_at"`
		} `json:"agents"`
		Detections consoleDetectionWindowInfo `json:"detections"`
	}
	consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
	if !state.Detections.Since.Equal(now.Add(-consoleDetectionWindow)) || state.Detections.Truncated {
		t.Fatalf("detection window=%+v", state.Detections)
	}
	seen := 0
	for _, agent := range state.Agents {
		switch agent.ID {
		case "agent-a":
			seen++
			if agent.Count == nil || *agent.Count != 4 || agent.Last == nil || !agent.Last.Equal(now.Add(-2*time.Minute)) {
				t.Fatalf("agent-a detections=%v last=%v", agent.Count, agent.Last)
			}
		case "agent-b":
			seen++
			// Zero is reported, so the console can tell it from an older server.
			if agent.Count == nil || *agent.Count != 0 || agent.Last != nil {
				t.Fatalf("agent-b detections=%v last=%v", agent.Count, agent.Last)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("agents=%+v", state.Agents)
	}
}

func TestRecentDetectionsReportTruncatedScan(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	addDetectionRecords(t, f, now)
	for _, test := range []struct {
		limit     int
		truncated bool
	}{{limit: 2, truncated: true}, {limit: 4, truncated: false}} {
		tx, err := f.store.db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		counts, info, err := consoleRecentDetections(context.Background(), tx, now.Add(-consoleDetectionWindow), test.limit)
		_ = tx.Rollback()
		if err != nil {
			t.Fatal(err)
		}
		if info.Truncated != test.truncated || !test.truncated && counts["agent-a"].Count != 4 {
			t.Fatalf("limit %d: counts=%+v info=%+v", test.limit, counts, info)
		}
	}
}
