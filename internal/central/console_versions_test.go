package central

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestConsoleRecreatedDraftRejectsStaleSaveAndDelete(t *testing.T) {
	for _, kind := range []struct {
		path  string
		build func(int64, string) any
	}{
		{"groups", func(version int64, name string) any {
			return ConsoleGroup{ID: "reused", Name: name, Version: version}
		}},
		{"templates", func(version int64, name string) any {
			return ConsoleTemplate{ID: "reused", Name: name, Version: version, Settings: defaultConsoleSettings(time.Now())}
		}},
	} {
		t.Run(kind.path, func(t *testing.T) {
			f := setup(t)
			path := "/api/" + kind.path
			var saved struct {
				Version int64 `json:"version"`
			}
			consoleWant(t, f.console(t, "POST", path, kind.build(0, "original")), 200, &saved)
			if saved.Version != 1 {
				t.Fatalf("initial version=%d", saved.Version)
			}
			consoleWant(t, f.console(t, "DELETE", path+"/reused?version=1", nil), 200, nil)
			consoleWant(t, f.console(t, "POST", path, kind.build(0, "recreated")), 200, &saved)
			if saved.Version != 2 {
				t.Fatalf("recreated version reset to %d", saved.Version)
			}
			consoleWant(t, f.console(t, "POST", path, kind.build(1, "stale overwrite")), 409, nil)
			consoleWant(t, f.console(t, "DELETE", path+"/reused?version=1", nil), 409, nil)
			var state struct {
				Groups []struct {
					Name    string `json:"name"`
					Version int64  `json:"version"`
				} `json:"groups"`
				Templates []struct {
					Name    string `json:"name"`
					Version int64  `json:"version"`
				} `json:"templates"`
			}
			consoleWant(t, f.console(t, "GET", "/api/state", nil), 200, &state)
			if kind.path == "groups" && (len(state.Groups) != 1 || state.Groups[0].Name != "recreated" || state.Groups[0].Version != 2) || kind.path == "templates" && (len(state.Templates) != 1 || state.Templates[0].Name != "recreated" || state.Templates[0].Version != 2) {
				t.Fatalf("stale edit changed recreated record: %+v", state)
			}
			consoleWant(t, f.console(t, "POST", path, kind.build(2, "edited")), 200, &saved)
			if saved.Version != 3 {
				t.Fatalf("edited version=%d", saved.Version)
			}
			consoleWant(t, f.console(t, "DELETE", path+"/reused?version=3", nil), 200, nil)
			consoleWant(t, f.console(t, "POST", path, kind.build(0, "recreated again")), 200, &saved)
			if saved.Version != 4 {
				t.Fatalf("edited/deleted version was lost: %d", saved.Version)
			}
		})
	}
}

func TestConsoleVersionLedgerMigrationAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "central.db")
	open := func() *Store {
		store, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return store
	}
	store := open()
	group, err := store.saveConsoleGroup(ctx, ConsoleGroup{ID: "persisted", Name: "original"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an earlier schema-v2 database that has live drafts but no ledger.
	if _, err = store.db.Exec("DROP TABLE console_record_versions"); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store = open()
	var seeded int64
	if err = store.db.QueryRow("SELECT last_version FROM console_record_versions WHERE kind='console_groups' AND id='persisted'").Scan(&seeded); err != nil || seeded != group.Version {
		t.Fatalf("existing version not migrated: %d %v", seeded, err)
	}
	group.Name = "edited"
	group, err = store.saveConsoleGroup(ctx, group, time.Now())
	if err != nil || group.Version != 2 {
		t.Fatalf("migrated edit=%+v error=%v", group, err)
	}
	if err = store.deleteConsoleRecord(ctx, true, group.ID, group.Version, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store = open()
	recreated, err := store.saveConsoleGroup(ctx, ConsoleGroup{ID: group.ID, Name: "recreated"}, time.Now())
	if err != nil || recreated.Version != 3 {
		t.Fatalf("deleted version lost across restart: %+v %v", recreated, err)
	}
}
