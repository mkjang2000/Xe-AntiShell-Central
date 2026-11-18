package central

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func TestObservationReclaimSchedule(t *testing.T) {
	start := time.Unix(10000, 0)
	next := start.Add(observationReclaimInterval)
	for _, tt := range []struct {
		name    string
		now     time.Time
		backlog bool
		want    bool
	}{
		{"startup", start, false, false},
		{"before deadline", next.Add(-time.Nanosecond), false, false},
		{"expiry backlog", next, true, false},
		{"caught up", next.Add(time.Second), false, true},
		{"another idle tick", next.Add(2 * time.Second), false, false},
		{"next attempt", next.Add(time.Second + observationReclaimInterval), false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := next
			var due bool
			next, due = scheduleObservationReclaim(tt.now, next, tt.backlog)
			if due != tt.want || (due && next != tt.now.Add(observationReclaimInterval)) || (!due && next != old) {
				t.Fatalf("due=%t next=%v, want due=%t; old deadline=%v", due, next, tt.want, old)
			}
		})
	}
}

func TestObservationReclaimReservesFreePagesAndBoundsEachStep(t *testing.T) {
	for _, pageSize := range []int64{4096, 16384} {
		t.Run(fmt.Sprint(pageSize), func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			_, err = db.Exec(fmt.Sprintf("PRAGMA page_size=%d; PRAGMA auto_vacuum=INCREMENTAL; CREATE TABLE scratch(data BLOB)", pageSize))
			if err != nil {
				t.Fatal(err)
			}
			freeBytes := func() int64 {
				t.Helper()
				var pages int64
				if err := db.QueryRow("PRAGMA freelist_count").Scan(&pages); err != nil {
					t.Fatal(err)
				}
				return pages * pageSize
			}
			if _, err = db.Exec("INSERT INTO scratch VALUES(zeroblob(?))", observationReclaimReserve+2*observationReclaimMaxBytes); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("DELETE FROM scratch"); err != nil {
				t.Fatal(err)
			}
			initial := freeBytes()
			if initial < observationReclaimReserve+observationReclaimMaxBytes {
				t.Fatalf("insufficient free pages in fixture: %d bytes", initial)
			}
			store := &Store{db: db}
			before := initial
			for {
				if err := store.reclaimObservationPages(context.Background()); err != nil {
					t.Fatal(err)
				}
				after := freeBytes()
				wantChange := min(before-observationReclaimReserve, int64(observationReclaimMaxBytes))
				if change := before - after; change != wantChange {
					t.Fatalf("released %d bytes, want %d (before %d, after %d)", change, wantChange, before, after)
				}
				if before == after {
					break
				}
				before = after
			}
		})
	}
}
