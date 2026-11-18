package central

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

const storageBenchAgents = 4
const storageBenchBatch = 32
const storageBenchBatches = 8

type storageBenchDelivery struct {
	agent string
	batch managed.Batch
}

// Use a fixed, pre-encoded workload on each run. The process CPU and logical
// WAL measure Ingest and TTL deletion; they exclude fixture creation, online
// vacuum, checkpoints, sender costs and unrelated services.
func BenchmarkOrdinaryHistoryStorage(b *testing.B) {
	b.StopTimer()
	ctx := context.Background()
	start := time.Unix(1800000000, 0).UTC()
	deliveries := make([]storageBenchDelivery, 0, storageBenchAgents*storageBenchBatches)
	for group := 0; group < storageBenchBatches; group++ {
		for host := 0; host < storageBenchAgents; host++ {
			agent := fmt.Sprintf("fixture-host-%02d", host)
			batch := managed.Batch{EnrollmentID: fmt.Sprintf("enroll_%032x", host+1), SpoolID: fmt.Sprintf("spool_%032x", host+1)}
			for offset := 1; offset <= storageBenchBatch; offset++ {
				sequence := uint64(group*storageBenchBatch + offset)
				sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", agent, sequence)))
				id := fmt.Sprintf("event_%x", sum[:16])
				event := model.Event{
					SchemaVersion: "1", ID: id, HostID: agent, BootID: "fixture-boot",
					StreamID: "fixture-stream", Sequence: sequence, EventTime: start, IngestTime: start,
					Type: "process.exec", Source: "tetragon", SourceEventID: fmt.Sprintf("%x", sum[16:]),
					Process: model.Process{Key: fmt.Sprintf("proc_%x", sum[:16]), PID: int(sequence),
						Exe: "/usr/bin/true", PPID: 1, FirstSeen: start, LastSeen: start, StartTime: start},
				}
				payload, err := json.Marshal(managed.EventBundle{Event: event})
				if err != nil {
					b.Fatal(err)
				}
				batch.Records = append(batch.Records, managed.Record{Sequence: sequence, ID: id, Kind: managed.RecordKindEventBundle, Payload: payload})
			}
			deliveries = append(deliveries, storageBenchDelivery{agent, batch})
		}
	}
	var wal, ingestWAL, used, allocated, cpu, elapsed int64
	const total = storageBenchAgents * storageBenchBatch * storageBenchBatches
	for i := 0; i < b.N; i++ {
		path := filepath.Join(b.TempDir(), "central.db")
		empty, err := sql.Open("sqlite", path)
		if err != nil {
			b.Fatal(err)
		}
		// Production databases using incremental auto-vacuum have pointer-map
		// pages. Set this before creating any tables.
		if _, err = empty.Exec("PRAGMA auto_vacuum=INCREMENTAL"); err != nil {
			b.Fatal(err)
		}
		if err = empty.Close(); err != nil {
			b.Fatal(err)
		}
		store, err := Open(ctx, path)
		if err != nil {
			b.Fatal(err)
		}
		for _, delivery := range deliveries[:storageBenchAgents] {
			if _, err := store.db.Exec("INSERT INTO agents(agent_id,enrollment_id,cert_serial,enrolled_at_ns) VALUES(?,?,?,?)",
				delivery.agent, delivery.batch.EnrollmentID, delivery.agent, start.UnixNano()); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := store.db.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
			b.Fatal(err)
		}
		var busy, frames, checkpointed int
		if err = store.db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &checkpointed); err != nil || busy != 0 {
			b.Fatalf("reset WAL: busy=%d: %v", busy, err)
		}
		initialBytes := storageBenchLiveBytes(b, store)
		initialFile := storageBenchFileSize(b, path)
		cpuStart := storageBenchCPU(b)
		b.StartTimer()
		wallStart := time.Now()
		for index, delivery := range deliveries {
			ack, err := store.Ingest(ctx, delivery.agent, delivery.batch, start.Add(time.Duration(index)*time.Millisecond))
			if err != nil || ack.Acknowledged != delivery.batch.Records[storageBenchBatch-1].Sequence {
				b.Fatalf("ingest: %+v %v", ack, err)
			}
		}
		ingestWAL += storageBenchFileSize(b, path+"-wal")
		for expired := 0; expired < total; {
			n, backfilled, err := store.pruneObservationHistory(ctx, start.Add(2*time.Hour), 128)
			if err != nil || n == 0 || backfilled {
				b.Fatalf("expire: processed=%d, backfilled=%t: %v", n, backfilled, err)
			}
			expired += n
		}
		elapsed += time.Since(wallStart).Nanoseconds()
		cpu += storageBenchCPU(b) - cpuStart
		b.StopTimer()
		wal += storageBenchFileSize(b, path+"-wal")
		used += storageBenchLiveBytes(b, store) - initialBytes
		if err := store.Close(); err != nil {
			b.Fatal(err)
		}
		allocated += storageBenchFileSize(b, path) - initialFile
	}
	events := float64(b.N) * total
	b.ReportMetric(float64(cpu)/events, "cpu-ns/event")
	b.ReportMetric(float64(elapsed)/events, "wall-ns/event")
	b.ReportMetric(float64(wal)/events, "WAL-B/event")
	b.ReportMetric(float64(ingestWAL)/events, "ingest-WAL-B/event")
	b.ReportMetric(float64(used)/events, "retained-B/event")
	b.ReportMetric(float64(allocated)/events, "allocated-DB-B/event")
}

func storageBenchCPU(b *testing.B) int64 {
	b.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		b.Fatal(err)
	}
	return usage.Utime.Nano() + usage.Stime.Nano()
}

func storageBenchLiveBytes(b *testing.B, store *Store) int64 {
	b.Helper()
	var size, pages, free int64
	if err := store.db.QueryRow("SELECT page_size, page_count, freelist_count FROM pragma_page_size, pragma_page_count, pragma_freelist_count").Scan(&size, &pages, &free); err != nil {
		b.Fatal(err)
	}
	return (pages - free) * size
}

func storageBenchFileSize(b *testing.B, path string) int64 {
	b.Helper()
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	return info.Size()
}
