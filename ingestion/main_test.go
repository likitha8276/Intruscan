package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestIngestArchivesFlowsAndConfiguresSQLite(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "archive.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	ctx := context.Background()
	if err := initializeArchive(ctx, db); err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	var synchronous int
	if err := db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if synchronous != 1 {
		t.Fatalf("synchronous = %d, want NORMAL (1)", synchronous)
	}

	line := `{"flow_id":"flow-1","timestamp":"2026-11-03T10:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":443,"protocol":"TCP","packets":12,"bytes":4096,"duration_ms":100.5,"label":"benign"}`
	input := strings.NewReader(line + "\n" + line + "\n")
	count, err := ingest(ctx, db, input, 2)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("input flow count = %d, want 2", count)
	}

	var archived int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM flow_archive").Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if archived != 1 {
		t.Fatalf("archived flow count = %d, want duplicate flow_id deduplicated to 1", archived)
	}
	var payload []byte
	if err := db.QueryRowContext(
		ctx, "SELECT raw_json FROM flow_archive WHERE flow_id = 'flow-1'",
	).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != line {
		t.Fatalf("raw JSON = %s, want exact original record", payload)
	}
}

func TestIngestRejectsMalformedRecordWithoutArchivingBatch(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "archive.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeArchive(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	valid := `{"flow_id":"flow-1","timestamp":"2026-11-03T10:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":443,"protocol":"TCP","packets":12,"bytes":4096,"duration_ms":100.5}`
	_, err = ingest(
		context.Background(),
		db,
		strings.NewReader(valid+"\n"+`{"flow_id":"invalid"}`+"\n"),
		1,
	)
	if err == nil {
		t.Fatal("expected invalid record error")
	}
	var count int
	if queryErr := db.QueryRow("SELECT COUNT(*) FROM flow_archive").Scan(&count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if count != 0 {
		t.Fatalf("archived %d records from a rejected batch, want 0", count)
	}
}

func TestIngestProcessesMultipleBatchesWithWorkers(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "archive.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	if err := initializeArchive(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	var input strings.Builder
	const flowCount = maxBatchSize*3 + 4
	for i := 0; i < flowCount; i++ {
		fmt.Fprintf(
			&input,
			`{"flow_id":"flow-%d","timestamp":"2026-11-03T10:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":443,"protocol":"TCP","packets":12,"bytes":4096,"duration_ms":100.5}`+"\n",
			i,
		)
	}
	count, err := ingest(context.Background(), db, strings.NewReader(input.String()), 4)
	if err != nil {
		t.Fatal(err)
	}
	if count != flowCount {
		t.Fatalf("input flow count = %d, want %d", count, flowCount)
	}
	var archived int
	if err := db.QueryRow("SELECT COUNT(*) FROM flow_archive").Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if archived != flowCount {
		t.Fatalf("archived flow count = %d, want %d", archived, flowCount)
	}
}
