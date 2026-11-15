package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultArchivePath = "forensics_archive.db"
	maxBatchSize       = 500
	maxRecordBytes     = 16 << 20
)

type config struct {
	input       string
	archive     string
	workerCount int
}

type flowRecord struct {
	FlowID     string                     `json:"flow_id"`
	Timestamp  string                     `json:"timestamp"`
	SrcIP      string                     `json:"src_ip"`
	DstIP      string                     `json:"dst_ip"`
	SrcPort    *uint16                    `json:"src_port"`
	DstPort    *uint16                    `json:"dst_port"`
	Protocol   string                     `json:"protocol"`
	Packets    *uint64                    `json:"packets"`
	Bytes      *uint64                    `json:"bytes"`
	DurationMS *float64                   `json:"duration_ms"`
	Label      string                     `json:"label,omitempty"`
	Metadata   map[string]json.RawMessage `json:"metadata,omitempty"`
	Features   map[string]float64         `json:"features,omitempty"`
	RawJSON    json.RawMessage            `json:"-"`
}

type batchJob struct {
	lines  [][]byte
	result chan error
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func loadConfig() (config, error) {
	var cfg config
	flag.StringVar(&cfg.input, "input", "flows.jsonl", "input NetFlow/IPFIX JSONL file")
	flag.StringVar(&cfg.archive, "archive", defaultArchivePath, "SQLite archive path")
	flag.IntVar(&cfg.workerCount, "workers", 4, "number of concurrent archival workers")
	flag.Parse()
	if cfg.workerCount < 1 {
		return config{}, fmt.Errorf("-workers must be a positive integer")
	}
	return cfg, nil
}

func run(ctx context.Context, cfg config) error {
	if cfg.workerCount < 1 {
		return fmt.Errorf("worker count must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.archive), 0o750); err != nil && filepath.Dir(cfg.archive) != "." {
		return fmt.Errorf("create archive directory: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(cfg.archive))
	if err != nil {
		return fmt.Errorf("open archive database: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(cfg.workerCount)
	db.SetMaxIdleConns(cfg.workerCount)
	if err := initializeArchive(ctx, db); err != nil {
		return err
	}
	file, err := os.Open(cfg.input)
	if err != nil {
		return fmt.Errorf("open input %q: %w", cfg.input, err)
	}
	defer file.Close()

	count, err := ingest(ctx, db, file, cfg.workerCount)
	if err != nil {
		return err
	}
	log.Printf("archived %d flows from %s into %s", count, cfg.input, cfg.archive)
	return nil
}

func ingest(ctx context.Context, db *sql.DB, input io.Reader, workerCount int) (int64, error) {
	if workerCount < 1 {
		return 0, fmt.Errorf("worker count must be positive")
	}
	jobs := make(chan batchJob, workerCount)
	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go archiveWorker(ctx, &workers, db, jobs)
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxRecordBytes)
	var total int64
	batch := make([][]byte, 0, maxBatchSize)
	pending := make([]chan error, 0, workerCount)
	var batchErr error
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		batch = append(batch, line)
		total++
		if len(batch) == maxBatchSize {
			result, err := queueBatch(ctx, jobs, batch)
			if err != nil {
				batchErr = err
				break
			}
			pending = append(pending, result)
			batch = make([][]byte, 0, maxBatchSize)
			if len(pending) == workerCount {
				completed := pending
				pending = make([]chan error, 0, workerCount)
				if err := waitBatchResults(completed); err != nil {
					batchErr = err
					break
				}
			}
		}
	}
	if batchErr == nil {
		batchErr = scanner.Err()
	}
	if batchErr == nil && len(batch) > 0 {
		var result chan error
		result, batchErr = queueBatch(ctx, jobs, batch)
		if batchErr == nil {
			pending = append(pending, result)
		}
	}
	close(jobs)
	waitErr := waitBatchResults(pending)
	workers.Wait()
	if batchErr != nil {
		return 0, batchErr
	}
	if waitErr != nil {
		return 0, waitErr
	}
	return total, nil
}

func queueBatch(ctx context.Context, jobs chan<- batchJob, lines [][]byte) (chan error, error) {
	result := make(chan error, 1)
	select {
	case jobs <- batchJob{lines: lines, result: result}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return result, nil
}

func waitBatchResults(results []chan error) error {
	var firstErr error
	for _, result := range results {
		if err := <-result; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func archiveWorker(ctx context.Context, workers *sync.WaitGroup, db *sql.DB, jobs <-chan batchJob) {
	defer workers.Done()
	for job := range jobs {
		job.result <- insertBatch(ctx, db, job.lines)
	}
}

func insertBatch(ctx context.Context, db *sql.DB, lines [][]byte) error {
	records := make([]flowRecord, len(lines))
	for i, line := range lines {
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&records[i]); err != nil {
			return fmt.Errorf("decode JSONL record in batch at line %d: %w", i+1, err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return fmt.Errorf("decode JSONL record in batch at line %d: %w", i+1, err)
		}
		records[i].RawJSON = append(json.RawMessage(nil), line...)
		if err := validateRecord(records[i]); err != nil {
			return fmt.Errorf("invalid flow record in batch at line %d: %w", i+1, err)
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin archive transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO flow_archive
			(flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
			 packets, bytes, duration_ms, label, raw_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(flow_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("prepare archive insert: %w", err)
	}
	defer stmt.Close()
	for _, record := range records {
		timestamp, _ := time.Parse(time.RFC3339Nano, record.Timestamp)
		if _, err := stmt.ExecContext(
			ctx, record.FlowID, timestamp.UTC(), record.SrcIP, record.DstIP,
			*record.SrcPort, *record.DstPort, strings.ToLower(record.Protocol),
			*record.Packets, *record.Bytes, *record.DurationMS, nullableLabel(record.Label),
			[]byte(record.RawJSON),
		); err != nil {
			return fmt.Errorf("insert flow %q: %w", record.FlowID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit archive batch: %w", err)
	}
	return nil
}

func validateRecord(record flowRecord) error {
	if strings.TrimSpace(record.FlowID) == "" {
		return fmt.Errorf("flow_id is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
		return fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	if strings.TrimSpace(record.SrcIP) == "" || strings.TrimSpace(record.DstIP) == "" {
		return fmt.Errorf("src_ip and dst_ip are required")
	}
	if strings.TrimSpace(record.Protocol) == "" {
		return fmt.Errorf("protocol is required")
	}
	if record.SrcPort == nil || record.DstPort == nil {
		return fmt.Errorf("src_port and dst_port are required")
	}
	if record.Packets == nil || record.Bytes == nil {
		return fmt.Errorf("packets and bytes are required")
	}
	if record.DurationMS == nil {
		return fmt.Errorf("duration_ms is required")
	}
	if *record.DurationMS < 0 {
		return fmt.Errorf("duration_ms must be non-negative")
	}
	for name, value := range record.Features {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("feature names must not be empty")
		}
		if value < 0 {
			return fmt.Errorf("feature %q must be non-negative", name)
		}
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values in one line")
		}
		return err
	}
	return nil
}

func nullableLabel(label string) any {
	if label == "" {
		return nil
	}
	return label
}

func initializeArchive(ctx context.Context, db *sql.DB) error {
	const schema = `
		CREATE TABLE IF NOT EXISTS flow_archive (
			flow_id TEXT PRIMARY KEY,
			timestamp DATETIME NOT NULL,
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			src_port INTEGER NOT NULL,
			dst_port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			packets INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			duration_ms REAL NOT NULL,
			label TEXT,
			raw_json BLOB NOT NULL
		)`
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create archive schema: %w", err)
	}
	return nil
}

func sqliteDSN(path string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator +
		"_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
}
