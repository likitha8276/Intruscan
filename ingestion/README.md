Local Layer 1 → Layer 2 pipeline
Layer 1 reads NetFlow/IPFIX-derived flow records from JSONL and archives the
normalized fields plus the exact input JSON in SQLite. A channel-based worker
pool archives records in transactions of up to 500. Rows are idempotent by
flow_id. Kafka is intentionally not part of this local integration.

The SQLite connection uses WAL, NORMAL synchronous mode, and a busy timeout.
No ORM is used.
Canonical input
{"flow_id":"f-001","timestamp":"2026-11-03T10:00:00Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":51000,"dst_port":443,"protocol":"tcp","packets":12,"bytes":4096,"duration_ms":125.5,"label":"benign"}
Required fields are flow_id, RFC3339 timestamp, src_ip, dst_ip,
src_port, dst_port, protocol, packets, bytes, and duration_ms.
label is optional, but training only uses records explicitly labeled
"benign". Unknown fields and malformed records fail the ingestion run.
Run end to end
From the repository root, use the included synthetic demo data:
cd ingestion
go run . -input ../sample_flows.jsonl -archive ../forensics_archive.db -workers 4
cd ..
python -m soc_agent.fast_brain_cli train \
  --archive forensics_archive.db --model fast_brain.joblib
python -m soc_agent.fast_brain_cli score \
  --archive forensics_archive.db --model fast_brain.joblib --output scored_flows.jsonl
sample_flows.jsonl is only a smoke-test fixture, not a representative training
dataset. For real use, replace its path with your exported flow JSONL. Train on
representative benign traffic; do not use attack-labeled records as the
Isolation Forest baseline. The archived model has exactly 51 trees. Scoring
outputs each original flow with s_score and route (CLEAR, SLOW_BRAIN, or
FAST_TRACK). Scores are normalized anomaly strengths, not calibrated
probabilities. Tune/evaluate routing thresholds against held-out labeled data
before operational use.
Layer 2 scoring
Four features are derived consistently by the Python runner: log1p(packets),
log1p(bytes), log1p(duration_ms), and log1p(bytes / packets) (zero when
packet count is zero). The library class is also available for direct use.
UGR'16 CSV conversion and direct scoring
The streaming converter at tools/parse_ugr16.py recognizes common UGR'16
headers such as SrcAddr, DstAddr, Proto, TotBytes, TotPkts, Label,
and Dur. It outputs the requested typed fields (flow_id, source_ip,
dest_ip, protocol, byte_count, packet_count, label) and adds
duration_ms when a duration column exists. UGR'16 Dur is interpreted as
seconds; a header ending in ms is interpreted as milliseconds. Override with
--duration-unit seconds or --duration-unit milliseconds when needed.
Malformed rows are skipped and counted; the converter streams rows and does not
buffer the dataset.
python tools/parse_ugr16.py /data/ugr16.csv ugr16_flows.jsonl
python -m soc_agent.fast_brain_cli train \
  --input ugr16_flows.jsonl --normal-label background \
  --model fast_brain.joblib
python -m soc_agent.fast_brain_cli score \
  --input ugr16_flows.jsonl --model fast_brain.joblib \
  --output scored_flows.jsonl
Use the dataset's exact normal/background label with --normal-label; repeat
the option to include more than one normal label. Training keeps at most
100,000 normal feature vectors in a seeded reservoir by default
(--max-training-rows changes the cap), so fitting does not retain every row.
The scorer emits one JSONL object per valid flow, retaining its input fields and
adding s_score and route. The SQLite ingester uses the separate richer
schema documented above; this direct JSONL mode avoids requiring extra flow
columns that are not in the compact UGR'16 conversion schema.

After scoring labeled UGR'16 data, estimate score-distribution cutoffs with:
python tools/calibrate_thresholds.py \
  --input scored_flows.jsonl --benign-label background
This prints benign 90th/95th/99th and anomalous 1st/5th/10th percentiles and
writes calibration_histogram.png. The suggested lower cutoff is the benign
95th percentile and the upper cutoff is the anomalous 5th percentile. These
are starting points for validation on held-out data, not calibrated malicious
probabilities; if the cutoffs overlap, the script warns that the distributions
do not support the suggested three-way band.
Slow Brain handoff
The handoff streams scored JSONL and sends only SLOW_BRAIN records to the
Layer 4 SOC CLI. The complete original flow is preserved as the event payload
and included in the analyst's untrusted log context; the event's canonical
parse_conf and match_conf are both set to 1.0.

Configure the provider keys in the repository-root .env file. For automatic
provider selection, set both GROQ_API_KEY and GEMINI_API_KEY. The CLI tries
Groq first and falls back to Gemini only for transient provider failures
(for example, rate limits, server errors, timeouts, or connection failures).
Authentication, configuration, and malformed-response errors do not trigger
fallback. Do not commit .env or share API keys.
python tools/slow_brain_handoff.py \
  --input scored_flows.jsonl --output final_soc_alerts.jsonl \
  --llm auto --model openai/gpt-oss-20b --timeout 120
To run with only one provider, use --llm groq or --llm gemini. The --llm sim mode is intended for deterministic pipeline testing, not live analysis.

Each result is appended immediately as JSONL with the original flow and
soc_result (including outcome, verdicts, gate flags, and reasons). A timed-out
inference is saved with a TIMEOUT outcome and processing continues. Temporary
event/context files are removed after each flow. The SOC CLI can also be called
directly with python -m soc_agent.cli --input <events.jsonl> --logs <logs.json>.