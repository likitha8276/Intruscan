# IntruScan integration matrix

Evidence = an automated test that runs in `pytest` (offline, no Go toolchain, no LLM keys).
"Go" rows are covered by `ingestion/main_test.go` (run `cd ingestion && go test ./...`).

| # | Component | Input | Output | Upstream | Downstream | Evidence | Open gap |
|---|-----------|-------|--------|----------|------------|----------|----------|
| 1 | Go ingester `ingestion/main.go` | flow JSONL | SQLite `flow_archive` (+`raw_json`) | file | 3 | `main_test.go`; schema mirrored in `test_end_to_end_pipeline` | JSONL file only; no live producer; one bad record rejects its batch |
| 2 | Flow contract `soc_agent/flow_contract.py` | any flow dict/JSONL | problems list | - | 1, 3, 3b, 4 | `test_flow_contract` (parses Go struct tags; fails on drift) | an older UGR16 parser emitted legacy keys (`source_ip`, `packet_count`), not canonical; use the native converter (row 3b) |
| 3 | CICIDS parser `tools/parse_cicids2017.py` | CICIDS CSV | canonical JSONL | CSV upload | 4, dashboard | `test_parse_cicids2017`, contract check in e2e | relative timestamps are surrogates (flagged, quarantined downstream) |
| 3b | UGR'16 native converter `tools/parse_ugr16_native.py` | UGR'16 flow CSV | canonical JSONL | CSV file | 4 | `tests/test_parse_ugr16_native.py` | timestamps are wall-clock UTC by assumption (the dataset states no time zone); the `background` label is not verified benign |
| 4 | Fast Brain CLI `fast_brain_cli.py` | JSONL or archive | scored JSONL (`s_score`,`route`) | 1, 3 or 3b | 5, 8 | `test_v2_cli_integration`, `test_end_to_end_pipeline` | thresholds fall back to 0.40/0.85 if none approved (see below); UGR'16 v3 thresholds are approved in `soc_agent/thresholds.json` (2026-11-17, model sha256 prefix `9f2e1e30`) |
| 5 | RAG bridge `rag/bridge.py` | scored JSONL | signed events + logs | 4 | 6 | e2e (real subprocess, key set) | MITRE index stubbed in tests; real MiniLM/Chroma path not exercised offline |
| 6 | Slow Brain `soc_agent/cli.py` + verifier | events, logs | verdict JSON | 5 | 7 | `test_pipeline`, `test_verifier`, e2e with `--llm sim` | Groq/Gemini paths need live keys |
| 7 | Incident store `incidents.py` | CLI results, scored rows | SQLite incidents | 4, 6 | 8 | e2e: slow_brain + untimed incidents recorded, feature_set=v2 | - |
| 8 | Dashboard `dashboard/` | scored JSONL, incident DB | Streamlit views | 4, 7 | - | e2e loads scored data via `dashboard.data` | UI itself untested; viewing scored files and incident DBs (e.g. UGR'16) needs no model, but the upload button is CICIDS2017-only and needs `data/models/fast_brain_cicids2017.joblib` (not in repo) |

## Contracts now enforced
* **Flow**: `flow_contract.py` == Go `flowRecord` + `validateRecord`. `provenance_signature` is **not** a flow field.
* **Provenance trust boundary**: flows are unsigned; `rag.bridge` HMAC-signs each *event* with `SOC_PROVENANCE_KEY`; `soc_agent.cli` verifies. e2e runs with the key set and every incident returns status OK.
* **Feature set**: the trained model records `v1|v2`; training takes `--feature-set`; scoring ignores any caller choice and uses the model's set.
* **Timestamps**: parser flags `timestamp_is_wall_clock`; metadata survives archive and scoring; surrogate-time flows become `untimed` incidents and never reach the LLM (asserted).
* **Two ingestion paths agree**: archive scoring and JSONL scoring give identical scores, routes and metadata (asserted).

## Findings that need your decision
1. **Uncalibrated fallback thresholds.** Isolation-Forest scores of ordinary traffic sit around 0.42-0.62, so the built-in `lower=0.40` routes essentially everything (even the training set) to SLOW_BRAIN. Run `tools/calibrate_thresholds.py` and approve a thresholds file bound to the model before any real run; the e2e test deliberately uses the fallback and does not assert CLEAR counts.
   **UGR'16 result (2026-11-17):** calibrating `fast_brain_ugr16_v2.joblib` on a 28 July UGR'16 CALIB sample (260,994 `background` flows against 190,681 `blacklist` and 138,321 dos/scan/botnet flows) found no threshold pair meeting at most 5% benign escalation and at least 60% attack escalation recall. Recall at the 5% benign cap was 4.0% (`blacklist`) and 0.28% (dos/scan/botnet). No candidate or approved file exists for this model, so UGR'16 runs use 0.40/0.85 and route every scored flow to SLOW_BRAIN. This is a limit of the model's features on this data, not a threshold bug; improving the features is future work. `background` is not verified benign.
   **UGR'16 v3 update (2026-11-17):** `fast_brain_ugr16_v3.joblib` (TCP-flag features, sha256 prefix `9f2e1e30`) reaches 56% attack recall (dos, scan, botnet) at the 5% benign-escalation cap on CALIB, and 56.15% on 29 July. The recall target was relaxed from 60% to 55% after seeing CALIB. Thresholds lower=0.596033, upper=0.635351 were approved on 2026-11-17 and are bound to that model file; retraining v3 invalidates them. Per-label recall on 29 July: scan11 99.6%, scan44 80.8%, dos 50.1%, botnet 4.1%. Blacklist was excluded from this evaluation (about 6% recall on CALIB). About 44% of attacks still route to CLEAR, and the dos `.A..S.` pattern is missed entirely. The 0.40/0.85 fallback above applies only when no approved file exists.
2. **Dashboard bootstrap.** The upload (pipeline) button is CICIDS2017-specific and needs a trained model at `data/models/fast_brain_cicids2017.joblib`; none ships, so on a fresh clone the button errors at step 1. Viewing existing scored files and incident databases works without it. The UGR'16 upload option also needs `data/raw/ugr16_train.jsonl` (baseline) locally; it is not in the repo. Train one with `python -m soc_agent.fast_brain_cli train --input flows.jsonl --model data/models/fast_brain_cicids2017.joblib --feature-set v2`.
3. **Go not run here.** Parity is checked from the Go source; run `go test ./...` locally.
4. **Live ingestion** is out of scope unless your capstone needs it; there is no Kafka/pcap producer.