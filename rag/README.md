# rag: Layer 3 bridge (VectorRAG + GraphRAG)

Reads the scored flows from Layer 2 and hands context-enriched incidents to the Layer 4 SOC agent.

## Run (from the repo root, venv active)

    python -m rag.bridge  --scored scored_flows.jsonl --baseline-file NORMAL_FLOWS.jsonl --baseline-label NORMAL_LABEL
    python -m rag.handoff --scored scored_flows.jsonl --baseline-file NORMAL_FLOWS.jsonl --baseline-label NORMAL_LABEL --output rag_soc_alerts.jsonl
    python -m rag.handoff ... --llm sim          # t
    # test the plumbing without an API provider
    python -m rag.retrieval_check [--mitre full] [--bench]  # test the MITRE lookup; --bench scores 14 attack behaviours

NORMAL_FLOWS.jsonl is the data the fast brain was trained on; NORMAL_LABEL is the same label used for
`fast_brain_cli train --normal-label`. Extra packages beyond requirements.txt: chromadb, sentence-transformers.

## Files

| File | Job |
|---|---|
| bridge.py | scored flows -> events.jsonl + logs.json (MITRE and host-graph context) |
| handoff.py | groups SLOW_BRAIN flows per source host, calls `soc_agent.cli` once per host |
| event_builder.py | flow -> event (rel is always `connect`), heuristic behaviour label, retrieval phrases |
| graph_store.py | NetworkX host graph: authorized pairs, unauthorized edges, blast radius |
| mitre_store.py | ChromaDB vector store (MiniLM, cosine) of ATT&CK techniques |
| mitre_loader.py | loads the official ATT&CK Enterprise matrix (`--mitre full`) |
| retrieval_check.py | prints top matches per behaviour phrase for tuning |

## Notes and limits

- Only SLOW_BRAIN flows are processed. FAST_TRACK bypasses this layer. The ground truth `label` is never forwarded.
- Events use `rel = connect` plus one `baseline_connect` summary per authorized host pair. Scan, brute force and
  exfiltration labels are heuristics and appear only in the log text, marked as inferred.
- Behaviour labels: PORT_SCAN, BRUTE_FORCE_SUSPECTED, EXFIL_SUSPECTED, DOS_FLOOD_SUSPECTED. Anything else is ANOMALOUS_FLOW and gets no lookup.
- MITRE lookup defaults to the official ATT&CK Enterprise matrix filtered to network detectable techniques
  (231). The first run downloads about 55 MB into ./mitre_cache/ (do not commit it). `--mitre seed` is a 4 technique
  offline fallback (T1110, T1046, T1041, T1071). On a hand written 14 case benchmark (`retrieval_check --bench`) the
  full matrix scored top-1 10/14 and top-3 12/14; the seed scored 6/14 and 7/14.
- Sub-techniques are rolled up to their parent (flows cannot tell Password Spraying from Password Guessing). Matches
  are shown as candidates, not verdicts: cosine confidence does not separate right from wrong matches on the full matrix.
  Filter defaults (min-conf 0.30, gap 0.10, max-hits 2) are starting values.
- The agent sees at most 12 flows per host (earliest first) plus baseline events.
