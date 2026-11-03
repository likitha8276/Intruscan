import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from tools.slow_brain_handoff import map_flow_to_event, process_file


def _flow(flow_id, route):
    return {
        "flow_id": flow_id,
        "timestamp": "2016-01-01T00:00:00Z",
        "source_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "protocol": "tcp",
        "byte_count": 8000,
        "packet_count": 10,
        "label": "background",
        "s_score": 0.6,
        "route": route,
    }


def test_map_flow_preserves_entire_payload_and_adds_event_fields():
    flow = _flow("flow_000001", "SLOW_BRAIN")

    event = map_flow_to_event(flow)

    assert all(event[key] == value for key, value in flow.items())
    assert event["event_id"] == flow["flow_id"]
    assert event["ts"] == flow["timestamp"]
    assert event["rel"] == "network_flow_tcp"
    assert event["src"] == flow["source_ip"]
    assert event["dst"] == flow["dest_ip"]
    assert event["parse_conf"] == event["match_conf"] == 1.0


def test_process_file_filters_routes_persists_timeout_and_cleans_tempfiles(tmp_path):
    source = tmp_path / "scored.jsonl"
    destination = tmp_path / "final_soc_alerts.jsonl"
    flows = [
        _flow("slow-timeout", "SLOW_BRAIN"),
        _flow("clear", "CLEAR"),
        _flow("slow-ok", "SLOW_BRAIN"),
        _flow("fast", "FAST_TRACK"),
    ]
    source.write_text(
        "".join(json.dumps(flow) + "\n" for flow in flows),
        encoding="utf-8",
    )
    calls = 0
    temp_paths = []

    def fake_run(command, **kwargs):
        nonlocal calls
        calls += 1
        assert kwargs["timeout"] == 2.0
        assert command[command.index("--llm") + 1] == "ollama"
        event_path = Path(command[command.index("--input") + 1])
        logs_path = Path(command[command.index("--logs") + 1])
        temp_paths.extend((event_path, logs_path))
        event = json.loads(event_path.read_text(encoding="utf-8"))
        assert event["parse_conf"] == event["match_conf"] == 1.0
        assert event["byte_count"] == 8000
        context = json.loads(logs_path.read_text(encoding="utf-8"))[event["event_id"]]
        assert json.loads(context)["s_score"] == 0.6
        if calls == 1:
            raise subprocess.TimeoutExpired(command, 2.0, output="partial")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "outcome": "ESCALATE",
                    "reasons": ["needs analyst"],
                    "verdicts": ["UNKNOWN"],
                    "gate_flags": [],
                }
            ),
            stderr="",
        )

    with patch("tools.slow_brain_handoff.subprocess.run", side_effect=fake_run):
        processed, ignored, invalid = process_file(
            source,
            destination,
            "python",
            "llama3.1:8b",
            "http://localhost:11434",
            "D_full",
            2.0,
        )

    results = [json.loads(line) for line in destination.read_text().splitlines()]
    assert (processed, ignored, invalid) == (2, 2, 0)
    assert len(results) == 2
    assert results[0]["soc_result"]["outcome"] == "TIMEOUT"
    assert results[0]["soc_result"]["verdicts"] == ["TIMEOUT"]
    assert results[0]["soc_result"]["stdout"] == "partial"
    assert results[1]["flow_id"] == "slow-ok"
    assert results[1]["soc_result"]["verdicts"] == ["UNKNOWN"]
    assert all(not path.exists() for path in temp_paths)


def test_process_file_logs_invalid_flow_and_continues(tmp_path):
    source = tmp_path / "scored.jsonl"
    destination = tmp_path / "final_soc_alerts.jsonl"
    invalid = _flow("missing-time", "SLOW_BRAIN")
    del invalid["timestamp"]
    valid = _flow("valid", "SLOW_BRAIN")
    source.write_text(
        json.dumps(invalid) + "\n" + json.dumps(valid) + "\n",
        encoding="utf-8",
    )
    completed = subprocess.CompletedProcess(
        ["python"], 0, stdout='{"outcome":"ESCALATE","verdicts":[],"reasons":[],"gate_flags":[]}', stderr=""
    )
    with patch("tools.slow_brain_handoff.subprocess.run", return_value=completed) as run:
        processed, ignored, invalid_count = process_file(
            source, destination, "python", "llama3.1:8b",
            "http://localhost:11434", "D_full", 2.0,
        )
    results = [json.loads(line) for line in destination.read_text().splitlines()]
    assert (processed, ignored, invalid_count) == (2, 0, 1)
    assert results[0]["soc_result"]["status"] == "INVALID_FLOW"
    assert results[1]["soc_result"]["outcome"] == "ESCALATE"
    assert run.call_count == 1


def test_cli_accepts_requested_input_shorthand(tmp_path):
    event_path = tmp_path / "event.jsonl"
    logs_path = tmp_path / "logs.json"
    event = map_flow_to_event(_flow("simulated", "SLOW_BRAIN"))
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    logs_path.write_text(
        json.dumps({"simulated": json.dumps(_flow("simulated", "SLOW_BRAIN"))}),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "python",
            "-m",
            "soc_agent.cli",
            "--input",
            str(event_path),
            "--logs",
            str(logs_path),
            "--entity",
            event["src"],
            "--entity",
            event["dst"],
            "--llm",
            "sim",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    decoded = json.loads(result.stdout)
    assert "verdicts" in decoded
    assert "gate_flags" in decoded
    assert "reasons" in decoded
