import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from soc_agent import cli
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
        assert command[command.index("--llm") + 1] == "auto"
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
            "openai/gpt-oss-20b",
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
        ["python"],
        0,
        stdout='{"outcome":"ESCALATE","verdicts":[],"reasons":[],"gate_flags":[]}',
        stderr="",
    )
    with patch(
        "tools.slow_brain_handoff.subprocess.run",
        return_value=completed,
    ) as run:
        processed, ignored, invalid_count = process_file(
            source, destination, "python", "openai/gpt-oss-20b", "D_full", 2.0,
        )
    results = [json.loads(line) for line in destination.read_text().splitlines()]
    assert (processed, ignored, invalid_count) == (2, 0, 1)
    assert results[0]["soc_result"]["status"] == "INVALID_FLOW"
    assert results[1]["soc_result"]["outcome"] == "ESCALATE"
    assert run.call_count == 1


def test_cli_accepts_requested_input_shorthand_and_auto_fallback(
    tmp_path, monkeypatch, capsys
):
    event_path = tmp_path / "event.jsonl"
    logs_path = tmp_path / "logs.json"
    event = map_flow_to_event(_flow("simulated", "SLOW_BRAIN"))
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    logs_path.write_text(
        json.dumps({"simulated": json.dumps(_flow("simulated", "SLOW_BRAIN"))}),
        encoding="utf-8",
    )
    argv = [
        "--input", str(event_path),
        "--logs", str(logs_path),
        "--entity", event["src"],
        "--entity", event["dst"],
        "--llm", "auto",
    ]

    # Dummy credentials satisfy auto-mode configuration. Both clients are
    # replaced below, so this test never contacts either provider.
    monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

    def forbid_network(*args, **kwargs):
        raise AssertionError("test must not make a real provider/network request")

    monkeypatch.setattr("urllib.request.urlopen", forbid_network)

    created = []

    class FakeGroqClient:
        def __init__(self, model, *args, **kwargs):
            self.model = model
            self.calls = []
            self.last_usage = {}
            created.append(("groq", self))

        def generate(self, system, user, seed_key=""):
            self.calls.append(
                {"system": system, "user": user, "seed_key": seed_key}
            )
            return json.dumps(
                {
                    "severity": "low",
                    "action": {"type": "investigate", "target": ""},
                    "claims": [
                        {
                            "id": "c1",
                            "text": "flow observed between the alert entities",
                            "chain": [
                                {
                                    "rel": event["rel"],
                                    "src": event["src"],
                                    "dst": event["dst"],
                                }
                            ],
                        }
                    ],
                }
            )

    class FakeGeminiClient:
        def __init__(self, *args, **kwargs):
            self.calls = []
            self.last_usage = {}
            created.append(("gemini", self))

        def generate(self, system, user, seed_key=""):
            self.calls.append(
                {"system": system, "user": user, "seed_key": seed_key}
            )
            raise AssertionError("Gemini should not run when Groq succeeds")

    monkeypatch.setattr(cli, "GroqClient", FakeGroqClient)
    monkeypatch.setattr(cli, "GeminiClient", FakeGeminiClient)

    parsed = cli.build_parser().parse_args(argv)
    assert parsed.events == str(event_path)
    assert parsed.logs == str(logs_path)
    assert parsed.entity == [event["src"], event["dst"]]
    assert parsed.llm == "auto"

    # Run the real CLI: loaders, scenario, SOCAgent, verifier, gate, router, JSON output.
    cli.main(argv)

    assert [provider for provider, _ in created] == ["groq", "gemini"]
    groq_client = created[0][1]
    gemini_client = created[1][1]
    assert groq_client.model == "openai/gpt-oss-20b"
    assert len(groq_client.calls) == 1
    assert gemini_client.calls == []
    prompt = groq_client.calls[0]["user"]
    assert event["src"] in prompt and event["dst"] in prompt
    assert '"flow_id": "simulated"' in prompt

    decoded = json.loads(capsys.readouterr().out)
    assert isinstance(decoded["verdicts"], list)
    assert isinstance(decoded["gate_flags"], list)
    assert isinstance(decoded["reasons"], list) and decoded["reasons"]
    assert decoded["verdicts"] == ["SUPPORTED"]
    assert decoded["outcome"] == "ESCALATE"
