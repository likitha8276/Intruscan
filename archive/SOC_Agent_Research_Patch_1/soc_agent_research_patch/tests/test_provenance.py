
from dataclasses import replace
from datetime import datetime, timezone

from soc_agent.provenance import sign_event, verify_event
from soc_agent.schemas import Event


def test_valid_signature_is_accepted():
    key = b"test-secret-key"
    event = Event(
        event_id="e1",
        ts=datetime(2026, 10, 22, tzinfo=timezone.utc),
        rel="exec",
        src="host-a",
        dst="powershell.exe",
        source_system="edr",
        parse_conf=0.98,
        match_conf=0.97,
    )

    signed = replace(event, provenance_signature=sign_event(event, key))

    assert verify_event(signed, key)


def test_tampered_event_is_rejected():
    key = b"test-secret-key"
    event = Event(
        event_id="e2",
        ts=datetime(2026, 10, 22, tzinfo=timezone.utc),
        rel="exec",
        src="host-a",
        dst="powershell.exe",
        source_system="edr",
        parse_conf=0.98,
        match_conf=0.97,
    )

    signed = replace(event, provenance_signature=sign_event(event, key))
    tampered = replace(signed, dst="malicious.exe")

    assert not verify_event(tampered, key)


def test_unsigned_event_is_rejected():
    event = Event(
        event_id="e3",
        ts=datetime(2026, 10, 22, tzinfo=timezone.utc),
        rel="exec",
        src="host-a",
        dst="powershell.exe",
    )

    assert not verify_event(event, b"test-secret-key")


def test_provenance_controls_are_independently_configurable():
    from soc_agent.config import VerifierConfig
    from soc_agent.evaluate import make_configs

    configs = make_configs(VerifierConfig())
    verifier_only = configs["F_verifier_provenance"].verifier
    full = configs["G_full_provenance"].verifier

    assert verifier_only.require_provenance is True
    assert verifier_only.provenance_key is not None
    assert verifier_only.use_provenance_floor is False
    assert full.require_provenance is True
    assert full.use_provenance_floor is True
