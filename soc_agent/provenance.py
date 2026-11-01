"""Authenticate event provenance using HMAC signatures."""
import hashlib
import hmac
import json

from .schemas import Event

def _event_payload(ev: Event) -> bytes:
    """Create a stable representation of the event fields we authenticate."""
    data ={
        "event_id": ev.event_id,
        "ts": ev.ts.isoformat(),
        "rel": ev.rel,
        "src": ev.src,
        "dst": ev.dst,
        "source_system": ev.source_system,
        "parse_conf": ev.parse_conf,
        "match_conf": ev.match_conf,
    }
    return json.dumps(
        data,sort_keys=True , separators=(",",":")
    ).encode("utf-8")


def sign_event(ev:Event , key:bytes) -> str:
    """Create an authentication signature for a trusted event."""
    return hmac.new(
        key, _event_payload(ev) , hashlib.sha256
    ).hexdigest()

def verify_event(ev: Event, key: bytes)-> bool:
    """Return True only when the event signature is valid"""
    if not ev.provenance_signature:
        return False

    expected = sign_event(ev,key)
    return hmac.compare_digest(
        ev.provenance_signature,expected
    )