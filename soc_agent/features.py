"""Selectable Fast Brain feature sets.

``v1`` is the original four-feature set (``soc_agent.fast_brain.features_from_flow``) and
remains the default everywhere. ``v2`` extends it using ONLY fields of the canonical flow
schema that the Go ingester already archives (``packets``, ``bytes``, ``duration_ms``,
``src_port``, ``dst_port``, ``protocol``). Nothing is inferred or invented: a flow that
lacks a field a feature set needs is rejected with a ValueError.

``v3`` extends ``v2`` with six TCP-flag indicators and a SYN-without-ACK indicator, read
from ``metadata.tcp_flags`` (UGR'16 flows carry it as a six-character string in the order
U A P R S F, with "." for an unset flag). v3 is UGR'16-specific: a flow without
``metadata.tcp_flags`` is rejected, in line with the rule above.

``v3b`` extends ``v3`` with the source and destination port as numbers (value / 65535), so
the model can tell apart flows whose port *class* is the same but whose port differs
(for example a reply from port 80 versus one from port 8080). It adds no label-derived
information and no hand-picked values.

A trained model records which feature set it was fitted with (``EarlyExitMVIForest.feature_set``)
and scoring always uses that set, so train-time and score-time features cannot diverge.
Models pickled before this module existed have no such attribute and are treated as ``v1``.

This module must not import ``soc_agent.fast_brain`` at import time (fast_brain imports it).
"""

from __future__ import annotations

import math
from collections.abc import Mapping

import numpy as np

V1_FEATURES: tuple[str, ...] = (
    "log1p_packets",
    "log1p_bytes",
    "log1p_duration_ms",
    "log1p_mean_packet_size",
)

V2_FEATURES: tuple[str, ...] = V1_FEATURES + (
    "log1p_packets_per_s",
    "log1p_bytes_per_s",
    "dst_port_well_known",
    "src_port_unprivileged",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
)

V3_FEATURES: tuple[str, ...] = V2_FEATURES + (
    "flag_urg",
    "flag_ack",
    "flag_psh",
    "flag_rst",
    "flag_syn",
    "flag_fin",
    "syn_without_ack",
)

V3B_FEATURES: tuple[str, ...] = V3_FEATURES + (
    "src_port_norm",
    "dst_port_norm",
)

FEATURE_SETS: dict[str, tuple[str, ...]] = {
    "v1": V1_FEATURES,
    "v2": V2_FEATURES,
    "v3": V3_FEATURES,
    "v3b": V3B_FEATURES,
}
DEFAULT_FEATURE_SET = "v1"

# IANA protocol numbers for the three protocols given their own indicator; everything else
# (including unknown names) leaves all three indicators at zero ("other").
_PROTO_NUMBERS = {1: "icmp", 6: "tcp", 17: "udp"}
_PROTO_NAMES = {"icmp", "tcp", "udp"}
# Duration floor used only for rate features, so single-packet (0 ms) flows do not divide by 0.
_MIN_RATE_DURATION_MS = 1.0
# UGR'16 TCP flag string order: URG, ACK, PSH, RST, SYN, FIN ("." = flag not set).
_FLAG_ORDER = "UAPRSF"


def validate_feature_set(name: str) -> str:
    if name not in FEATURE_SETS:
        raise ValueError(
            f"unknown feature set {name!r}; choose one of {', '.join(sorted(FEATURE_SETS))}"
        )
    return name


def _port(flow: Mapping[str, object], key: str) -> int:
    if key not in flow or flow[key] is None:
        raise ValueError(f"feature set v2 requires {key}; this flow has none")
    value = flow[key]
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer port, got {value!r}")
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer port, got {value!r}") from exc
    if not math.isfinite(number) or number != int(number) or not 0 <= number <= 65535:
        raise ValueError(f"{key} must be an integer in 0..65535, got {value!r}")
    return int(number)


def _protocol_name(flow: Mapping[str, object]) -> str:
    value = flow.get("protocol")
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("feature set v2 requires protocol; this flow has none")
    if isinstance(value, bool):
        raise ValueError(f"protocol must be a name or IANA number, got {value!r}")
    if isinstance(value, (int, float)):
        return _PROTO_NUMBERS.get(int(value), "other")
    text = str(value).strip().lower()
    if text.isdigit():
        return _PROTO_NUMBERS.get(int(text), "other")
    return text if text in _PROTO_NAMES else "other"


def _tcp_flags(flow: Mapping[str, object]) -> str:
    """The six-character TCP flag string from ``metadata.tcp_flags``, validated."""
    metadata = flow.get("metadata")
    flags = metadata.get("tcp_flags") if isinstance(metadata, Mapping) else None
    if flags is None:
        raise ValueError("feature set v3 requires metadata.tcp_flags; this flow has none")
    if not isinstance(flags, str) or len(flags) != 6:
        raise ValueError(
            f"metadata.tcp_flags must be a 6-character string like '.A..SF', got {flags!r}"
        )
    for position, char in enumerate(flags):
        if char != "." and char.upper() != _FLAG_ORDER[position]:
            raise ValueError(
                f"metadata.tcp_flags {flags!r} has an unexpected character {char!r} "
                f"at position {position} (expected '.' or {_FLAG_ORDER[position]!r})"
            )
    return flags


def features_v2(flow: Mapping[str, object]) -> np.ndarray:
    """Eleven features: the V1 four plus rates, port classes and protocol indicators."""
    from .fast_brain import features_from_flow  # lazy: avoids an import cycle

    base = features_from_flow(flow)  # raises ValueError on bad packets/bytes/duration
    # base already validated these fields as finite and non-negative
    packets = float(flow["packets"] if "packets" in flow else flow["packet_count"])  # type: ignore[arg-type]
    byte_count = float(flow["bytes"] if "bytes" in flow else flow["byte_count"])  # type: ignore[arg-type]
    duration_ms = float(flow.get("duration_ms", 0.0))  # type: ignore[arg-type]
    seconds = max(duration_ms, _MIN_RATE_DURATION_MS) / 1000.0

    dst_port = _port(flow, "dst_port")
    src_port = _port(flow, "src_port")
    proto = _protocol_name(flow)

    extra = np.array(
        [
            math.log1p(packets / seconds),
            math.log1p(byte_count / seconds),
            1.0 if dst_port < 1024 else 0.0,
            1.0 if src_port >= 1024 else 0.0,
            1.0 if proto == "tcp" else 0.0,
            1.0 if proto == "udp" else 0.0,
            1.0 if proto == "icmp" else 0.0,
        ],
        dtype=np.float64,
    )
    vector = np.concatenate([base, extra])
    if not np.isfinite(vector).all():
        raise ValueError("feature vector contains a non-finite value")
    return vector


def features_v3(flow: Mapping[str, object]) -> np.ndarray:
    """Eighteen features: the V2 eleven plus six TCP-flag indicators and SYN-without-ACK."""
    base = features_v2(flow)
    flags = _tcp_flags(flow)
    indicators = [0.0 if char == "." else 1.0 for char in flags]
    # positions follow _FLAG_ORDER = U A P R S F
    ack, syn = indicators[1], indicators[4]
    extra = np.array(indicators + [1.0 if (syn == 1.0 and ack == 0.0) else 0.0], dtype=np.float64)
    return np.concatenate([base, extra])


def features_v3b(flow: Mapping[str, object]) -> np.ndarray:
    """Twenty features: the V3 eighteen plus normalised source and destination port."""
    base = features_v3(flow)
    extra = np.array(
        [_port(flow, "src_port") / 65535.0, _port(flow, "dst_port") / 65535.0],
        dtype=np.float64,
    )
    return np.concatenate([base, extra])


def extract_features(flow: Mapping[str, object], feature_set: str = DEFAULT_FEATURE_SET) -> np.ndarray:
    """Feature vector of ``flow`` under the named feature set."""
    validate_feature_set(feature_set)
    if feature_set == "v1":
        from .fast_brain import features_from_flow  # lazy: avoids an import cycle

        return features_from_flow(flow)
    if feature_set == "v3":
        return features_v3(flow)
    if feature_set == "v3b":
        return features_v3b(flow)
    return features_v2(flow)
