import numpy as np


V2_FEATURE_NAMES = (
    "total_packets",
    "total_bytes",
    "duration_ms",
    "mean_packet_size",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "flow_bytes_per_second",
    "flow_packets_per_second",
    "fwd_packets_per_second",
    "bwd_packets_per_second",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "packet_length_std",
    "flow_iat_mean",
    "flow_iat_std",
    "syn_flag_count",
    "rst_flag_count",
    "ack_flag_count",
)


def _number(flow: dict, key: str, default: float = 0.0) -> float:
    value = float(flow.get(key, default))

    if not np.isfinite(value) or value < 0:
        raise ValueError(f"{key} must be finite and non-negative")

    return value


def features_from_flow_v2(flow: dict) -> np.ndarray:
    """
    Extract 20 log-transformed network-flow features for Fast Brain V2.
    Ground-truth labels and identifying metadata are never model inputs.
    """

    fwd_packets = _number(flow, "fwd_packets")
    bwd_packets = _number(flow, "bwd_packets")
    fwd_bytes = _number(flow, "fwd_bytes")
    bwd_bytes = _number(flow, "bwd_bytes")

    packets = _number(
        flow, "packet_count", fwd_packets + bwd_packets
    )
    bytes_count = _number(
        flow, "byte_count", fwd_bytes + bwd_bytes
    )
    duration = _number(flow, "duration_ms")

    mean_packet_size = bytes_count / packets if packets > 0 else 0.0

    raw_features = [
        packets,
        bytes_count,
        duration,
        mean_packet_size,
        fwd_packets,
        bwd_packets,
        fwd_bytes,
        bwd_bytes,
        _number(flow, "flow_bytes_per_second"),
        _number(flow, "flow_packets_per_second"),
        _number(flow, "fwd_packets_per_second"),
        _number(flow, "bwd_packets_per_second"),
        _number(flow, "fwd_packet_length_mean"),
        _number(flow, "bwd_packet_length_mean"),
        _number(flow, "packet_length_std"),
        _number(flow, "flow_iat_mean"),
        _number(flow, "flow_iat_std"),
        _number(flow, "syn_flag_count"),
        _number(flow, "rst_flag_count"),
        _number(flow, "ack_flag_count"),
    ]
        
    result = np.log1p(np.asarray(raw_features, dtype=np.float64))

    if result.shape != (len(V2_FEATURE_NAMES),):
        raise ValueError("Fast Brain V2 feature count mismatch")

    return result
    