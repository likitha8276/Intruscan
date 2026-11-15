"""Fast Brain V2 feature extraction."""
import numpy as np

V2_FEATURE_NAMES = ("total_packets","total_bytes","duration_ms","mean_packet_size",
"fwd_packets","bwd_packets","fwd_bytes","bwd_bytes","flow_bytes_per_second",
"flow_packets_per_second","fwd_packets_per_second","bwd_packets_per_second",
"fwd_packet_length_mean","bwd_packet_length_mean","packet_length_std",
"flow_iat_mean","flow_iat_std","syn_flag_count","rst_flag_count","ack_flag_count")

def _number(value,key):
    try: n=float(value)
    except (TypeError,ValueError) as e: raise ValueError(f"{key} must be numeric") from e
    if not np.isfinite(n) or n<0: raise ValueError(f"{key} must be finite and non-negative")
    return n

def features_from_flow_v2(flow:dict)->np.ndarray:
    """Extract 20 log1p features; supports canonical nested and legacy flat flows."""
    nested=flow.get("features")
    if isinstance(nested,dict):
        raw=[_number(nested.get(k,0.0),k) for k in V2_FEATURE_NAMES]
    else:
        fp=_number(flow.get("fwd_packets",0.0),"fwd_packets")
        bp=_number(flow.get("bwd_packets",0.0),"bwd_packets")
        fb=_number(flow.get("fwd_bytes",0.0),"fwd_bytes")
        bb=_number(flow.get("bwd_bytes",0.0),"bwd_bytes")
        packets=_number(flow.get("packet_count",fp+bp),"packet_count")
        byte_count=_number(flow.get("byte_count",fb+bb),"byte_count")
        duration=_number(flow.get("duration_ms",0.0),"duration_ms")
        raw=[packets,byte_count,duration,byte_count/packets if packets else 0.0,fp,bp,fb,bb]
        raw += [_number(flow.get(k,0.0),k) for k in V2_FEATURE_NAMES[8:]]
    result=np.log1p(np.asarray(raw,dtype=np.float64))
    if result.shape!=(20,): raise ValueError("Fast Brain V2 feature count mismatch")
    return result
