"""Fast Isolation Forest scoring and routing for individual network flows."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Self

import numpy as np
from sklearn.ensemble import IsolationForest


_TREE_COUNT = 51
_MAJORITY = 26
_EULER_MASCHERONI = 0.5772156649015329


def features_from_flow(flow: Mapping[str, object]) -> np.ndarray:
    """Convert the documented JSONL flow shape into four model features."""
    try:
        packets = float(
            flow["packets"] if "packets" in flow else flow["packet_count"]
        )
        byte_count = float(flow["bytes"] if "bytes" in flow else flow["byte_count"])
        duration_ms = float(flow.get("duration_ms", 0.0))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("flow requires numeric packets, bytes, and duration_ms") from exc
    values = (packets, byte_count, duration_ms)
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("flow packet, byte, and duration counts must be finite and non-negative")
    mean_packet_size = byte_count / packets if packets > 0 else 0.0
    if not math.isfinite(mean_packet_size):
        raise ValueError("flow mean packet size must be finite")
    return np.log1p(
        np.asarray(
            (packets, byte_count, duration_ms, mean_packet_size),
            dtype=np.float64,
        )
    )


def _average_path_length(sample_count: int) -> float:
    if sample_count <= 1:
        return 0.0
    if sample_count == 2:
        return 1.0
    return (
        2.0
        * (math.log(sample_count - 1) + _EULER_MASCHERONI)
        - 2.0 * (sample_count - 1) / sample_count
    )


class EarlyExitMVIForest:
    """51-tree Isolation Forest with majority-vote early termination.

    The constructor fits a small, deterministic four-feature bootstrap forest so
    the instance is ready to score immediately. Call ``fit`` with representative
    baseline traffic before using the scores for production routing.
    """

    def __init__(
        self,
        random_state: int | None = None,
        *,
        n_features: int = 4,
        contamination: str | float = "auto",
    ) -> None:
        if n_features < 1:
            raise ValueError("n_features must be positive")
        self.random_state = random_state
        self.n_features = n_features
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=_TREE_COUNT,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1,
        )
        rng = np.random.default_rng(random_state)
        self.model.fit(rng.standard_normal(size=(256, n_features)))

    def fit(self, feature_matrix: np.ndarray) -> Self:
        """Train on a finite 2-D feature matrix and return this instance."""
        samples = np.asarray(feature_matrix, dtype=np.float64)
        if samples.ndim != 2 or samples.shape[0] < 2:
            raise ValueError("feature_matrix must contain at least two rows")
        if samples.shape[1] != self.n_features:
            raise ValueError(
                f"expected {self.n_features} features, received {samples.shape[1]}"
            )
        if not np.isfinite(samples).all():
            raise ValueError("feature_matrix must contain only finite values")
        self.model.fit(samples)
        return self

    def compute_s_score(self, feature_vector: np.ndarray) -> float:
        """Return the normalized anomaly score, in [0, 1], for one flow.

        A tree votes anomalous when its standard Isolation Forest score exceeds
        the model's anomaly threshold. Traversal stops once either class reaches
        26 votes. The returned score applies the standard Isolation Forest
        exponential path-length normalization to the trees visited.
        """
        features = np.asarray(feature_vector, dtype=np.float64)
        if features.ndim != 1 or features.shape[0] != self.model.n_features_in_:
            raise ValueError(
                f"feature_vector must be 1-D with "
                f"{self.model.n_features_in_} features"
            )
        if not np.isfinite(features).all():
            raise ValueError("feature_vector must contain only finite values")

        normalizer = _average_path_length(int(self.model.max_samples_))
        if normalizer <= 0.0:
            raise ValueError("the fitted forest has no usable path-length scale")

        path_length_sum = 0.0
        anomaly_votes = 0
        normal_votes = 0
        visited = 0
        anomaly_threshold = -float(self.model.offset_)

        for estimator in self.model.estimators_:
            tree = estimator.tree_
            node = 0
            depth = 0
            while tree.children_left[node] != tree.children_right[node]:
                feature = tree.feature[node]
                if features[feature] <= tree.threshold[node]:
                    node = tree.children_left[node]
                else:
                    node = tree.children_right[node]
                depth += 1

            path_length = depth + _average_path_length(
                int(tree.n_node_samples[node])
            )
            tree_score = math.exp(-math.log(2.0) * path_length / normalizer)
            path_length_sum += path_length
            visited += 1

            if tree_score > anomaly_threshold:
                anomaly_votes += 1
            else:
                normal_votes += 1
            if anomaly_votes == _MAJORITY or normal_votes == _MAJORITY:
                break

        mean_path_length = path_length_sum / visited
        return float(math.exp(-math.log(2.0) * mean_path_length / normalizer))

    @staticmethod
    def route_flow(s_score: float) -> str:
        """Map a normalized anomaly score to its response path."""
        score = float(s_score)
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("s_score must be a finite value between 0 and 1")
        if score < 0.40:
            return "CLEAR"
        if score <= 0.85:
            return "SLOW_BRAIN"
        return "FAST_TRACK"
