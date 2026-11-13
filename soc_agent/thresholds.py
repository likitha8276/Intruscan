"""Validation, fingerprinting and persistence for Fast Brain routing thresholds.

Two kinds of threshold files exist and are never interchangeable:

* a *candidate* (``status: "candidate"``) written by ``tools/calibrate_thresholds.py``;
* an *approved* configuration (``status: "approved"``), created only by the explicit
  ``approve`` action and bound to one model artifact by its SHA-256 fingerprint.

Only an approved configuration can be loaded for routing. If no approved file exists,
routing falls back to the original 0.40 / 0.85 values and says so. An approved file that
is invalid, of an unsupported version, or tied to a different model is an error.

This module must not import ``soc_agent.fast_brain`` (which imports it).
"""

from __future__ import annotations

import hashlib
import json
import math
import numbers
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
STATUS_CANDIDATE = "candidate"
STATUS_APPROVED = "approved"

DEFAULT_LOWER_THRESHOLD = 0.40
DEFAULT_UPPER_THRESHOLD = 0.85
DEFAULT_APPROVED_PATH = Path(__file__).with_name("thresholds.json")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ThresholdConfigError(ValueError):
    """Raised for an invalid threshold pair or threshold configuration."""


@dataclass(frozen=True)
class RoutingThresholds:
    """Thresholds in force for one scoring run, and where they came from."""

    lower: float
    upper: float
    source: str  # "approved" or "fallback"
    detail: str

    def describe(self) -> str:
        return (
            f"fast-brain thresholds: lower={self.lower:g} upper={self.upper:g} "
            f"source={self.source} ({self.detail})"
        )


def validate_thresholds(lower: object, upper: object) -> tuple[float, float]:
    """Return ``(lower, upper)`` as floats, or raise ``ThresholdConfigError``.

    Both must be real numbers (not bool or string), finite, within [0, 1], and
    ``lower`` must be strictly smaller than ``upper``.
    """
    values: list[float] = []
    for name, value in (("lower", lower), ("upper", upper)):
        if (
            isinstance(value, bool)
            or not isinstance(value, numbers.Real)
        ):
            raise ThresholdConfigError(
                f"{name} threshold must be a number, got {value!r}"
            )
        number = float(value)
        if not math.isfinite(number):
            raise ThresholdConfigError(
                f"{name} threshold must be finite, got {value!r}"
            )
        if not 0.0 <= number <= 1.0:
            raise ThresholdConfigError(
                f"{name} threshold must be between 0 and 1, got {number!r}"
            )
        values.append(number)
    if values[0] >= values[1]:
        raise ThresholdConfigError(
            f"lower threshold ({values[0]!r}) must be strictly smaller than "
            f"upper threshold ({values[1]!r})"
        )
    return values[0], values[1]


def file_sha256(path: str | os.PathLike[str]) -> str:
    """SHA-256 hex digest of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_fingerprint(model_path: str | os.PathLike[str]) -> str:
    """Identity of a saved model artifact: SHA-256 of the exact ``.joblib`` bytes.

    The fingerprint identifies the file, not the learned parameters: re-saving or
    retraining the model produces a new fingerprint, which correctly invalidates any
    thresholds approved for the old file.
    """
    return file_sha256(model_path)


def read_json_object(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read a JSON object. ``FileNotFoundError`` propagates; other problems do not."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise ThresholdConfigError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ThresholdConfigError(
            f"{path} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise ThresholdConfigError(f"{path} must contain a JSON object")
    return data


@dataclass(frozen=True)
class ThresholdConfig:
    lower: float
    upper: float
    model_sha256: str
    status: str
    raw: dict[str, Any]


def validate_config(
    data: dict[str, Any],
    *,
    expect_status: str,
    model_sha256: str | None = None,
    label: str = "threshold configuration",
) -> ThresholdConfig:
    """Validate a parsed configuration; optionally require a model fingerprint match."""
    version = data.get("schema_version")
    if isinstance(version, bool) or version != SCHEMA_VERSION:
        raise ThresholdConfigError(
            f"{label}: unsupported schema_version {version!r} "
            f"(this build supports {SCHEMA_VERSION})"
        )
    status = data.get("status")
    if status != expect_status:
        raise ThresholdConfigError(
            f"{label}: status is {status!r}, expected {expect_status!r}"
            + (
                " (a candidate must be approved before it can be used)"
                if status == STATUS_CANDIDATE and expect_status == STATUS_APPROVED
                else ""
            )
        )
    try:
        lower, upper = validate_thresholds(
            data.get("lower_threshold"), data.get("upper_threshold")
        )
    except ThresholdConfigError as exc:
        raise ThresholdConfigError(f"{label}: {exc}") from exc
    recorded = data.get("model_sha256")
    if not isinstance(recorded, str) or not _SHA256_RE.match(recorded):
        raise ThresholdConfigError(
            f"{label}: model_sha256 must be a 64-character lowercase hex SHA-256"
        )
    if model_sha256 is not None and recorded != model_sha256:
        raise ThresholdConfigError(
            f"{label} was calibrated for a different model "
            f"(configuration model_sha256 {recorded[:12]}..., "
            f"model in use {model_sha256[:12]}...); recalibrate and approve "
            "thresholds for this model"
        )
    return ThresholdConfig(lower, upper, recorded, status, data)


def load_approved_thresholds(
    path: str | os.PathLike[str], model_sha256: str
) -> ThresholdConfig:
    """Load and validate an approved configuration for the given model fingerprint."""
    return validate_config(
        read_json_object(path),
        expect_status=STATUS_APPROVED,
        model_sha256=model_sha256,
        label=f"approved thresholds {path}",
    )


def resolve_routing_thresholds(
    config_path: str | os.PathLike[str] | None,
    model_path: str | os.PathLike[str],
) -> RoutingThresholds:
    """Thresholds to use when scoring with ``model_path``.

    * File missing -> the original 0.40 / 0.85 fallback, reported as such.
    * File present but invalid / unsupported / candidate / other model -> raises.
    """
    path = Path(config_path) if config_path is not None else DEFAULT_APPROVED_PATH
    try:
        data = read_json_object(path)
    except FileNotFoundError:
        return RoutingThresholds(
            DEFAULT_LOWER_THRESHOLD,
            DEFAULT_UPPER_THRESHOLD,
            "fallback",
            f"no approved threshold configuration at {path}; using built-in defaults",
        )
    config = validate_config(
        data,
        expect_status=STATUS_APPROVED,
        model_sha256=model_fingerprint(model_path),
        label=f"approved thresholds {path}",
    )
    return RoutingThresholds(
        config.lower, config.upper, "approved", f"loaded from {path}"
    )


def atomic_write_json(
    path: str | os.PathLike[str],
    payload: dict[str, Any],
    *,
    overwrite: bool,
) -> None:
    """Write JSON atomically (temp file + rename).

    With ``overwrite=False`` an existing destination is never replaced.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, allow_nan=False) + "\n"
    descriptor, temp_name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp"
    )
    temp_path: str | None = temp_name
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        if overwrite:
            os.replace(temp_name, destination)
            temp_path = None
            return
        try:
            os.link(temp_name, destination)  # atomic, fails if destination exists
        except FileExistsError as exc:
            raise ThresholdConfigError(
                f"{destination} already exists; refusing to overwrite it"
            ) from exc
        except OSError:  # filesystem without hard links
            if destination.exists():
                raise ThresholdConfigError(
                    f"{destination} already exists; refusing to overwrite it"
                ) from None
            os.replace(temp_name, destination)
            temp_path = None
    finally:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)
