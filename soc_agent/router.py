"""Decision router: verified + consistent -> PROPOSE, otherwise abstain to an analyst."""
from __future__ import annotations

from .models import CONTAINMENT, Action, Decision, GateResult, Outcome, ParsedOutput
from .schemas import Verdict, VerifyResult


def aggregate(verifs: list[VerifyResult]) -> Verdict:
    if not verifs:
        return Verdict.UNKNOWN

    vs = {v.verdict for v in verifs}

    if Verdict.CONTRADICTED in vs:
        return Verdict.CONTRADICTED

    if Verdict.UNKNOWN in vs:
        return Verdict.UNKNOWN

    return Verdict.SUPPORTED


def route(
    parsed: ParsedOutput | None,
    verifs: list[VerifyResult],
    gate: GateResult,
    use_verifier: bool,
    three_state: bool,
    use_gate: bool = True,
) -> Decision:
    if parsed is None:
        return Decision(Outcome.ESCALATE, None, ["bad_output_schema"])

    a: Action = parsed.action

    if a.type == "close":
        if use_gate and gate.flags:
            return Decision(
                Outcome.ESCALATE,
                None,
                ["close_blocked_by_gate"] + gate.flags,
            )

        if use_verifier and three_state and use_gate:
            verdict = aggregate(verifs)
            if verdict != Verdict.SUPPORTED:
                return Decision(
                    Outcome.ESCALATE,
                    None,
                    [f"close_blocked_by_verification_{verdict.value.lower()}"],
                )

        return Decision(Outcome.CLOSE, None, ["llm_closed"])

    if a.type == "investigate":
        return Decision(
            Outcome.ESCALATE,
            None,
            ["llm_requested_investigation"] + (gate.flags if use_gate else []),
        )

    if not use_verifier:
        return Decision(Outcome.PROPOSE, a, ["unverified"])

    verdict = aggregate(verifs)
    reasons = [r for v in verifs for r in v.reasons]

    if verdict == Verdict.SUPPORTED and (gate.ok or not use_gate):
        return Decision(Outcome.PROPOSE, a, ["verified"])

    if three_state:
        why = [f"claims_{verdict.value.lower()}"]
        if use_gate:
            why += gate.flags
        why += reasons
        return Decision(Outcome.ESCALATE, None, why)

    return Decision(
        Outcome.CLOSE,
        None,
        ["claim_rejected_binary"] + reasons,
    )