"""PostProcessNode — traceable credential exception briefing output formatting for SVC-C2-070."""

from __future__ import annotations

import re
from typing import ClassVar

from framework.errors import SecurityViolationError
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json
from src.services.llm_runtime import provider_metadata, request_advisory

# Patterns that indicate prohibited autonomous credential decisions
_PROHIBITED_OUTPUT_PATTERNS = re.compile(
    r"\b(credential\s+(approved|granted|denied|revoked|provisioned)|"
    r"access\s+(approved|granted|denied|revoked)|"
    r"applicant\s+(is\s+)?(approved|cleared|rejected)|"
    r"exception\s+(approved|granted|denied)|"
    r"credential\s+exception\s+is\s+(approved|denied|granted))\b",
    re.IGNORECASE,
)


def _format_exception_factors(factors: list[dict]) -> str:
    lines = []
    for f in factors:
        assumption_tag = " [ASSUMPTION/GAP]" if f.get("is_assumption") else ""
        cit = f" (ref: {f['citation_ref']})" if f.get("citation_ref") else ""
        lines.append(f"  [{f.get('factor_id', '')}]{assumption_tag} {f.get('description', '')}{cit}")
    return "\n".join(lines) if lines else "  No exception factors identified."


class PostProcessNode(FunctionNode):
    """Aggregate briefing draft, review disposition, citations, and limitations for final output.

    Outer node — VERIFIED_EXTERNAL. Retains operator-verifiable provenance without
    exposing credentials or raw restricted payloads. S-3 extension rejects
    prohibited credential decision-framing language.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, llm: object | None = None, config: dict | None = None) -> None:
        super().__init__()
        self._llm = llm
        self._config = config or {}

    # -- S-3 extension --------------------------------------------------------

    def _extra_security_gate_output(self, result: dict) -> dict:
        output = result.get("formatted_output", "")
        if output and _PROHIBITED_OUTPUT_PATTERNS.search(output):
            raise SecurityViolationError(
                "PostProcessNode: output contains prohibited credential decision-framing language"
            )
        return result

    # -- execute --------------------------------------------------------------

    def execute(self, state: dict) -> dict:
        if state.get("input_error_message"):
            message = str(state["input_error_message"])
            return {"formatted_output": message, "status": AgentStatus.SUCCESS.value, "input_error_message": message}
        request_advisory(
            state,
            "Review the safety of a deterministic credential exception briefing.",
            self._llm,
            timeout_s=float(self._config.get("timeout_s", 30)),
            max_retry=int(self._config.get("max_retry", 3)),
        )
        review_outcome = state.get("review_outcome", "")
        review_notes = state.get("review_notes", "")
        briefing_draft_json = state.get("briefing_draft_json", "")
        draft = from_json(briefing_draft_json, default={})

        if not draft:
            emit_trace_event("PostProcessNode_event", {"result": "no_draft"}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": ["PostProcessNode: no briefing draft available for output"],
                **provider_metadata(state),
            }

        event_id = draft.get("event_id", "")
        broadcast_role = draft.get("broadcast_role", "")
        exception_criteria = draft.get("exception_criteria", "")
        requestor_ref = draft.get("requestor_ref", "")
        summary = draft.get("summary", "")
        exception_factors = draft.get("exception_factors", [])
        unresolved_items = draft.get("unresolved_items", [])
        history_pattern_summary = draft.get("history_pattern_summary", "")
        citations = draft.get("citations", [])
        limitations = draft.get("limitations", [])

        lines = [
            "=" * 70,
            "LIVE EVENT BROADCAST CREDENTIAL EXCEPTION BRIEFING",
            "Agent: SVC-C2-070 | Decision Support — NOT Credential Approval or Denial",
            "=" * 70,
            "",
            f"Event ID: {event_id}",
            f"Broadcast Role: {broadcast_role}",
            f"Exception Criteria: {exception_criteria}",
            f"Requestor Reference: {requestor_ref}",
            "",
            "SUMMARY",
            "-" * 40,
            summary,
            "",
        ]

        # Human review disposition
        if review_outcome:
            lines += [
                "HUMAN REVIEW DISPOSITION",
                "-" * 40,
                f"Outcome: {review_outcome.upper()}",
            ]
            if review_notes:
                lines.append(f"Notes: {review_notes}")
            lines.append("")

        # Historical context
        if history_pattern_summary:
            lines += [
                "HISTORICAL APPROVAL PATTERN",
                "-" * 40,
                history_pattern_summary,
                "",
            ]

        # Exception factors
        lines += [
            "EXCEPTION FACTORS AND POLICY EVIDENCE",
            "-" * 40,
        ]
        lines.append(_format_exception_factors(exception_factors))
        lines.append("")

        # Unresolved items
        if unresolved_items:
            lines += [
                "UNRESOLVED ITEMS / POLICY GAPS",
                "-" * 40,
            ]
            for item in unresolved_items:
                lines.append(f"  * {item}")
            lines.append("")

        # Citations
        if citations:
            lines += [
                "CITATIONS / PROVENANCE",
                "-" * 40,
            ]
            for cit in citations:
                lines.append(f"  {cit}")
            lines.append("")

        # Limitations
        lines += [
            "LIMITATIONS AND DISCLAIMERS",
            "-" * 40,
        ]
        for lim in limitations:
            lines.append(f"  * {lim}")
        lines.append("")

        lines += [
            "NOTE: This briefing does not approve, deny, provision, or revoke credentials.",
            "      No access-control systems were modified. Applicant notification is out of scope.",
            "=" * 70,
        ]

        formatted = "\n".join(lines)

        emit_trace_event(
            "PostProcessNode_event",
            {
                "result": "formatted",
                "review_outcome": review_outcome or "none",
                "factor_count": len(exception_factors),
                "unresolved_count": len(unresolved_items),
            },
            state,
        )

        return {
            "formatted_output": formatted,
            "result": to_json(draft),
            "status": AgentStatus.SUCCESS.value,
            **provider_metadata(state),
        }
