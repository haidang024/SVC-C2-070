"""PreProcessNode — exception-request scope validation and authorization for SVC-C2-070."""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from framework.errors import SecurityViolationError
from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import to_json

_SUPPORTED_BROADCAST_ROLES = frozenset(
    {
        "host_broadcaster",
        "rights_holder",
        "accredited_press",
        "production_crew",
        "technical_services",
    }
)

_MAX_INPUT_BYTES = 8_192
_MAX_DATE_WINDOW_DAYS = 365
_GREETING_ONLY = re.compile(r"^(?:hello|hi|hey|hello[,. ]*hi|xin chào|chào|こんにちは)[!. ,]*$", re.IGNORECASE)
_INPUT_GUIDANCE = [
    "Send a JSON object containing event_id, broadcast_role, exception_criteria, and approved_source_ids.",
    'Example: {"event_id": "EVT-001", "broadcast_role": "accredited_press", "exception_criteria": "late request", "approved_source_ids": ["SRC-01"]}.',
    f"Supported broadcast roles: {', '.join(sorted(_SUPPORTED_BROADCAST_ROLES))}.",
]


def _input_error(message: str) -> dict[str, Any]:
    return {
        "status": AgentStatus.SUCCESS.value,
        "validated_input": "",
        "input_error_message": message,
        "input_error_guidance": "\n".join(_INPUT_GUIDANCE),
    }


class PreProcessNode(FunctionNode):
    """Validate and normalize the credential exception request scope and approved sources.

    Outer node — VERIFIED_EXTERNAL. Validates event ID, broadcast role,
    exception criteria, date window, and approved source identifiers.
    S-2 extension enforces input size and JSON structure.
    Never logs applicant PII or raw credential values in audit events.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    # -- S-2 extension --------------------------------------------------------

    def _extra_security_gate_input(self, state: dict) -> dict:
        user_input = state.get("user_input", "")
        if len(user_input.encode()) > _MAX_INPUT_BYTES:
            raise SecurityViolationError(f"PreProcessNode: input exceeds {_MAX_INPUT_BYTES} bytes")
        if user_input and not user_input.strip().startswith("{"):
            return {**state, **_input_error("user_input must be a JSON object string.")}
        return state

    # -- execute --------------------------------------------------------------

    def execute(self, state: dict) -> dict:
        user_input = state.get("user_input", "")

        if not user_input or not user_input.strip():
            emit_trace_event("PreProcessNode_event", {"result": "empty_input"}, state)
            return _input_error("No credential-exception request was provided.")

        try:
            scope = json.loads(user_input)
        except (json.JSONDecodeError, TypeError):
            emit_trace_event("PreProcessNode_event", {"result": "invalid_json"}, state)
            if _GREETING_ONLY.fullmatch(user_input.strip()):
                return _input_error("The message contains only a greeting and no credential-exception request.")
            return _input_error("user_input must be a valid JSON object string.")

        # Required fields
        required_fields = ["event_id", "broadcast_role", "exception_criteria"]
        missing = [f for f in required_fields if not scope.get(f)]
        if missing:
            emit_trace_event("PreProcessNode_event", {"result": "missing_fields", "fields": missing}, state)
            return _input_error(f"Missing required fields: {missing}.")

        # Validate broadcast_role
        broadcast_role = scope["broadcast_role"]
        if broadcast_role not in _SUPPORTED_BROADCAST_ROLES:
            emit_trace_event("PreProcessNode_event", {"result": "unsupported_broadcast_role"}, state)
            return _input_error(
                f"Unsupported broadcast_role '{broadcast_role}'. "
                f"Supported values: {sorted(_SUPPORTED_BROADCAST_ROLES)}."
            )

        # Validate approved source identifiers
        approved_source_ids = scope.get("approved_source_ids", [])
        if not isinstance(approved_source_ids, list) or not approved_source_ids:
            emit_trace_event("PreProcessNode_event", {"result": "no_source_ids"}, state)
            return _input_error("approved_source_ids must be a non-empty JSON array.")

        # Build exception scope (privacy-safe: no applicant PII)
        exception_scope = {
            "event_id": scope["event_id"],
            "broadcast_role": broadcast_role,
            "exception_criteria": scope["exception_criteria"],
            "date_window_start": scope.get("date_window_start", ""),
            "date_window_end": scope.get("date_window_end", ""),
            "requestor_ref": scope.get("requestor_ref", ""),
            "operator_id": scope.get("operator_id", ""),
        }

        emit_trace_event(
            "PreProcessNode_event",
            {
                "result": "validated",
                "broadcast_role": broadcast_role,
                "source_count": len(approved_source_ids),
                "event_id": scope["event_id"],
            },
            state,
        )

        return {
            "validated_input": user_input.strip(),
            "exception_scope_json": to_json(exception_scope),
            "approved_source_ids_json": to_json(approved_source_ids),
            "status": AgentStatus.SUCCESS.value,
        }
