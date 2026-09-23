"""State — flat TypedDict for SVC-C2-070 Live Event Broadcast Credential Exception Agent."""

from __future__ import annotations

import json

from framework.schemas.agent_state import AgentState


# ---------------------------------------------------------------------------
# JSON helpers (mandatory per ADR-005)
# ---------------------------------------------------------------------------


def to_json(value) -> str:
    """Serialize a value to a JSON string for safe state storage."""
    return json.dumps(value, ensure_ascii=False)


def from_json(value: str | None, default=None):
    """Deserialize a JSON string from state; return default on empty/error."""
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------


class State(AgentState):
    """Flat agent state for the Live Event Broadcast Credential Exception Agent.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, correlation_id, formatted_output, result, etc.)
    are inherited from AgentState.

    All structured fields are JSON-encoded as str via to_json()/from_json().
    No credentials, secrets, clients, or raw access-control payloads are stored here.

    Field ownership:
      pre_process_node            -> exception_scope_json, approved_source_ids_json,
                                     validated_input
      retrieval_node              -> prior_approvals_json, policy_refs_json
      history_analysis_node       -> approval_history_analysis_json
      policy_applicability_node   -> policy_applicability_json
      briefing_node               -> exception_factors_json, briefing_draft_json,
                                     review_outcome, review_notes
      post_process_node           -> formatted_output, result
    """

    # -- Exception request scope ---------------------------------------------
    # JSON-encoded dict: {event_id, broadcast_role, exception_criteria,
    #                     date_window_start, date_window_end, requestor_ref}
    # No applicant PII; requestor_ref is an opaque operator-assigned reference.
    exception_scope_json: str

    # JSON-encoded list[str]: operator-configured approved source identifiers
    approved_source_ids_json: str

    # Normalized validated intake string (set by pre_process)
    validated_input: str

    # -- Retrieved data ------------------------------------------------------
    # JSON-encoded list[dict]: [{approval_id, event_id, broadcast_role,
    #                            approved_date, constraints, citation_ref}]
    # Normalized prior approval records — no raw credential values stored.
    prior_approvals_json: str

    # JSON-encoded list[dict]: [{policy_id, policy_title, section,
    #                            applicability_scope, citation_ref}]
    # References to applicable event-access policy sections.
    policy_refs_json: str

    # -- Analysis outputs ----------------------------------------------------
    # JSON-encoded dict: {pattern_summary, relevant_approvals, constraints,
    #                     uncertainty_markers, evidence_count, citation_refs}
    approval_history_analysis_json: str

    # JSON-encoded dict: {applicable_policies, requirements, prohibitions,
    #                     exceptions, policy_gaps, citation_refs}
    policy_applicability_json: str

    # -- Briefing / HITL -----------------------------------------------------
    # JSON-encoded list[dict]: [{factor_id, description, source_support,
    #                            is_assumption, citation_ref}]
    # Source-supported exception factors and unresolved items.
    exception_factors_json: str

    # JSON-encoded dict: assembled briefing draft for human review
    # Contains: summary, exception_factors, unresolved_items, citations, limitations
    # Labeled as decision support — NOT credential approval/denial.
    briefing_draft_json: str

    # "approved" | "corrected" | "rejected" | ""
    review_outcome: str

    # Operator review notes (free text, no applicant PII)
    review_notes: str

    # -- Output --------------------------------------------------------------
    # Formatted briefing string (set by post_process_node)
    formatted_output: str

    # JSON-encoded full briefing dict for structured consumption
    result: str

    # User-correctable input guidance (newline-delimited for flat state compatibility)
    input_error_message: str
    input_error_guidance: str

    # Invocation-scoped provider observability (never contains secret details)
    generation_mode: str
    provider_error_message: str
