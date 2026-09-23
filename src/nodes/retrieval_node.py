"""RetrievalNode — approved credential history and policy retrieval for SVC-C2-070."""

from __future__ import annotations

from typing import ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json
from src.services.credential_history_adapter import (
    CredentialHistoryAdapter,
    FakeCredentialHistoryAdapter,
    SourceNotAllowedError,
)


class RetrievalNode(FunctionNode):
    """Retrieve normalized prior approval records and policy references from approved sources.

    Inner node — ANONYMOUS. Enforces source allowlisting; maps provider data
    to serializable records with citation provenance before state storage.
    Supports safe no-result and source-error paths.
    Never stores raw credential values or access-control system responses in state.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, adapter: CredentialHistoryAdapter | None = None) -> None:
        self._adapter = adapter or FakeCredentialHistoryAdapter()

    def execute(self, state: dict) -> dict:
        ctx = InvocationContext.from_state(state)
        # Secrets declared in agent.yaml under requires.secrets
        _history_token = ctx.secrets.require("CREDENTIAL_HISTORY_TOKEN")

        exception_scope = from_json(state.get("exception_scope_json"), default={})
        approved_source_ids = from_json(state.get("approved_source_ids_json"), default=[])

        event_id = (exception_scope or {}).get("event_id", "")
        broadcast_role = (exception_scope or {}).get("broadcast_role", "")
        date_window_start = (exception_scope or {}).get("date_window_start", "")
        date_window_end = (exception_scope or {}).get("date_window_end", "")

        if not event_id or not approved_source_ids:
            emit_trace_event("RetrievalNode_event", {"result": "missing_scope"}, state)
            return {
                "prior_approvals_json": to_json([]),
                "policy_refs_json": to_json([]),
                "status": AgentStatus.SUCCESS.value,
            }

        all_prior_approvals: list[dict] = []
        all_policy_refs: list[dict] = []
        retrieval_errors: list[str] = []

        for source_id in approved_source_ids:
            # Fetch prior approvals
            try:
                approvals = self._adapter.fetch_prior_approvals(
                    source_id=source_id,
                    event_id=event_id,
                    broadcast_role=broadcast_role,
                    date_window_start=date_window_start,
                    date_window_end=date_window_end,
                )
                all_prior_approvals.extend(approvals)
            except SourceNotAllowedError as exc:
                retrieval_errors.append(f"RetrievalNode: source not allowed: {exc}")
            except Exception as exc:  # noqa: BLE001
                retrieval_errors.append(f"RetrievalNode: prior approval fetch error for '{source_id}': {exc}")

            # Fetch policy refs
            try:
                policy_refs = self._adapter.fetch_policy_refs(
                    source_id=source_id,
                    event_id=event_id,
                    broadcast_role=broadcast_role,
                )
                all_policy_refs.extend(policy_refs)
            except SourceNotAllowedError as exc:
                retrieval_errors.append(f"RetrievalNode: source not allowed for policy: {exc}")
            except Exception as exc:  # noqa: BLE001
                retrieval_errors.append(f"RetrievalNode: policy ref fetch error for '{source_id}': {exc}")

        emit_trace_event(
            "RetrievalNode_event",
            {
                "result": "retrieved",
                "prior_approval_count": len(all_prior_approvals),
                "policy_ref_count": len(all_policy_refs),
                "source_count": len(approved_source_ids),
                "errors": len(retrieval_errors),
            },
            state,
        )

        result: dict = {
            "prior_approvals_json": to_json(all_prior_approvals),
            "policy_refs_json": to_json(all_policy_refs),
            "status": AgentStatus.SUCCESS.value,
        }
        if retrieval_errors:
            result["error_log"] = retrieval_errors
        return result
