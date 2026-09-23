"""BriefingNode — credential exception briefing synthesis and HITL review for SVC-C2-070."""

from __future__ import annotations

from typing import ClassVar

from langgraph.errors import GraphInterrupt
from langgraph.types import Interrupt

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.hitl_status import HitlStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json


class BriefingNode(FunctionNode):
    """Synthesize exception factors and build a traceable briefing for authorized human review.

    Inner node — ANONYMOUS. Separates source-supported facts from assumptions and gaps.
    Makes no approval/denial, operational, legal, or security conclusion.
    Uses D6 interrupt() guarded by hitl_allowed for human review.
    Output is clearly labeled as decision support — not credential provisioning.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: dict) -> dict:
        exception_scope = from_json(state.get("exception_scope_json"), default={})
        history_analysis = from_json(state.get("approval_history_analysis_json"), default={})
        policy_applicability = from_json(state.get("policy_applicability_json"), default={})

        event_id = (exception_scope or {}).get("event_id", "")
        broadcast_role = (exception_scope or {}).get("broadcast_role", "")
        exception_criteria = (exception_scope or {}).get("exception_criteria", "")
        requestor_ref = (exception_scope or {}).get("requestor_ref", "")

        # ── Check for resume after human review ──────────────────────────────
        hitl_status = state.get("hitl_status")
        if hitl_status == HitlStatus.APPROVED.value:
            emit_trace_event(
                "BriefingNode_event",
                {"result": "review_approved", "event_id": event_id},
                state,
            )
            return {
                "review_outcome": "approved",
                "review_notes": state.get("hitl_feedback", ""),
                "status": AgentStatus.SUCCESS.value,
            }

        if hitl_status == HitlStatus.CORRECTED.value:
            emit_trace_event(
                "BriefingNode_event",
                {"result": "review_corrected", "event_id": event_id},
                state,
            )
            return {
                "review_outcome": "corrected",
                "review_notes": str(state.get("hitl_feedback", "")),
                "status": AgentStatus.SUCCESS.value,
            }

        if hitl_status == HitlStatus.REJECTED.value:
            emit_trace_event(
                "BriefingNode_event",
                {"result": "review_rejected", "event_id": event_id},
                state,
            )
            return {
                "review_outcome": "rejected",
                "review_notes": str(state.get("hitl_feedback", "")),
                "status": AgentStatus.ERROR.value,
                "error_log": ["BriefingNode: briefing rejected by authorized reviewer"],
            }

        # ── Check for pre-existing draft (idempotency) ───────────────────────
        existing_draft_json = state.get("briefing_draft_json", "")
        if existing_draft_json:
            existing_draft = from_json(existing_draft_json, default={})
            if existing_draft:
                # Draft already assembled — go directly to interrupt if HITL allowed
                self._interrupt_for_review(state, existing_draft, event_id)
                # Execution resumes here after interrupt (only when hitl_allowed=False)
                emit_trace_event(
                    "BriefingNode_event",
                    {"result": "draft_reused", "event_id": event_id},
                    state,
                )
                return {
                    "review_outcome": "",
                    "status": AgentStatus.SUCCESS.value,
                }

        # ── Build exception factors ──────────────────────────────────────────
        exception_factors = self._build_exception_factors(
            exception_scope=exception_scope or {},
            history_analysis=history_analysis or {},
            policy_applicability=policy_applicability or {},
        )

        # ── Collect all citation refs ────────────────────────────────────────
        all_citations: list[str] = []
        all_citations.extend((history_analysis or {}).get("citation_refs", []))
        all_citations.extend((policy_applicability or {}).get("citation_refs", []))
        all_citations = list(dict.fromkeys(all_citations))  # deduplicate, preserve order

        # ── Identify unresolved items ────────────────────────────────────────
        unresolved_items: list[str] = []
        unresolved_items.extend((history_analysis or {}).get("uncertainty_markers", []))
        unresolved_items.extend((policy_applicability or {}).get("policy_gaps", []))

        # ── Assemble briefing draft ──────────────────────────────────────────
        briefing_draft = {
            "event_id": event_id,
            "broadcast_role": broadcast_role,
            "exception_criteria": exception_criteria,
            "requestor_ref": requestor_ref,
            "summary": (
                f"Credential exception briefing for event '{event_id}', "
                f"broadcast role '{broadcast_role}'. "
                f"Exception criteria: {exception_criteria}. "
                "This briefing is decision support for authorized human review — "
                "it does not approve, deny, or provision credentials."
            ),
            "exception_factors": exception_factors,
            "unresolved_items": unresolved_items,
            "history_pattern_summary": (history_analysis or {}).get("pattern_summary", ""),
            "applicable_policy_count": len((policy_applicability or {}).get("applicable_policies", [])),
            "citations": all_citations,
            "limitations": [
                "This briefing is decision support only — it does not approve or deny credentials.",
                "The agent does not provision, revoke, or alter access-control settings.",
                "Applicant notifications are out of scope.",
                "Policy interpretation requires authorized human judgment.",
                "Historical evidence is bounded to approved sources only.",
            ],
            "label": "DECISION SUPPORT — NOT CREDENTIAL APPROVAL OR DENIAL",
        }

        briefing_draft_json = to_json(briefing_draft)

        # ── Interrupt for human review ───────────────────────────────────────
        self._interrupt_for_review(state, briefing_draft, event_id)
        # Execution resumes here only when hitl_allowed=False (automated path)

        emit_trace_event(
            "BriefingNode_event",
            {
                "result": "briefing_assembled",
                "event_id": event_id,
                "factor_count": len(exception_factors),
                "unresolved_count": len(unresolved_items),
                "citation_count": len(all_citations),
            },
            state,
        )

        return {
            "exception_factors_json": to_json(exception_factors),
            "briefing_draft_json": briefing_draft_json,
            "review_outcome": "",
            "status": AgentStatus.SUCCESS.value,
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _interrupt_for_review(self, state: dict, draft: dict, event_id: str) -> None:
        """Fire HITL interrupt only when hitl_allowed — guards against deadlock in pipelines."""
        if state.get("hitl_allowed", True):
            raise GraphInterrupt(
                (
                    Interrupt(
                        value={
                            "message": (
                                "Credential exception briefing assembled for authorized human review. "
                                "This is decision support — NOT credential approval or provisioning."
                            ),
                            "event_id": event_id,
                            "label": "DECISION SUPPORT REVIEW",
                            "actions": ["approve", "correct", "reject"],
                            "draft_summary": draft.get("summary", ""),
                            "unresolved_items": draft.get("unresolved_items", []),
                        }
                    ),
                )
            )

    def _build_exception_factors(
        self,
        exception_scope: dict,
        history_analysis: dict,
        policy_applicability: dict,
    ) -> list[dict]:
        """Build traceable exception factors from source-supported evidence only."""
        factors: list[dict] = []
        factor_id = 1

        # Historical evidence factor
        evidence_count = history_analysis.get("evidence_count", 0)
        pattern_summary = history_analysis.get("pattern_summary", "")
        if pattern_summary:
            factors.append(
                {
                    "factor_id": f"F-{factor_id:03d}",
                    "description": f"Historical approval evidence: {pattern_summary}",
                    "source_support": "prior_approval_records",
                    "is_assumption": evidence_count == 0,
                    "citation_ref": "; ".join(history_analysis.get("citation_refs", [])),
                }
            )
            factor_id += 1

        # Constraint factors from history
        for constraint in history_analysis.get("constraints", []):
            factors.append(
                {
                    "factor_id": f"F-{factor_id:03d}",
                    "description": f"Historical constraint observed: {constraint}",
                    "source_support": "prior_approval_records",
                    "is_assumption": False,
                    "citation_ref": "; ".join(history_analysis.get("citation_refs", [])),
                }
            )
            factor_id += 1

        # Policy requirement factors
        for req in policy_applicability.get("requirements", []):
            factors.append(
                {
                    "factor_id": f"F-{factor_id:03d}",
                    "description": f"Policy requirement applies: {req}",
                    "source_support": "policy_refs",
                    "is_assumption": False,
                    "citation_ref": req,
                }
            )
            factor_id += 1

        # Policy prohibition factors
        for proh in policy_applicability.get("prohibitions", []):
            factors.append(
                {
                    "factor_id": f"F-{factor_id:03d}",
                    "description": f"Policy prohibition applies: {proh}",
                    "source_support": "policy_refs",
                    "is_assumption": False,
                    "citation_ref": proh,
                }
            )
            factor_id += 1

        # Policy exception factors
        for exc in policy_applicability.get("exceptions", []):
            factors.append(
                {
                    "factor_id": f"F-{factor_id:03d}",
                    "description": f"Policy exception clause identified: {exc}",
                    "source_support": "policy_refs",
                    "is_assumption": False,
                    "citation_ref": exc,
                }
            )
            factor_id += 1

        return factors
