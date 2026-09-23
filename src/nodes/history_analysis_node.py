"""HistoryAnalysisNode — prior credential exception approval history analysis for SVC-C2-070."""

from __future__ import annotations

from typing import ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json


class HistoryAnalysisNode(FunctionNode):
    """Analyze normalized prior credential exception approvals for patterns and constraints.

    Inner node — ANONYMOUS. Produces evidence and uncertainty markers from
    historical records only. Never issues approval/denial recommendations or
    determines eligibility. Returns safe partial results when evidence is sparse.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: dict) -> dict:
        prior_approvals = from_json(state.get("prior_approvals_json"), default=[])
        exception_scope = from_json(state.get("exception_scope_json"), default={})

        broadcast_role = (exception_scope or {}).get("broadcast_role", "")
        event_id = (exception_scope or {}).get("event_id", "")

        if not prior_approvals:
            emit_trace_event(
                "HistoryAnalysisNode_event",
                {"result": "no_history", "event_id": event_id},
                state,
            )
            analysis = {
                "pattern_summary": (
                    "No prior approval records found for this event/role combination. "
                    "Evidence is insufficient to identify historical patterns."
                ),
                "relevant_approvals": [],
                "constraints": [],
                "uncertainty_markers": ["No historical precedent records available for this scope"],
                "evidence_count": 0,
                "citation_refs": [],
            }
            return {
                "approval_history_analysis_json": to_json(analysis),
                "status": AgentStatus.SUCCESS.value,
            }

        # Extract relevant approvals matching broadcast_role
        relevant = [a for a in prior_approvals if not broadcast_role or a.get("broadcast_role") == broadcast_role]

        # Collect all unique constraints
        all_constraints: list[str] = []
        citation_refs: list[str] = []
        for rec in relevant:
            constraints_val = rec.get("constraints", "")
            if constraints_val and constraints_val not in all_constraints:
                all_constraints.append(constraints_val)
            cit = rec.get("citation_ref", "")
            if cit and cit not in citation_refs:
                citation_refs.append(cit)

        evidence_count = len(relevant)
        uncertainty_markers: list[str] = []

        if evidence_count == 0:
            uncertainty_markers.append(f"No approvals found matching broadcast_role='{broadcast_role}'")
            pattern_summary = (
                f"No prior approvals matching broadcast role '{broadcast_role}' were found. "
                "Insufficient historical evidence for this role."
            )
        elif evidence_count < 3:
            uncertainty_markers.append(
                f"Limited sample size ({evidence_count} records) — patterns may not be representative"
            )
            pattern_summary = (
                f"Limited history: {evidence_count} prior approval(s) found for "
                f"broadcast role '{broadcast_role}'. Patterns noted but evidence is sparse."
            )
        else:
            pattern_summary = (
                f"{evidence_count} prior approval records found for broadcast role "
                f"'{broadcast_role}'. Historical patterns and constraints documented below."
            )

        # Summarize approval records (exclude raw credential values)
        relevant_summaries = [
            {
                "approval_id": r.get("approval_id", ""),
                "approved_date": r.get("approved_date", ""),
                "broadcast_role": r.get("broadcast_role", ""),
                "constraints": r.get("constraints", ""),
                "citation_ref": r.get("citation_ref", ""),
            }
            for r in relevant
        ]

        analysis = {
            "pattern_summary": pattern_summary,
            "relevant_approvals": relevant_summaries,
            "constraints": all_constraints,
            "uncertainty_markers": uncertainty_markers,
            "evidence_count": evidence_count,
            "citation_refs": citation_refs,
        }

        emit_trace_event(
            "HistoryAnalysisNode_event",
            {
                "result": "analyzed",
                "evidence_count": evidence_count,
                "constraint_count": len(all_constraints),
                "uncertainty_markers": len(uncertainty_markers),
            },
            state,
        )

        return {
            "approval_history_analysis_json": to_json(analysis),
            "status": AgentStatus.SUCCESS.value,
        }
