"""DomainWorkflowGraph — inner BaseGraph for SVC-C2-070 credential exception workflow."""

from __future__ import annotations

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from src.nodes.retrieval_node import RetrievalNode
from src.nodes.history_analysis_node import HistoryAnalysisNode
from src.nodes.policy_applicability_node import PolicyApplicabilityNode
from src.nodes.briefing_node import BriefingNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner fixed-workflow graph for the Live Event Broadcast Credential Exception Agent.

    Called by CredentialExceptionGraphNode.get_subgraph() in graph.py.

    Pipeline:
        START
          → retrieval          (approved credential history and policy retrieval)
          → history_analysis   (prior approval pattern analysis)
          → policy_applicability (event-access policy mapping)
          → briefing           (exception factor synthesis + HITL review)
          → END

    All nodes are ANONYMOUS trust level (inner graph — trust-trap anti-pattern if violated).
    Output labeled as decision support only — not credential approval, denial, or provisioning.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "svc_c2_070_credential_exception_workflow"

    @property
    def state_schema(self) -> type:
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        pass  # No mandatory inner-graph config keys

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all domain nodes. No super() — BaseGraph is abstract."""
        self._nodes["retrieval"] = RetrievalNode(adapter=self.config.get("credential_history_adapter"))
        self._nodes["history_analysis"] = HistoryAnalysisNode()
        self._nodes["policy_applicability"] = PolicyApplicabilityNode()
        self._nodes["briefing"] = BriefingNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the fixed credential exception workflow."""
        self._sg.add_edge(START, "retrieval")
        self._sg.add_edge("retrieval", "history_analysis")
        self._sg.add_edge("history_analysis", "policy_applicability")
        self._sg.add_edge("policy_applicability", "briefing")
        self._sg.add_edge("briefing", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Required by BaseGraph ABC — not called in this linear topology."""
        return str(END)

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> dict:
        """Shape the output dict returned to the outer GraphNode as sub_result.

        Designed together with CredentialExceptionGraphNode.merge_output() in graph.py.
        """
        return {
            "output": state.get("formatted_output") or state.get("result"),
            "status": state.get("status"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
            # Domain-specific fields for outer merge
            "validated_input": state.get("validated_input", ""),
            "exception_scope_json": state.get("exception_scope_json", ""),
            "approved_source_ids_json": state.get("approved_source_ids_json", ""),
            "prior_approvals_json": state.get("prior_approvals_json", ""),
            "policy_refs_json": state.get("policy_refs_json", ""),
            "approval_history_analysis_json": state.get("approval_history_analysis_json", ""),
            "policy_applicability_json": state.get("policy_applicability_json", ""),
            "exception_factors_json": state.get("exception_factors_json", ""),
            "briefing_draft_json": state.get("briefing_draft_json", ""),
            "review_outcome": state.get("review_outcome", ""),
            "review_notes": state.get("review_notes", ""),
            "formatted_output": state.get("formatted_output", ""),
            "result": state.get("result", ""),
            "error_log": state.get("error_log", []),
        }
