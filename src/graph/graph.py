"""Graph — outer AgentBaseGraph for SVC-C2-070 Live Event Broadcast Credential Exception Agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.utils.config_loader import load_config
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import State


# Customer-facing failure reasons (Harness H3).
#
# framework/nodes/base_node.py stores error_log entries as
# f"[{node_name}] {exc}\n{traceback.format_exc()}". Marketplace Chat renders
# `output` verbatim, so a raw entry would leak node class names, absolute file
# paths and line numbers to the end user.
_SAFE_REASONS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("missingsecret", "required secret", "not found (checked"), "CONFIGURATION_MISSING"),
    (("authentication", "unauthorized", "401"), "AUTHENTICATION_FAILED"),
    (("ratelimit", "rate limit", "too many requests", "429"), "RATE_LIMITED"),
    (("timeout", "timed out"), "SERVICE_TIMEOUT"),
    (("connecterror", "connection refused", "proxyerror"), "CONNECTION_FAILED"),
    (("not yet wired", "notimplementederror"), "SOURCE_UNAVAILABLE"),
)

_SAFE_REASON_TEXT: dict[str, str] = {
    "CONFIGURATION_MISSING": (
        "A credential required to read the credential-history source is not configured "
        "in this environment. Ask an administrator to provision it, then retry."
    ),
    "AUTHENTICATION_FAILED": "A configured credential was rejected by the upstream service.",
    "RATE_LIMITED": "An upstream service is rate limiting requests.",
    "SERVICE_TIMEOUT": "An upstream service did not respond in time.",
    "CONNECTION_FAILED": "An upstream service could not be reached.",
    "SOURCE_UNAVAILABLE": "A required data source is not available in this environment.",
    "INTERNAL_PROCESSING_ERROR": (
        "The credential-exception review could not be completed because of an internal error."
    ),
}


def _safe_reason(error_log: object) -> str:
    """Map raw framework error_log entries to one customer-safe line.

    Never returns node names, file paths, line numbers or traceback text.
    """
    entries = [str(e) for e in error_log] if isinstance(error_log, (list, tuple)) else []
    haystack = " ".join(entries).lower()
    for needles, code in _SAFE_REASONS:
        if any(n in haystack for n in needles):
            return f"{_SAFE_REASON_TEXT[code]} (Reference: {code})"
    code = "INTERNAL_PROCESSING_ERROR"
    return f"{_SAFE_REASON_TEXT[code]} (Reference: {code})"


class CredentialExceptionGraphNode(GraphNode):
    """Wraps the inner DomainWorkflowGraph; assigned to the `main` slot.

    propagate_hitl=True surfaces the briefing HITL interrupt to the outer
    caller (server.py / AgentGateway) for authorized operator review.
    """

    # "handle", not "propagate": a propagated SubgraphError ends the run at
    # status=error, and the Marketplace runner then drops `output` and shows the
    # caller a bare RuntimeError with no reason (Harness G2/G3).
    error_strategy: ClassVar[str] = "handle"
    propagate_hitl: ClassVar[bool] = True

    def __init__(self, config: dict[str, Any] | None = None, llm: Any = None) -> None:
        super().__init__()
        self._config = dict(config or {})
        self._llm = llm
        self._config["llm"] = llm

    def get_subgraph(self):
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=self._parent_config())

    def extract_input(self, state: AgentState) -> str:
        return state.get("validated_input", state.get("user_input", ""))

    def on_subgraph_error(self, state: AgentState, error: Exception) -> dict[str, Any]:
        """Report an inner failure through the caller-visible guidance channel.

        Reported on a SUCCESS envelope because the Marketplace runner only
        forwards `output` when status == "success" (Harness G3/H6).
        """
        del state
        return {
            "status": AgentStatus.SUCCESS.value,
            "input_error_message": _safe_reason(getattr(error, "error_log", None) or []),
        }

    def merge_output(self, state: AgentState, sub_result: dict) -> dict:
        """Map all inner graph domain fields back to the outer state.

        Receives the dict from DomainWorkflowGraph.get_output().
        Returns only the keys changed by the inner graph.
        """
        delta: dict = {
            "status": sub_result.get("status"),
        }
        for key in (
            "validated_input",
            "exception_scope_json",
            "approved_source_ids_json",
            "prior_approvals_json",
            "policy_refs_json",
            "approval_history_analysis_json",
            "policy_applicability_json",
            "exception_factors_json",
            "briefing_draft_json",
            "review_outcome",
            "review_notes",
            "formatted_output",
            "result",
            "error_log",
            "node_history",
        ):
            val = sub_result.get(key)
            if val is not None:
                delta[key] = val
        return delta

    def execute(self, state: AgentState) -> dict[str, Any]:
        if state.get("input_error_message"):
            return {"status": AgentStatus.SUCCESS.value}
        return cast(dict[str, Any], super().execute(state))

    def _parent_config(self) -> dict[str, Any]:
        """Forward runtime configuration, including the injected LLM."""
        return self._config


class Graph(AgentBaseGraph):
    """Cat 2 outer AgentBaseGraph for SVC-C2-070.

    Domain logic is encapsulated in CredentialExceptionGraphNode (main slot).
    Backbone: initialize → pre_process → main → post_process → finalize.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    # Harness J2/J4: the Marketplace runner constructs the agent with a bare
    # ``agent_cls()`` on agentcore 1.0.1 and ``agent_cls(config=...)`` on 1.0.3,
    # and it never reads ``config/config.yaml``. Without it the inner graph gets
    # an empty config, so hitl.enabled never reaches it and its interrupt() call
    # raises "no checkpointer is attached". ``**kwargs`` absorbs arguments added
    # by later runner versions.
    def __init__(self, config: dict[str, Any] | None = None, **kwargs: Any) -> None:
        # Load config/config.yaml first, then overlay whatever the runner passed.
        # agentcore 1.0.1 calls agent_cls() (config=None) but 1.0.3 calls
        # agent_cls(config={...}) — often an EMPTY dict. Keying off `is None`
        # alone therefore skipped the file load on 1.0.3 and left required keys
        # missing, which surfaced as a bare
        # "Graph invocation did not succeed: status='error'".
        config_path = Path(__file__).resolve().parents[2] / "config" / "config.yaml"
        file_config = load_config(str(config_path)) if config_path.exists() else {}
        config = {**file_config, **dict(config or {})}
        self._config: dict[str, Any] = dict(config)
        super().__init__(config=self._config, **kwargs)

    @property
    def name(self) -> str:
        return "svc_c2_070"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # fills: initialize, finalize
        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = CredentialExceptionGraphNode(
            config=self.config,
            llm=self.config.get("llm"),
        )
        self._nodes["post_process"] = PostProcessNode(
            llm=self.config.get("llm"),
            config=self.config,
        )

    def get_output(self, state: AgentState) -> dict[str, Any]:
        output = {
            "output": state.get("formatted_output") or state.get("result", ""),
            "result": state.get("result", ""),
            "status": state.get("status", AgentStatus.ERROR.value),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
            "generation_mode": state.get("generation_mode"),
            "provider_error_message": state.get("provider_error_message"),
        }
        _set_marketplace_guidance(output, state, "Broadcast credential-exception request")
        return output


def _set_marketplace_guidance(output: dict[str, Any], state: AgentState, subject: str) -> None:
    context = state.get("input_context")
    message = state.get("input_error_message")
    if not (isinstance(context, dict) and "conversation_history" in context and message):
        return
    lines = [f"{subject} could not be processed.", "", f"Reason: {message}"]
    guidance = state.get("input_error_guidance")
    if isinstance(guidance, str) and guidance:
        lines.extend(["", "How to continue:"])
        lines.extend(f"- {item}" for item in guidance.splitlines())
    output["output"] = "\n".join(lines)

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.
