# PB-7: HITL interrupt propagation for the credential briefing review gate.

from __future__ import annotations

import pathlib
import warnings

import pytest
from framework.schemas.trust_level import TrustLevel
from src.nodes.briefing_node import BriefingNode
from src.schemas.state import to_json

_CONFIG_PATH = pathlib.Path(__file__).parents[2] / "config" / "config.yaml"


def _hitl_enabled() -> bool:
    if not _CONFIG_PATH.exists():
        warnings.warn(f"{_CONFIG_PATH} not found — PB-7 skipped.", stacklevel=2)
        return False
    try:
        import yaml

        data = yaml.safe_load(_CONFIG_PATH.read_text())
    except Exception as exc:
        warnings.warn(f"{_CONFIG_PATH} could not be read as YAML ({exc}) — PB-7 skipped.", stacklevel=2)
        return False
    hitl = (data or {}).get("hitl", {}) if isinstance(data, dict) else None
    if not isinstance(hitl, dict):
        warnings.warn(
            f"{_CONFIG_PATH} does not have the expected 'hitl:' mapping shape — PB-7 skipped.",
            stacklevel=2,
        )
        return False
    return bool(hitl.get("enabled", False))


pytestmark = pytest.mark.skipif(
    not _hitl_enabled(),
    reason="config/config.yaml does not set hitl.enabled: true — PB-7 not applicable",
)

def _base_state(**overrides) -> dict:
    state = {
        "caller_trust_level": TrustLevel.ANONYMOUS.value,
        "correlation_id": "pb7-test",
        "session_id": "pb7-session",
        "thread_id": "pb7-thread",
        "trace_id": "pb7-trace",
        "node_history": [],
        "error_log": [],
        "hitl_allowed": True,
        "hitl_count": 0,
        "hitl_status": None,
        "exception_scope_json": to_json(
            {
                "event_id": "EVT-BROADCAST-2024",
                "broadcast_role": "host_broadcaster",
                "exception_criteria": "Replacement after credential loss",
                "date_window_start": "2024-03-01",
                "date_window_end": "2024-04-30",
                "requestor_ref": "REQ-2024-001",
                "operator_id": "OP-001",
            }
        ),
        "approved_source_ids_json": to_json(["source-approved-history"]),
        "prior_approvals_json": to_json([]),
        "policy_refs_json": to_json([]),
        "approval_history_analysis_json": to_json(
            {
                "pattern_summary": "No prior approvals.",
                "relevant_approvals": [],
                "constraints": [],
                "uncertainty_markers": ["No history"],
                "evidence_count": 0,
                "citation_refs": [],
            }
        ),
        "policy_applicability_json": to_json(
            {
                "applicable_policies": [],
                "requirements": [],
                "prohibitions": [],
                "exceptions": [],
                "policy_gaps": ["No policy data"],
                "citation_refs": [],
            }
        ),
    }
    state.update(overrides)
    return state


def test_pb7_hitl_interrupt_propagates() -> None:
    from langgraph.errors import GraphInterrupt

    with pytest.raises(GraphInterrupt):
        BriefingNode()(_base_state(hitl_allowed=True))


def test_pb7_hitl_allowed_false_skips_interrupt() -> None:
    from framework.schemas.agent_status import AgentStatus

    result = BriefingNode()(_base_state(hitl_allowed=False))
    assert result["status"] == AgentStatus.SUCCESS.value
    assert result["briefing_draft_json"]
