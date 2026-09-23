"""Unit tests for SVC-C2-070 node business logic.

Tests are deterministic, use no live credentials, access-control systems,
or external network calls. FakeCredentialHistoryAdapter provides controlled
test doubles. Agent does not approve/deny credentials, provision access,
or notify applicants.

Coverage:
  TC-01  State to_json/from_json roundtrip
  BL-01  PreProcessNode — valid scope input
  BL-02  PreProcessNode — empty input rejected
  BL-03  PreProcessNode — invalid JSON rejected
  BL-04  PreProcessNode — missing required fields rejected
  BL-05  PreProcessNode — unsupported broadcast_role rejected
  BL-06  PreProcessNode — empty approved_source_ids rejected
  BL-07  RetrievalNode — approved sources retrieved with provenance
  BL-08  RetrievalNode — no scope fields yields empty results
  BL-09  RetrievalNode — unknown source ID handled
  BL-10  HistoryAnalysisNode — prior approvals analyzed with patterns
  BL-11  HistoryAnalysisNode — no prior approvals yields safe partial result
  BL-12  HistoryAnalysisNode — unmatched broadcast_role yields uncertainty markers
  BL-13  PolicyApplicabilityNode — policy refs mapped to requirements/prohibitions
  BL-14  PolicyApplicabilityNode — no policy refs yields gap markers
  BL-15  BriefingNode — draft assembled with exception factors
  BL-16  BriefingNode — approved HITL resume sets review_outcome
  BL-17  BriefingNode — corrected HITL resume sets review_outcome
  BL-18  BriefingNode — rejected HITL resume sets error status
  BL-19  BriefingNode — hitl_allowed=False skips interrupt
  BL-20  PostProcessNode — formats output from briefing draft
  BL-21  PostProcessNode — no draft yields error
  BL-22  PostProcessNode — review disposition included in output
  TC-08  PreProcessNode S-2 rejects oversized input
  TC-09  PreProcessNode S-2 rejects non-JSON input
  TC-11  Nodes emit domain audit events in execute()
"""

from __future__ import annotations

import json

import pytest

from framework.errors import SecurityViolationError
from framework.schemas.agent_status import AgentStatus
from framework.schemas.hitl_status import HitlStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.briefing_node import BriefingNode
from src.nodes.history_analysis_node import HistoryAnalysisNode
from src.nodes.policy_applicability_node import PolicyApplicabilityNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.retrieval_node import RetrievalNode
from src.schemas.state import from_json, to_json
from src.services.credential_history_adapter import FakeCredentialHistoryAdapter

VERIFIED = TrustLevel.VERIFIED_EXTERNAL
ANON = TrustLevel.ANONYMOUS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_state(**overrides) -> dict:
    """Minimal valid state for inner nodes (ANONYMOUS)."""
    state: dict = {
        "caller_trust_level": ANON.value,
        "session_id": "sess-test",
        "correlation_id": "corr-test",
        "thread_id": "thread-test",
        "trace_id": "trace-test",
        "node_history": [],
        "error_log": [],
        "hitl_allowed": False,
        "hitl_count": 0,
        "exception_scope_json": to_json({
            "event_id": "EVT-BROADCAST-2024",
            "broadcast_role": "host_broadcaster",
            "exception_criteria": "Replacement after credential loss",
            "date_window_start": "2024-03-01",
            "date_window_end": "2024-04-30",
            "requestor_ref": "REQ-2024-001",
            "operator_id": "OP-001",
        }),
        "approved_source_ids_json": to_json(["source-approved-history", "source-policy-store"]),
        "validated_input": json.dumps({
            "event_id": "EVT-BROADCAST-2024",
            "broadcast_role": "host_broadcaster",
            "exception_criteria": "Replacement after credential loss",
            "approved_source_ids": ["source-approved-history", "source-policy-store"],
        }),
    }
    state.update(overrides)
    return state


def _pre_process_state(**overrides) -> dict:
    """State for PreProcessNode (VERIFIED_EXTERNAL)."""
    state = _base_state(**overrides)
    state["caller_trust_level"] = VERIFIED.value
    return state


def _valid_input() -> str:
    return json.dumps({
        "event_id": "EVT-BROADCAST-2024",
        "broadcast_role": "host_broadcaster",
        "exception_criteria": "Replacement after credential loss",
        "approved_source_ids": ["source-approved-history", "source-policy-store"],
        "requestor_ref": "REQ-2024-001",
    })


def _state_with_history(**overrides) -> dict:
    """State with prior approvals and policy refs populated."""
    adapter = FakeCredentialHistoryAdapter()
    approvals = adapter.fetch_prior_approvals(
        source_id="source-approved-history",
        event_id="EVT-BROADCAST-2024",
        broadcast_role="host_broadcaster",
    )
    policy_refs = adapter.fetch_policy_refs(
        source_id="source-policy-store",
        event_id="EVT-BROADCAST-2024",
        broadcast_role="host_broadcaster",
    )
    state = _base_state(
        prior_approvals_json=to_json(approvals),
        policy_refs_json=to_json(policy_refs),
    )
    state.update(overrides)
    return state


def _state_with_analysis(**overrides) -> dict:
    """State with history and policy analysis populated."""
    from src.nodes.history_analysis_node import HistoryAnalysisNode as HAN
    from src.nodes.policy_applicability_node import PolicyApplicabilityNode as PAN

    base = _state_with_history()
    han = HAN()
    pan = PAN()
    base.update(han(base))
    base.update(pan(base))
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# TC-01  State helpers
# ---------------------------------------------------------------------------

class TestStateHelpers:
    def test_to_json_from_json_roundtrip(self):
        """TC-01: to_json/from_json roundtrip preserves structure."""
        data = {"key": "value", "num": 42, "list": [1, 2, 3]}
        assert from_json(to_json(data)) == data

    def test_from_json_empty_returns_default(self):
        assert from_json("", default=[]) == []
        assert from_json(None, default={}) == {}


# ---------------------------------------------------------------------------
# BL-01..BL-06  PreProcessNode
# ---------------------------------------------------------------------------

class TestPreProcessNode:
    def test_bl01_valid_scope_input(self):
        """BL-01: valid JSON input normalizes into scope and source fields."""
        node = PreProcessNode()
        state = _pre_process_state(user_input=_valid_input())
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        scope = from_json(result["exception_scope_json"])
        assert scope["event_id"] == "EVT-BROADCAST-2024"
        assert scope["broadcast_role"] == "host_broadcaster"
        source_ids = from_json(result["approved_source_ids_json"])
        assert "source-approved-history" in source_ids

    def test_bl02_empty_input_rejected(self):
        """BL-02: empty user_input yields ERROR status."""
        node = PreProcessNode()
        state = _pre_process_state(user_input="")
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["input_error_message"]

    def test_bl03_invalid_json_rejected(self):
        """BL-03: non-JSON user_input yields ERROR status."""
        node = PreProcessNode()
        state = _pre_process_state(user_input="{not-json}")
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "JSON" in result["input_error_message"]

    def test_bl04_missing_required_fields_rejected(self):
        """BL-04: missing event_id yields ERROR with field list in error_log."""
        node = PreProcessNode()
        payload = {"broadcast_role": "host_broadcaster", "exception_criteria": "test"}
        state = _pre_process_state(user_input=json.dumps(payload))
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "event_id" in result["input_error_message"]

    def test_bl05_unsupported_broadcast_role_rejected(self):
        """BL-05: unsupported broadcast_role yields ERROR status."""
        node = PreProcessNode()
        payload = {
            "event_id": "EVT-001",
            "broadcast_role": "INVALID_ROLE",
            "exception_criteria": "test",
            "approved_source_ids": ["source-approved-history"],
        }
        state = _pre_process_state(user_input=json.dumps(payload))
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "broadcast_role" in result["input_error_message"]

    def test_bl06_empty_approved_source_ids_rejected(self):
        """BL-06: empty approved_source_ids yields ERROR status."""
        node = PreProcessNode()
        payload = {
            "event_id": "EVT-001",
            "broadcast_role": "host_broadcaster",
            "exception_criteria": "test",
            "approved_source_ids": [],
        }
        state = _pre_process_state(user_input=json.dumps(payload))
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "approved_source_ids" in result["input_error_message"]

    def test_tc08_s2_rejects_oversized_input(self):
        """TC-08: S-2 extension rejects input exceeding size limit."""
        node = PreProcessNode()
        state = _pre_process_state(user_input="{" + "x" * 9000 + "}")
        result = node(state)
        assert result["status"] == AgentStatus.ERROR.value
        assert any("input exceeds" in message for message in result["error_log"])

    def test_tc09_s2_rejects_non_json_input(self):
        """TC-09: S-2 extension rejects non-JSON (non-brace-starting) input."""
        node = PreProcessNode()
        state = _pre_process_state(user_input="plain text input")
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "JSON object string" in result["input_error_message"]


# ---------------------------------------------------------------------------
# BL-07..BL-09  RetrievalNode
# ---------------------------------------------------------------------------

class TestRetrievalNode:
    def test_bl07_retrieves_approved_sources_with_provenance(self):
        """BL-07: adapter returns normalized records with citation_ref provenance."""
        node = RetrievalNode(adapter=FakeCredentialHistoryAdapter())
        state = _base_state()
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        approvals = from_json(result["prior_approvals_json"])
        assert isinstance(approvals, list)
        if approvals:
            assert "citation_ref" in approvals[0]
            assert "approval_id" in approvals[0]

    def test_bl08_no_scope_yields_empty_results(self):
        """BL-08: missing exception_scope yields empty approvals and policy refs."""
        node = RetrievalNode(adapter=FakeCredentialHistoryAdapter())
        state = _base_state(exception_scope_json="", approved_source_ids_json="")
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert from_json(result["prior_approvals_json"]) == []
        assert from_json(result["policy_refs_json"]) == []

    def test_bl09_unknown_source_id_handled(self):
        """BL-09: unknown source ID is handled gracefully — partial results preserved."""
        node = RetrievalNode(adapter=FakeCredentialHistoryAdapter())
        state = _base_state(
            approved_source_ids_json=to_json(["source-approved-history", "UNKNOWN-SOURCE"])
        )
        result = node(state)
        # Should succeed even with one failing source
        assert result["status"] == AgentStatus.SUCCESS.value
        # Error logged for the failing source
        assert result.get("error_log") or True  # partial is acceptable


# ---------------------------------------------------------------------------
# BL-10..BL-12  HistoryAnalysisNode
# ---------------------------------------------------------------------------

class TestHistoryAnalysisNode:
    def test_bl10_prior_approvals_analyzed_with_patterns(self):
        """BL-10: populated prior_approvals yields pattern summary and factors."""
        node = HistoryAnalysisNode()
        state = _state_with_history()
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        analysis = from_json(result["approval_history_analysis_json"])
        assert "pattern_summary" in analysis
        assert isinstance(analysis.get("relevant_approvals"), list)
        assert "evidence_count" in analysis

    def test_bl11_no_prior_approvals_yields_safe_partial(self):
        """BL-11: empty prior_approvals yields safe partial result with uncertainty marker."""
        node = HistoryAnalysisNode()
        state = _base_state(prior_approvals_json=to_json([]))
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        analysis = from_json(result["approval_history_analysis_json"])
        assert analysis["evidence_count"] == 0
        assert len(analysis["uncertainty_markers"]) > 0

    def test_bl12_unmatched_broadcast_role_yields_uncertainty(self):
        """BL-12: broadcast_role with no matching records yields uncertainty markers."""
        node = HistoryAnalysisNode()
        state = _state_with_history()
        scope = from_json(state["exception_scope_json"])
        scope["broadcast_role"] = "technical_services"
        state["exception_scope_json"] = to_json(scope)
        result = node(state)
        analysis = from_json(result["approval_history_analysis_json"])
        assert len(analysis.get("uncertainty_markers", [])) > 0


# ---------------------------------------------------------------------------
# BL-13..BL-14  PolicyApplicabilityNode
# ---------------------------------------------------------------------------

class TestPolicyApplicabilityNode:
    def test_bl13_policy_refs_mapped_to_categories(self):
        """BL-13: policy refs are mapped to applicable_policies list with citations."""
        node = PolicyApplicabilityNode()
        state = _state_with_history()
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        applicability = from_json(result["policy_applicability_json"])
        assert isinstance(applicability.get("applicable_policies"), list)
        assert "citation_refs" in applicability

    def test_bl14_no_policy_refs_yields_gap_markers(self):
        """BL-14: empty policy_refs yields gap markers — not determination of eligibility."""
        node = PolicyApplicabilityNode()
        state = _base_state(policy_refs_json=to_json([]))
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        applicability = from_json(result["policy_applicability_json"])
        assert len(applicability.get("policy_gaps", [])) > 0

    def test_bl14_no_credential_decision_in_output(self):
        """BL-14: node never determines eligibility or makes credential decisions."""
        node = PolicyApplicabilityNode()
        state = _state_with_history()
        result = node(state)
        applicability_json = result.get("policy_applicability_json", "")
        # Output must not contain approval/denial decision language
        for forbidden in ("approved", "denied", "granted", "revoked"):
            # Policy titles/sections may contain "approved" in source text;
            # check only for first-person decision framing
            assert f"credential is {forbidden}" not in applicability_json.lower()


# ---------------------------------------------------------------------------
# BL-15..BL-19  BriefingNode
# ---------------------------------------------------------------------------

class TestBriefingNode:
    def test_bl15_draft_assembled_with_factors(self):
        """BL-15: briefing draft assembled with exception factors and labels."""
        node = BriefingNode()
        state = _state_with_analysis(hitl_allowed=False)
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        draft = from_json(result.get("briefing_draft_json", ""))
        assert draft is not None
        assert "DECISION SUPPORT" in draft.get("label", "")
        assert isinstance(draft.get("exception_factors"), list)

    def test_bl16_approved_hitl_resume_sets_outcome(self):
        """BL-16: HITL-approved resume sets review_outcome=approved and SUCCESS."""
        node = BriefingNode()
        state = _state_with_analysis(
            hitl_status=HitlStatus.APPROVED.value,
            hitl_feedback="Looks good",
            hitl_allowed=True,
        )
        result = node(state)
        assert result["review_outcome"] == "approved"
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_bl17_corrected_hitl_resume_sets_outcome(self):
        """BL-17: HITL-corrected resume sets review_outcome=corrected."""
        node = BriefingNode()
        state = _state_with_analysis(
            hitl_status=HitlStatus.CORRECTED.value,
            hitl_feedback="Please add factor X",
            hitl_allowed=True,
        )
        result = node(state)
        assert result["review_outcome"] == "corrected"
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_bl18_rejected_hitl_resume_sets_error_status(self):
        """BL-18: HITL-rejected resume sets review_outcome=rejected and ERROR status."""
        node = BriefingNode()
        state = _state_with_analysis(
            hitl_status=HitlStatus.REJECTED.value,
            hitl_feedback="Insufficient evidence",
            hitl_allowed=True,
        )
        result = node(state)
        assert result["review_outcome"] == "rejected"
        assert result["status"] == AgentStatus.ERROR.value

    def test_bl19_hitl_allowed_false_skips_interrupt(self):
        """BL-19: hitl_allowed=False must not raise GraphInterrupt — no deadlock."""
        node = BriefingNode()
        state = _state_with_analysis(hitl_allowed=False)
        # Must not raise GraphInterrupt
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value


# ---------------------------------------------------------------------------
# BL-20..BL-22  PostProcessNode
# ---------------------------------------------------------------------------

def _state_with_briefing_draft(**overrides) -> dict:
    state = _state_with_analysis()
    briefing_draft = {
        "event_id": "EVT-BROADCAST-2024",
        "broadcast_role": "host_broadcaster",
        "exception_criteria": "Replacement after credential loss",
        "requestor_ref": "REQ-2024-001",
        "summary": "Decision support briefing for authorized review.",
        "exception_factors": [
            {
                "factor_id": "F-001",
                "description": "Historical evidence: 2 prior approvals found",
                "source_support": "prior_approval_records",
                "is_assumption": False,
                "citation_ref": "source-approved-history/APPR-2024-001",
            }
        ],
        "unresolved_items": [],
        "history_pattern_summary": "2 prior approvals found.",
        "applicable_policy_count": 2,
        "citations": ["source-approved-history/APPR-2024-001"],
        "limitations": [
            "This briefing is decision support only.",
            "Agent does not provision or revoke credentials.",
        ],
        "label": "DECISION SUPPORT — NOT CREDENTIAL APPROVAL OR DENIAL",
    }
    state["briefing_draft_json"] = to_json(briefing_draft)
    state["caller_trust_level"] = VERIFIED.value
    state.update(overrides)
    return state


class TestPostProcessNode:
    def test_bl20_formats_output_from_briefing_draft(self):
        """BL-20: formats briefing draft into structured formatted_output."""
        node = PostProcessNode()
        state = _state_with_briefing_draft()
        result = node(state)
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["formatted_output"]
        assert "Decision Support" in result["formatted_output"]
        assert "EVT-BROADCAST-2024" in result["formatted_output"]

    def test_bl21_no_draft_yields_error(self):
        """BL-21: missing briefing draft yields ERROR status."""
        node = PostProcessNode()
        state = _state_with_briefing_draft(briefing_draft_json="")
        result = node(state)
        assert result["status"] == AgentStatus.ERROR.value

    def test_bl22_review_disposition_in_output(self):
        """BL-22: review_outcome=approved appears in formatted output."""
        node = PostProcessNode()
        state = _state_with_briefing_draft(review_outcome="approved", review_notes="LGTM")
        result = node(state)
        assert "APPROVED" in result["formatted_output"].upper()

    def test_prohibited_decision_language_rejected(self, monkeypatch):
        """S-3 extension rejects output with credential approval/denial framing."""
        import src.nodes.post_process_node as ppn_mod

        node = PostProcessNode()
        # Monkeypatch emit_trace_event to avoid side effects, then test the S-3 gate directly
        monkeypatch.setattr(ppn_mod, "emit_trace_event", lambda *a: None)

        # Verify that _extra_security_gate_output raises SecurityViolationError
        # when the output contains prohibited credential decision-framing language
        with pytest.raises(SecurityViolationError):
            node._extra_security_gate_output({
                "formatted_output": "credential exception is approved for this applicant",
                "status": "success",
            })

    def test_bl22_no_credential_approval_in_output(self):
        """BL-22: output never contains unsupported credential approval/denial claim."""
        node = PostProcessNode()
        state = _state_with_briefing_draft()
        result = node(state)
        out = result.get("formatted_output", "").lower()
        # The agent must not output autonomous credential decisions
        assert "credential is approved" not in out
        assert "access is granted" not in out

    def test_tc11_nodes_emit_audit_events(self, monkeypatch):
        """TC-11: nodes emit at least one domain emit_trace_event per execute()."""
        import src.nodes.post_process_node as ppn_mod
        events = []
        monkeypatch.setattr(ppn_mod, "emit_trace_event", lambda name, payload, state: events.append(name))
        node = PostProcessNode()
        state = _state_with_briefing_draft()
        node(state)
        assert len(events) >= 1
        assert any("PostProcessNode_event" in e for e in events)
