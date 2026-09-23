"""PB-3: External Service Boundary — controlled fake adapter mapping and provenance.

Verifies that the L1-to-service boundary via CredentialHistoryAdapter:
  - Returns only normalized records (no raw credential values)
  - Enforces source allowlisting (raises SourceNotAllowedError for unknown IDs)
  - Attaches citation_ref provenance to every record
  - Handles no-result and source-error paths safely
"""

from __future__ import annotations

import pytest

from src.schemas.state import from_json, to_json
from src.services.credential_history_adapter import (
    FakeCredentialHistoryAdapter,
    SourceNotAllowedError,
)


class TestPB3ExternalServiceBoundary:
    """PB-3: L1 boundary — fake adapter mapping, provenance, and allowlisting."""

    def test_pb3_prior_approvals_have_citation_provenance(self):
        """PB-3: every prior approval record contains a citation_ref."""
        adapter = FakeCredentialHistoryAdapter()
        records = adapter.fetch_prior_approvals(
            source_id="source-approved-history",
            event_id="EVT-BROADCAST-2024",
            broadcast_role="host_broadcaster",
        )
        assert len(records) > 0
        for rec in records:
            assert "citation_ref" in rec and rec["citation_ref"]
            assert "approval_id" in rec
            assert "source_id" in rec
            # Must not contain raw credential values
            for forbidden_key in ("password", "api_key", "secret", "token"):
                assert forbidden_key not in rec

    def test_pb3_policy_refs_have_citation_provenance(self):
        """PB-3: every policy reference record contains a citation_ref."""
        adapter = FakeCredentialHistoryAdapter()
        records = adapter.fetch_policy_refs(
            source_id="source-policy-store",
            event_id="EVT-BROADCAST-2024",
            broadcast_role="host_broadcaster",
        )
        assert len(records) > 0
        for rec in records:
            assert "citation_ref" in rec and rec["citation_ref"]
            assert "policy_id" in rec
            assert "source_id" in rec

    def test_pb3_source_allowlisting_enforced_for_approvals(self):
        """PB-3: SourceNotAllowedError raised for unknown source IDs (prior approvals)."""
        adapter = FakeCredentialHistoryAdapter()
        with pytest.raises(SourceNotAllowedError):
            adapter.fetch_prior_approvals(
                source_id="UNKNOWN-SOURCE-99",
                event_id="EVT-BROADCAST-2024",
                broadcast_role="host_broadcaster",
            )

    def test_pb3_source_allowlisting_enforced_for_policy_refs(self):
        """PB-3: SourceNotAllowedError raised for unknown source IDs (policy refs)."""
        adapter = FakeCredentialHistoryAdapter()
        with pytest.raises(SourceNotAllowedError):
            adapter.fetch_policy_refs(
                source_id="UNKNOWN-SOURCE-99",
                event_id="EVT-BROADCAST-2024",
                broadcast_role="host_broadcaster",
            )

    def test_pb3_no_result_path_returns_empty_list(self):
        """PB-3: source with no matching records returns empty list (no error)."""
        adapter = FakeCredentialHistoryAdapter()
        records = adapter.fetch_prior_approvals(
            source_id="source-approved-history",
            event_id="EVT-NONEXISTENT-9999",
            broadcast_role="host_broadcaster",
        )
        assert records == []

    def test_pb3_adapter_filters_by_broadcast_role(self):
        """PB-3: adapter filters records to matching broadcast_role."""
        adapter = FakeCredentialHistoryAdapter()
        records = adapter.fetch_prior_approvals(
            source_id="source-approved-history",
            event_id="EVT-BROADCAST-2024",
            broadcast_role="accredited_press",
        )
        for rec in records:
            assert rec.get("broadcast_role") == "accredited_press"

    def test_pb3_retrieval_node_normalizes_records(self):
        """PB-3: RetrievalNode maps provider records to normalized JSON state fields."""
        from src.nodes.retrieval_node import RetrievalNode
        from framework.schemas.trust_level import TrustLevel

        node = RetrievalNode(adapter=FakeCredentialHistoryAdapter())
        state = {
            "caller_trust_level": TrustLevel.ANONYMOUS.value,
            "session_id": "pb3-session",
            "correlation_id": "pb3-correlation",
            "thread_id": "pb3-thread",
            "trace_id": "pb3-trace",
            "node_history": [],
            "error_log": [],
            "hitl_allowed": False,
            "hitl_count": 0,
            "exception_scope_json": to_json({
                "event_id": "EVT-BROADCAST-2024",
                "broadcast_role": "host_broadcaster",
                "exception_criteria": "test",
                "date_window_start": "",
                "date_window_end": "",
                "requestor_ref": "",
                "operator_id": "",
            }),
            "approved_source_ids_json": to_json(["source-approved-history", "source-policy-store"]),
        }
        result = node(state)
        from framework.schemas.agent_status import AgentStatus
        assert result["status"] == AgentStatus.SUCCESS.value

        # Records are stored as JSON strings (msgpack-safe)
        assert isinstance(result["prior_approvals_json"], str)
        assert isinstance(result["policy_refs_json"], str)

        # Deserialized records are lists
        approvals = from_json(result["prior_approvals_json"])
        policy_refs = from_json(result["policy_refs_json"])
        assert isinstance(approvals, list)
        assert isinstance(policy_refs, list)
