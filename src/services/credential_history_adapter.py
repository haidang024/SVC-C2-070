"""CredentialHistoryAdapter — approved source retrieval adapter for SVC-C2-070."""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Protocol — adapter interface
# ---------------------------------------------------------------------------


class CredentialHistoryAdapter:
    """Abstract interface for approved credential history and policy sources.

    Concrete implementations (real or fake) must implement:
      - fetch_prior_approvals(source_id, event_id, broadcast_role, date_window)
      - fetch_policy_refs(source_id, event_id, broadcast_role)

    All returned data must be normalized — no raw credential values
    are passed through. Provider transport logic stays here; nodes only
    see sanitized, JSON-serializable records with citation provenance.
    """

    def fetch_prior_approvals(
        self,
        source_id: str,
        event_id: str,
        broadcast_role: str,
        date_window_start: str = "",
        date_window_end: str = "",
    ) -> list[dict[str, Any]]:
        """Return normalized prior approval records for the given scope.

        Each record: {approval_id, event_id, broadcast_role, approved_date,
                      constraints, citation_ref, source_id}
        Raises SourceNotAllowedError if source_id is not in the allowlist.
        """
        raise NotImplementedError

    def fetch_policy_refs(
        self,
        source_id: str,
        event_id: str,
        broadcast_role: str,
    ) -> list[dict[str, Any]]:
        """Return applicable event-access policy references for the given scope.

        Each record: {policy_id, policy_title, section, applicability_scope,
                      citation_ref, source_id}
        Raises SourceNotAllowedError if source_id is not in the allowlist.
        """
        raise NotImplementedError


class SourceNotAllowedError(Exception):
    """Raised when a requested source_id is not in the operator allowlist."""


# ---------------------------------------------------------------------------
# Fake adapter — deterministic, no external dependencies
# ---------------------------------------------------------------------------

_FAKE_PRIOR_APPROVALS: dict[str, list[dict[str, Any]]] = {
    "source-approved-history": [
        {
            "approval_id": "APPR-2024-001",
            "event_id": "EVT-BROADCAST-2024",
            "broadcast_role": "host_broadcaster",
            "approved_date": "2024-03-15",
            "constraints": "Standard broadcast window; no archive rights",
            "citation_ref": "source-approved-history/APPR-2024-001",
            "source_id": "source-approved-history",
        },
        {
            "approval_id": "APPR-2024-002",
            "event_id": "EVT-BROADCAST-2024",
            "broadcast_role": "accredited_press",
            "approved_date": "2024-03-20",
            "constraints": "Press credential limited to assigned zones",
            "citation_ref": "source-approved-history/APPR-2024-002",
            "source_id": "source-approved-history",
        },
    ],
    "source-policy-store": [],
}

_FAKE_POLICY_REFS: dict[str, list[dict[str, Any]]] = {
    "source-policy-store": [
        {
            "policy_id": "POL-ACCESS-001",
            "policy_title": "Event Broadcast Access Policy",
            "section": "§3.2 Credential Exception Criteria",
            "applicability_scope": ["host_broadcaster", "accredited_press", "rights_holder"],
            "citation_ref": "source-policy-store/POL-ACCESS-001/§3.2",
            "source_id": "source-policy-store",
        },
        {
            "policy_id": "POL-ACCESS-002",
            "policy_title": "Event Broadcast Access Policy",
            "section": "§4.1 Prohibited Configurations",
            "applicability_scope": ["all"],
            "citation_ref": "source-policy-store/POL-ACCESS-002/§4.1",
            "source_id": "source-policy-store",
        },
    ],
    "source-approved-history": [],
}

_ALLOWED_SOURCES = frozenset(_FAKE_PRIOR_APPROVALS.keys())


class FakeCredentialHistoryAdapter(CredentialHistoryAdapter):
    """Deterministic in-memory adapter for testing and local execution.

    Returns predefined fixture records mapped by source_id.
    Enforces source allowlisting — raises SourceNotAllowedError for unknown sources.
    """

    def fetch_prior_approvals(
        self,
        source_id: str,
        event_id: str,
        broadcast_role: str,
        date_window_start: str = "",
        date_window_end: str = "",
    ) -> list[dict[str, Any]]:
        if source_id not in _ALLOWED_SOURCES:
            raise SourceNotAllowedError(f"Source '{source_id}' is not in the approved source allowlist")
        records = _FAKE_PRIOR_APPROVALS.get(source_id, [])
        # Filter by event_id and broadcast_role
        return [
            r
            for r in records
            if (not event_id or r.get("event_id") == event_id)
            and (not broadcast_role or r.get("broadcast_role") == broadcast_role)
        ]

    def fetch_policy_refs(
        self,
        source_id: str,
        event_id: str,
        broadcast_role: str,
    ) -> list[dict[str, Any]]:
        if source_id not in _ALLOWED_SOURCES:
            raise SourceNotAllowedError(f"Source '{source_id}' is not in the approved source allowlist")
        records = _FAKE_POLICY_REFS.get(source_id, [])
        # Filter by applicability_scope
        return [
            r
            for r in records
            if "all" in r.get("applicability_scope", []) or broadcast_role in r.get("applicability_scope", [])
        ]
