"""Shared pytest fixtures for SVC-C2-070.

Tests exercise the installed AgentCore framework rather than replacing its
security and lifecycle boundaries with local stubs.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def mock_secrets():
    """Bind the deterministic credential used by the retrieval node."""
    from framework.secrets.context import bound_secrets
    from shared.secrets.inmemory_provider import InMemoryProvider

    provider = InMemoryProvider({"CREDENTIAL_HISTORY_TOKEN": "mock-history-token"})
    with bound_secrets(provider):
        yield provider
