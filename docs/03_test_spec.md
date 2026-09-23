# Test Specification — SVC-C2-070 Live Event Broadcast Credential Exception Agent

## Test Strategy
- Coverage target: ≥80% (not measured in the verification run recorded below)
- Test types: Unit / Integration / Proof-of-Boundary
- All invocations use `node(state)` — never `node.execute(state)` — so the full lifecycle
  (S-1 trust gate, S-4 audit events, S-2/S-3 security gates) runs on every call in tests
  as it does at runtime
- No live credentials, access-control systems, or production secrets used in tests
- FakeCredentialHistoryAdapter provides deterministic test doubles

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result | Result |
|-------|------|----------------|--------|
| TC-01 | State `to_json`/`from_json` roundtrip | Serialization preserves structure; empty → default | PASS |
| TC-02 | S-2 rejects invalid input (oversized, non-JSON) | BaseNode returns an error result after the domain gate rejects input | PASS |
| TC-03 | No JWT/Credential in State | CI `gate-credential-scan`: 0 violations. This check runs as a CI job rather than as a runtime assertion inside the framework | PASS |
| TC-04 | InvocationContext via `from_state()` only | Direct `InvocationContext(...)` construction not used in nodes | PASS |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | `node_start` / `node_complete` / `node_error` absent from `execute()` body | PASS |
| TC-06 | S-2: `_security_gate_input()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | PASS |
| TC-07 | S-3: `_security_gate_output()` not overridden (`FunctionNode` subclass) | `TypeError` raised at class definition if overridden (`@final` enforced by framework) | PASS |
| TC-08 | `required_trust_level` enforced — insufficient trust rejected | ANONYMOUS caller refused before `execute()` and an error result returned | PASS |
| TC-09 | S-2: `_extra_security_gate_input()` non-trivial in PreProcessNode | Input size limit and JSON structure check executed; SecurityViolationError raised | PASS |
| TC-10 | S-3: `_extra_security_gate_output()` non-trivial in PostProcessNode | Credential decision-framing pattern scan executed; SecurityViolationError raised | PASS |
| TC-11 | S-4: at least one domain `emit_trace_event()` inside each `execute()` | Domain event emitted on every invocation path | PASS |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result | Result |
|-------|----------|------|----------------|--------|
| PB-1 | BaseNode → EventEmitter | `emit_trace_event()` fires on every invocation path (TC-11) | ≥1 domain event per node per execute() | PASS |
| PB-2 | State serialization | Post-invoke State is primitives + JSON-encoded strings only | No Pydantic/dataclass; `to_json`/`from_json` round-trips | PASS |
| PB-3 | L1 → External service | FakeCredentialHistoryAdapter maps and returns provenance-tagged records; SourceNotAllowedError on unknown source | Normalization and citation_ref verified; allowlist enforced | PASS |
| PB-4 | Import isolation | No Level 0 (`agenticstar`) imports in `src/` | AST scan: 0 violations | PASS |
| PB-5 | Checkpoint safety | Static state scan plus conditional full checkpoint-surface test | No unsafe state fields; full-surface test auto-waived when installed framework lacks ingress hooks | PASS / AUTO-WAIVED |
| PB-6 | Invoke execution order | `__call__()`: S-1 → node_start(S-4) → S-2 → execute() → S-3 → node_complete(S-4) | Order verified for all nodes; negative S-1 test: ANONYMOUS blocked by PreProcessNode | PASS |
| PB-7 | HITL interrupt propagation | `interrupt()` raises GraphInterrupt and propagates; `hitl_allowed=False` prevents deadlock | GraphInterrupt propagates; `hitl_allowed=False` returns normally without error | PASS (active when hitl.enabled: true) |

## Business Logic Tests

| TC-ID | Test | Input | Expected Result | Result |
|-------|------|-------|----------------|--------|
| BL-01 | PreProcessNode — valid JSON scope input | JSON with event_id, broadcast_role, exception_criteria, approved_source_ids | `status=success`; `exception_scope_json` and `approved_source_ids_json` populated | PASS |
| BL-02 | PreProcessNode — empty user_input rejected | "" | `status=error` | PASS |
| BL-03 | PreProcessNode — invalid JSON rejected | "{not-json}" | `status=error` | PASS |
| BL-04 | PreProcessNode — missing required fields | JSON without event_id | `status=error`; field names in error_log | PASS |
| BL-05 | PreProcessNode — unsupported broadcast_role | JSON with broadcast_role="INVALID_ROLE" | `status=error` | PASS |
| BL-06 | PreProcessNode — empty approved_source_ids | JSON with approved_source_ids=[] | `status=error` | PASS |
| BL-07 | RetrievalNode — approved sources retrieved | State with valid scope and approved_source_ids | `status=success`; records with citation_ref | PASS |
| BL-08 | RetrievalNode — no scope fields | Empty exception_scope_json | `status=success`; empty lists | PASS |
| BL-09 | RetrievalNode — unknown source ID | Source ID not in allowlist | Partial success; error_log populated | PASS |
| BL-10 | HistoryAnalysisNode — prior approvals analyzed | Populated prior_approvals_json | `status=success`; pattern_summary, evidence_count, citation_refs | PASS |
| BL-11 | HistoryAnalysisNode — no prior approvals | Empty prior_approvals_json | `status=success`; evidence_count=0; uncertainty_markers populated | PASS |
| BL-12 | HistoryAnalysisNode — unmatched broadcast_role | Records for different role | `status=success`; uncertainty_markers indicate insufficient evidence | PASS |
| BL-13 | PolicyApplicabilityNode — policy refs mapped | Populated policy_refs_json | `status=success`; applicable_policies; citation_refs | PASS |
| BL-14 | PolicyApplicabilityNode — no policy refs | Empty policy_refs_json | `status=success`; policy_gaps populated; no eligibility determination | PASS |
| BL-15 | BriefingNode — draft assembled | State with history and policy analysis | `status=success`; briefing_draft_json with DECISION SUPPORT label; exception_factors list | PASS |
| BL-16 | BriefingNode — approved HITL resume | hitl_status=APPROVED | review_outcome="approved"; status=success | PASS |
| BL-17 | BriefingNode — corrected HITL resume | hitl_status=CORRECTED | review_outcome="corrected"; status=success | PASS |
| BL-18 | BriefingNode — rejected HITL resume | hitl_status=REJECTED | review_outcome="rejected"; status=error | PASS |
| BL-19 | BriefingNode — hitl_allowed=False skips interrupt | hitl_allowed=False | No GraphInterrupt; returns normally | PASS |
| BL-20 | PostProcessNode — formats output from briefing draft | Populated briefing_draft_json | status=success; formatted_output with event_id and "Decision Support" label | PASS |
| BL-21 | PostProcessNode — no draft yields error | Empty briefing_draft_json | status=error | PASS |
| BL-22 | PostProcessNode — review disposition in output | review_outcome="approved" | "APPROVED" appears in formatted_output | PASS |

## Test Execution Summary
- Execution date: 2026-08-18
- Total tests: 51
- Pass: 50 / Fail: 0 / Skip: 1
- Skipped: PB-5 full checkpoint-surface assertion (installed AgentCore lacks both ingress-protection hooks)
- Coverage: Not measured in this run
- Command: `python -m pytest tests -q --tb=short`
