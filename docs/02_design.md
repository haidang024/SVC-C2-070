# Template Design Specification

## Position in AgentCore Architecture

- **Agent Class**: `Graph` (inherits `AgentBaseGraph` — L1 direct)
- **Template ID**: SVC-C2-070
- **Category**: Cat 2 — Fixed Multi-Step Workflow
- **L1 Base**: AgentBaseGraph (outer) + BaseGraph (inner)
- **Three-Layer Separation**:
  - State: flat TypedDict with JSON-encoded structured fields (no Pydantic — msgpack incompatible)
  - Node: L1 inheritance (Template Method: `execute(self, state: dict) -> dict` override only)
  - Graph: composition (`register_nodes()` for node substitution; `DomainWorkflowGraph` inner topology)

## Architecture Overview

### Node Configuration

| Node | Slot | Class | Trust Level | Responsibility |
|------|------|-------|-------------|----------------|
| initialize | outer:initialize | InitializeNode (default) | — | Framework-injected init |
| pre_process | outer:pre_process | `PreProcessNode` | VERIFIED_EXTERNAL | Exception-request scope validation, broadcast_role check, approved_source_ids normalization |
| main | outer:main | `CredentialExceptionGraphNode` (GraphNode) | — | Inner graph delegation |
| retrieval | inner:retrieval | `RetrievalNode` | ANONYMOUS | Approved credential history and policy retrieval via allowlisted sources |
| history_analysis | inner:history_analysis | `HistoryAnalysisNode` | ANONYMOUS | Prior approval pattern analysis with evidence and uncertainty markers |
| policy_applicability | inner:policy_applicability | `PolicyApplicabilityNode` | ANONYMOUS | Event-access policy mapping — requirements, prohibitions, exceptions, gaps |
| briefing | inner:briefing | `BriefingNode` | ANONYMOUS | Exception factor synthesis, briefing assembly, HITL interrupt for authorized review |
| post_process | outer:post_process | `PostProcessNode` | VERIFIED_EXTERNAL | Final briefing formatting with citations, review disposition, limitations; S-3 gate rejects decision-framing language |
| finalize | outer:finalize | FinalizeNode (default) | — | Framework-injected finalize |

### Data Flow

```
START
  → initialize                    (framework default)
  → pre_process                   (outer: VERIFIED_EXTERNAL)
      validate JSON, broadcast_role, approved_source_ids
      → exception_scope_json, approved_source_ids_json
  → main (CredentialExceptionGraphNode)
      → [inner DomainWorkflowGraph]
          → retrieval              (ANONYMOUS)
              fetch_prior_approvals + fetch_policy_refs from each approved source
              → prior_approvals_json, policy_refs_json
          → history_analysis       (ANONYMOUS)
              analyze patterns, constraints, uncertainty markers
              → approval_history_analysis_json
          → policy_applicability   (ANONYMOUS)
              map to requirements, prohibitions, exceptions, gaps
              → policy_applicability_json
          → briefing               (ANONYMOUS)
              synthesize exception_factors, assemble briefing_draft
              → HITL interrupt (if hitl_allowed=True)
              → resume: approved / corrected / rejected
              → briefing_draft_json, exception_factors_json, review_outcome
  → post_process                  (outer: VERIFIED_EXTERNAL)
      format final briefing with citations, limitations
      S-3 gate: reject credential-decision framing
      → formatted_output, result
  → finalize                      (framework default)
  → END
```

**HITL routing (AgentBaseGraph standard):**
- `APPROVED` → post_process
- `CORRECTED` → post_process (with feedback)
- `REJECTED` → finalize (error path)

### State Definition

| Field | Type | Producer | Purpose |
|-------|------|----------|---------|
| `exception_scope_json` | str (JSON) | pre_process_node | Event ID, broadcast role, exception criteria, date window, requestor ref |
| `approved_source_ids_json` | str (JSON) | pre_process_node | Operator-configured approved source identifiers |
| `validated_input` | str | pre_process_node | Normalized JSON input string |
| `prior_approvals_json` | str (JSON) | retrieval_node | Normalized prior approval records with citation provenance |
| `policy_refs_json` | str (JSON) | retrieval_node | Applicable event-access policy references with citation provenance |
| `approval_history_analysis_json` | str (JSON) | history_analysis_node | Pattern summary, relevant approvals, constraints, uncertainty markers |
| `policy_applicability_json` | str (JSON) | policy_applicability_node | Applicable policies, requirements, prohibitions, exceptions, gaps |
| `exception_factors_json` | str (JSON) | briefing_node | Source-supported exception factors with provenance |
| `briefing_draft_json` | str (JSON) | briefing_node | Full briefing draft for HITL review |
| `review_outcome` | str | briefing_node | "approved" / "corrected" / "rejected" / "" |
| `review_notes` | str | briefing_node | Operator review notes (no applicant PII) |
| `formatted_output` | str | post_process_node | Final formatted briefing text |
| `result` | str (JSON) | post_process_node | Structured briefing dict for API consumers |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types via `to_json()`/`from_json()`)
- No JWT, API keys, raw credentials in State (checkpoint DB leakage)
- InvocationContext via `InvocationContext.from_state(state)` only
- No Pydantic models, dataclass, arbitrary Python objects (msgpack incompatible)
- Structured fields encoded as `str` (JSON) — never `dict` or `list` field annotations

## Framework Utilization

### Shared Components Used

- [x] `InvocationContext.from_state(state)` — extracts correlation_id, session_id, secrets handle
- [x] `ctx.secrets.require("CREDENTIAL_HISTORY_TOKEN")` — service auth token (never os.environ in nodes)
- [x] `SecurityViolationError` — raised by S-2 extension in PreProcessNode; S-3 extension in PostProcessNode
- [x] S-2: `_extra_security_gate_input()` in PreProcessNode — input size limit, JSON structure check
- [x] S-3: `_extra_security_gate_output()` in PostProcessNode — rejects credential-decision framing language
- [x] S-4: `emit_trace_event()` — at least one domain event per `execute()` in every node
- [x] HITL: `interrupt()` in BriefingNode, guarded by `state.get("hitl_allowed", True)` (D6 pattern)
- [x] `HitlStatus.APPROVED / CORRECTED / REJECTED` — resume routing in BriefingNode

### Security Model

| Layer | Enforcement | Node Implementation |
|-------|-------------|---------------------|
| S-1 Trust Gate | `BaseNode.__call__()` automatic | `required_trust_level=VERIFIED_EXTERNAL` on outer nodes; `ANONYMOUS` on inner nodes |
| S-2 Input Gate | `FunctionNode._security_gate_input()` @final | Extended via `_extra_security_gate_input()` in PreProcessNode |
| S-3 Output Gate | `FunctionNode._security_gate_output()` @final | Extended via `_extra_security_gate_output()` in PostProcessNode |
| S-4 Audit | `__call__()` lifecycle events | `emit_trace_event("*Node_event", payload, state)` in every `execute()` |
| S-5 Credential Scan | `gate-credential-scan` CI | No credentials in `src/`; labelled mocks in tests |

**Trust level assignment:**
- Outer nodes (pre_process, post_process): `VERIFIED_EXTERNAL` — API-facing, access-sensitive operations
- Inner nodes (retrieval, history_analysis, policy_applicability, briefing): `ANONYMOUS` — trust inherited from outer graph context (trust-trap anti-pattern if raised to VERIFIED_EXTERNAL)

### Composition Pattern

- **Pattern**: Cat 2 — outer `AgentBaseGraph` + inner `BaseGraph` via `GraphNode` (`CredentialExceptionGraphNode`)
- **Inner graph**: `DomainWorkflowGraph` — linear topology, 4 ANONYMOUS nodes
- **Runtime injection**: the outer graph constructs `CredentialExceptionGraphNode(config=self.config, llm=self.config.get("llm"))`; the wrapper forwards the complete runtime config to the inner graph
- **propagate_hitl**: `True` — BriefingNode's HITL interrupt surfaces to outer caller for authorized review
- **Error propagation strategy**: `propagate` — inner errors raised as SubgraphError

## EU AI Act Art.13 Design-Time Evidence

The proposal declares this template outside Annex III scope. The following
transparency controls are nevertheless part of the design:

| Evidence item | Design reference / description |
|---------------|--------------------------------|
| Intended purpose and operating context | Authorized event operators use the agent to prepare a source-evidenced broadcast credential-exception briefing. |
| System capabilities and limitations | It retrieves only allowlisted normalized records and produces decision support; it cannot approve, deny, provision, revoke, or notify. |
| User-facing transparency information | Every briefing is labeled “DECISION SUPPORT — NOT CREDENTIAL APPROVAL OR DENIAL” and includes citations, unresolved items, and limitations. |
| Human oversight mechanism | `BriefingNode` interrupts before final formatting when `hitl_allowed=true`; an authorized reviewer approves, corrects, or rejects the draft. |

## Import Isolation Confirmation

- [x] Template does not import agenticstar-platform SDK (Level 0)
- [x] Import targets: `framework.*`, `shared.*`, own `src.*`, `langgraph.*` only
- [x] No imports from `mediator/`, other agents' `src.*`, or `agenticstar`

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | `AgentBaseGraph` | `AutonomousBaseGraph` | `AgentBaseGraph` | Fixed deterministic workflow; no LLM reasoning loop needed for this use case |
| Inner topology | `BaseGraph` (custom) | `AgentBaseGraph` (standard) | `BaseGraph` | Domain nodes have custom names (retrieval, history_analysis, policy_applicability, briefing) — not pre_process/main/post_process slots |
| HITL placement | PostProcessNode | BriefingNode (inner) | BriefingNode | Review must occur on assembled briefing draft before output formatting; propagate_hitl=True surfaces interrupt to outer caller |
| Source retrieval | Single source | Multi-source allowlist | Multi-source allowlist | Operators configure multiple approved history and policy sources; allowlist enforced in adapter layer |
| Credential data minimization | Full record pass-through | Normalized records only | Normalized records only | Raw credential values must never enter state; citation_ref provenance preserved for traceability |
