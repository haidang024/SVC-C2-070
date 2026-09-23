"""PolicyApplicabilityNode — event-access policy applicability mapping for SVC-C2-070."""

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event
from src.schemas.state import from_json, to_json


class PolicyApplicabilityNode(FunctionNode):
    """Map request facts to applicable event-access policy references, requirements, and prohibitions.

    Inner node — ANONYMOUS. Presents referenced policy evidence only.
    Never determines eligibility, approves or denies credentials, or changes
    any access-control setting. Explicitly marks policy gaps.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: dict) -> dict:
        policy_refs = from_json(state.get("policy_refs_json"), default=[])
        exception_scope = from_json(state.get("exception_scope_json"), default={})

        broadcast_role = (exception_scope or {}).get("broadcast_role", "")
        exception_criteria = (exception_scope or {}).get("exception_criteria", "")

        if not policy_refs:
            emit_trace_event(
                "PolicyApplicabilityNode_event",
                {"result": "no_policy_refs"},
                state,
            )
            no_policy_applicability = {
                "applicable_policies": [],
                "requirements": [],
                "prohibitions": [],
                "exceptions": [],
                "policy_gaps": [
                    "No policy references retrieved from approved sources. "
                    "Policy applicability cannot be assessed without source data."
                ],
                "citation_refs": [],
            }
            return {
                "policy_applicability_json": to_json(no_policy_applicability),
                "status": AgentStatus.SUCCESS.value,
            }

        # Organize policy refs into categories
        applicable_policies: list[dict] = []
        requirements: list[str] = []
        prohibitions: list[str] = []
        exceptions_found: list[str] = []
        citation_refs: list[str] = []
        policy_gaps: list[str] = []

        for ref in policy_refs:
            policy_id = ref.get("policy_id", "")
            policy_title = ref.get("policy_title", "")
            section = ref.get("section", "")
            citation_ref = ref.get("citation_ref", "")
            applicability_scope = ref.get("applicability_scope", [])

            # Check if this policy applies to the broadcast role
            applies = "all" in applicability_scope or broadcast_role in applicability_scope

            applicable_policies.append(
                {
                    "policy_id": policy_id,
                    "policy_title": policy_title,
                    "section": section,
                    "applies_to_role": applies,
                    "applicability_scope": applicability_scope,
                    "citation_ref": citation_ref,
                }
            )

            if citation_ref and citation_ref not in citation_refs:
                citation_refs.append(citation_ref)

            if applies:
                # Classify by section name patterns (reference text only)
                section_lower = section.lower()
                if "requirement" in section_lower or "criteria" in section_lower:
                    requirements.append(f"{policy_title} {section} [{citation_ref}]")
                elif "prohibited" in section_lower or "restriction" in section_lower:
                    prohibitions.append(f"{policy_title} {section} [{citation_ref}]")
                elif "exception" in section_lower:
                    exceptions_found.append(f"{policy_title} {section} [{citation_ref}]")

        # Identify gaps
        if not requirements and not prohibitions and not exceptions_found:
            policy_gaps.append(
                f"No policy sections directly addressing broadcast_role='{broadcast_role}' "
                f"and exception_criteria='{exception_criteria}' were found in retrieved sources."
            )

        applicability: dict[str, Any] = {
            "applicable_policies": applicable_policies,
            "requirements": requirements,
            "prohibitions": prohibitions,
            "exceptions": exceptions_found,
            "policy_gaps": policy_gaps,
            "citation_refs": citation_refs,
        }

        emit_trace_event(
            "PolicyApplicabilityNode_event",
            {
                "result": "mapped",
                "policy_count": len(applicable_policies),
                "requirement_count": len(requirements),
                "prohibition_count": len(prohibitions),
                "gap_count": len(policy_gaps),
            },
            state,
        )

        return {
            "policy_applicability_json": to_json(applicability),
            "status": AgentStatus.SUCCESS.value,
        }
