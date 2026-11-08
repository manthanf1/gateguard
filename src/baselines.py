"""
Baseline Implementations for Multi-Agent Security Comparison:
1. Baseline A: Prompt-Only In-Context Guardrails (System Prompt instructions)
2. Baseline B: In-Protocol Schema Validation (Standard unauthenticated A2A / MCP)
"""

import random
from typing import Dict, Any, List, Set, Tuple

class PromptGuardrailBaseline:
    """
    Models standard LLM swarm enforcement where security boundaries are set
    solely via natural language system prompts and role descriptions.
    Under adversarial attacks (jailbreaks, deceptive alignment, prompt injection),
    agents exhibit probabilistic compliance failure.
    """
    def __init__(self, adversarial_jailbreak_prob: float = 0.72):
        self.adversarial_jailbreak_prob = adversarial_jailbreak_prob
        self.local_transcripts: Dict[str, List[Dict[str, Any]]] = {}

    def delegate_subtask(
        self,
        parent_id: str,
        parent_tools: Set[str],
        child_id: str,
        requested_tools: Set[str],
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # If adversarial, the agent attempts prompt injection to override parent tools
        if is_adversarial and random.random() < self.adversarial_jailbreak_prob:
            # Downward laundering succeeds: child gets extra tools
            return True, "Delegation succeeded via adversarial jailbreak override"
        # Otherwise checks honest subset
        if not requested_tools.issubset(parent_tools):
            return False, "Prompt guardrail blocked unauthorized tool delegation"
        return True, "Delegation permitted"

    def invoke_tool(
        self,
        claimed_id: str,
        actual_id: str,
        tool: str,
        allowed_tools: Set[str],
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # Identity spoofing attack
        if claimed_id != actual_id:
            if is_adversarial and random.random() < self.adversarial_jailbreak_prob:
                return True, f"Identity spoofing accepted: impersonated {claimed_id}"
            return False, "Identity mismatch caught by prompt check"

        # Tool scope attack
        if tool not in allowed_tools:
            if is_adversarial and random.random() < self.adversarial_jailbreak_prob:
                return True, f"Scope check bypassed: unauthorized tool {tool} executed"
            return False, "Tool not in permitted list"

        return True, "Tool executed normally"

    def verify_result(
        self,
        child_id: str,
        claimed_executions: List[str],
        actual_executions: List[str],
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # Phantom execution / result forgery check: relying on agent self-reporting
        if claimed_executions != actual_executions:
            # In prompt-based setups, parent models easily accept fabricated tool outputs
            if is_adversarial and random.random() < (self.adversarial_jailbreak_prob + 0.15):
                return True, "Parent accepted fabricated tool output (phantom execution accepted)"
            return False, "Parent model rejected ungrounded output"
        return True, "Result accepted"


class InProtocolSchemaBaseline:
    """
    Models standard agent protocols (e.g. raw A2A, basic MCP) where tool schemas
    and JSON payloads specify agent_id and tool names, but lack cryptographic
    lineage binding and out-of-band execution verification.
    """
    def __init__(self):
        self.registered_sessions: Dict[str, Set[str]] = {}

    def register_agent(self, agent_id: str, tools: Set[str]):
        self.registered_sessions[agent_id] = set(tools)

    def delegate_subtask(
        self,
        parent_id: str,
        child_id: str,
        requested_tools: Set[str],
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # In-protocol: Schema validates JSON types, but lacks lineage chaining.
        # An adversary can forge a self-issued session for child with arbitrary tools.
        if is_adversarial:
            self.registered_sessions[child_id] = set(requested_tools)
            return True, "Child registered with forged capabilities (schema lacks lineage check)"
        
        parent_tools = self.registered_sessions.get(parent_id, set())
        if not requested_tools.issubset(parent_tools):
            return False, "Schema validation: requested tools exceed parent record"
        self.registered_sessions[child_id] = set(requested_tools)
        return True, "Delegation approved"

    def invoke_tool(
        self,
        claimed_id: str,
        tool: str,
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # Sybil/Aliasing: If adversarial, agent switches claimed_id in JSON header
        tools = self.registered_sessions.get(claimed_id, set())
        if tool not in tools:
            return False, "Tool not in registered session scope"
        return True, "Tool executed via registered session"

    def verify_result(
        self,
        child_id: str,
        claimed_executions: List[str],
        actual_gateway_executions: List[str],
        is_adversarial: bool = False
    ) -> Tuple[bool, str]:
        # In-protocol: Has no gateway-side ledger; accepts child's JSON transcript payload
        if is_adversarial and set(claimed_executions) - set(actual_gateway_executions):
            # Adversary forged tool outputs; schema has no cryptographic inclusion proof
            return True, "In-protocol accepted self-reported execution transcript (phantom execution)"
        return True, "Transcript accepted"
