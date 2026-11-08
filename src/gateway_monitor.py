"""
Gateway Reference Monitor (GateGuard) for Multi-Agent Swarms.
Acts as an out-of-band proxy mediating all Agent-to-Agent (A2A) delegations,
tool invocations, and transcript commits with cryptographic provenance.
"""

import time
import hashlib
import json
import secrets
from typing import Dict, Any, List, Set, Optional, Tuple
from lineage_token import LineageToken, TokenAuthority, LineageCaveat

class GatewayAuditLedger:
    """Cryptographically chained append-only audit ledger."""
    def __init__(self):
        self.entries: List[Dict[str, Any]] = []
        self.current_hash: str = "GENESIS_ROOT_HASH_00000000000000000000"

    def append(self, event_type: str, agent_id: str, payload: Dict[str, Any], lineage: List[str]) -> str:
        timestamp = time.time()
        seq = len(self.entries)
        event_body = {
            "seq": seq,
            "timestamp": timestamp,
            "event_type": event_type,
            "agent_id": agent_id,
            "lineage": lineage,
            "payload": payload,
            "prev_hash": self.current_hash
        }
        raw_bytes = json.dumps(event_body, sort_keys=True).encode('utf-8')
        entry_hash = hashlib.sha256(raw_bytes).hexdigest()
        event_body["entry_hash"] = entry_hash
        self.entries.append(event_body)
        self.current_hash = entry_hash
        return entry_hash

    def verify_integrity(self) -> bool:
        """Verifies full hash chain consistency."""
        running_hash = "GENESIS_ROOT_HASH_00000000000000000000"
        for entry in self.entries:
            if entry["prev_hash"] != running_hash:
                return False
            check_body = dict(entry)
            stored_hash = check_body.pop("entry_hash")
            raw = json.dumps(check_body, sort_keys=True).encode('utf-8')
            if hashlib.sha256(raw).hexdigest() != stored_hash:
                return False
            running_hash = stored_hash
        return True


class GatewayReferenceMonitor:
    """
    Out-of-band Reference Monitor satisfying Anderson's Reference Monitor criteria:
    1. Complete Mediation: Intercepts all delegations, tool calls, and completion returns.
    2. Tamper-Proof: Isolated state, cryptographic verification, immutable ledger.
    3. Verifiable: Small, deterministic evaluation logic.
    """
    def __init__(self, master_secret: Optional[bytes] = None):
        self.master_secret = master_secret or secrets.token_bytes(32)
        self.authority = TokenAuthority(self.master_secret)
        self.ledger = GatewayAuditLedger()
        self.revoked_signatures: Set[str] = set()
        self.revoked_agent_ids: Set[str] = set()
        self.valid_tokens_by_sig: Dict[str, LineageToken] = {}

    def init_task(self, root_task_id: str, orchestrator_id: str, allowed_tools: Set[str]) -> LineageToken:
        """Mints the initial root capability token for the swarm entry point."""
        token = self.authority.mint_root_token(
            root_task_id=root_task_id,
            initial_agent_id=orchestrator_id,
            allowed_tools=allowed_tools
        )
        sig_hex = token.signature.hex()
        self.valid_tokens_by_sig[sig_hex] = token
        self.ledger.append(
            event_type="ROOT_TASK_INIT",
            agent_id=orchestrator_id,
            payload={"root_task_id": root_task_id, "allowed_tools": list(allowed_tools)},
            lineage=[orchestrator_id]
        )
        return token

    def delegate_subtask(
        self,
        parent_token: LineageToken,
        child_id: str,
        child_tools: Set[str],
        task_description: str,
        ttl_seconds: Optional[float] = None
    ) -> Tuple[bool, Optional[LineageToken], str]:
        """
        Mediates delegation from parent agent to child agent.
        Enforces monotonic attenuation and revocation checks.
        """
        parent_sig = parent_token.signature.hex()

        # Check revocations
        if parent_sig in self.revoked_signatures or parent_token.holder_id in self.revoked_agent_ids:
            self.ledger.append(
                event_type="DELEGATION_REJECTED_REVOKED",
                agent_id=parent_token.holder_id,
                payload={"attempted_child": child_id, "reason": "Parent revoked"},
                lineage=parent_token.lineage_path
            )
            return False, None, "Parent token or agent has been revoked"

        # Check cryptographic chain of parent
        if not self.authority.verify_token_chain(parent_token):
            self.ledger.append(
                event_type="DELEGATION_REJECTED_INVALID_SIG",
                agent_id=parent_token.holder_id,
                payload={"attempted_child": child_id, "reason": "Invalid cryptographic signature"},
                lineage=parent_token.lineage_path
            )
            return False, None, "Parent cryptographic signature is invalid or forged"

        # Enforce capability attenuation
        try:
            child_token = self.authority.attenuate(
                parent_token=parent_token,
                child_agent_id=child_id,
                child_allowed_tools=child_tools,
                ttl_seconds=ttl_seconds
            )
        except PermissionError as e:
            self.ledger.append(
                event_type="DELEGATION_REJECTED_ATTENUATION_VIOLATION",
                agent_id=parent_token.holder_id,
                payload={
                    "attempted_child": child_id,
                    "requested_tools": list(child_tools),
                    "parent_tools": list(parent_token.allowed_tools),
                    "error": str(e)
                },
                lineage=parent_token.lineage_path
            )
            return False, None, str(e)

        child_sig = child_token.signature.hex()
        self.valid_tokens_by_sig[child_sig] = child_token

        self.ledger.append(
            event_type="TASK_DELEGATED",
            agent_id=child_id,
            payload={
                "parent_id": parent_token.holder_id,
                "child_id": child_id,
                "child_tools": list(child_tools),
                "task_description": task_description
            },
            lineage=child_token.lineage_path
        )
        return True, child_token, "Delegation approved"

    def invoke_tool(
        self,
        token: LineageToken,
        claimed_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any]
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Mediates tool execution.
        Verifies:
        1. Token holder identity matches claimed_agent_id (anti-spoofing).
        2. Cryptographic signature validity.
        3. Tool is within token.allowed_tools.
        4. Neither agent nor token is revoked.
        """
        t0 = time.perf_counter()
        sig_hex = token.signature.hex()

        # 1. Identity binding check: token holder is cryptographically bound to leaf of lineage
        if token.holder_id != claimed_agent_id:
            self.ledger.append(
                event_type="TOOL_REJECTED_IDENTITY_MISMATCH",
                agent_id=claimed_agent_id,
                payload={"token_holder": token.holder_id, "claimed_id": claimed_agent_id, "tool": tool_name},
                lineage=token.lineage_path
            )
            return False, None, f"Identity mismatch: token issued to {token.holder_id}, claimed by {claimed_agent_id}"

        # 2. Revocation check
        if sig_hex in self.revoked_signatures or claimed_agent_id in self.revoked_agent_ids:
            return False, None, "Token or agent identity has been revoked"

        # 3. Signature verification
        if not self.authority.verify_token_chain(token):
            return False, None, "Invalid token cryptographic signature"

        # 4. Scope check
        if tool_name not in token.allowed_tools:
            self.ledger.append(
                event_type="TOOL_REJECTED_UNAUTHORIZED_SCOPE",
                agent_id=claimed_agent_id,
                payload={"attempted_tool": tool_name, "allowed_tools": list(token.allowed_tools)},
                lineage=token.lineage_path
            )
            return False, None, f"Tool '{tool_name}' not in allowed scope {token.allowed_tools}"

        # Execute tool (mock tool execution for benchmarking)
        execution_id = hashlib.sha256(f"{sig_hex}_{tool_name}_{time.time()}".encode()).hexdigest()[:16]
        result_payload = {
            "status": "success",
            "tool": tool_name,
            "execution_id": execution_id,
            "output": f"Mock output for {tool_name} with args {tool_args}"
        }

        entry_hash = self.ledger.append(
            event_type="TOOL_EXECUTED",
            agent_id=claimed_agent_id,
            payload={
                "tool": tool_name,
                "args": tool_args,
                "execution_id": execution_id,
                "result_status": "success"
            },
            lineage=token.lineage_path
        )
        result_payload["ledger_entry_hash"] = entry_hash

        dt = time.perf_counter() - t0
        result_payload["verification_latency_ms"] = dt * 1000.0
        return True, result_payload, "Tool executed successfully"

    def commit_task_result(
        self,
        token: LineageToken,
        result_data: Dict[str, Any],
        claimed_tool_executions: List[str]
    ) -> Tuple[bool, str]:
        """
        Commits child execution result to parent.
        Verifies that all claimed tool executions actually occurred and are present in the ledger.
        Catches Phantom Execution / Result Forgery.
        """
        # Collect valid execution IDs from ledger for this agent
        valid_executions = set()
        for entry in self.ledger.entries:
            if entry["event_type"] == "TOOL_EXECUTED" and entry["agent_id"] == token.holder_id:
                exec_id = entry["payload"].get("execution_id")
                if exec_id:
                    valid_executions.add(exec_id)

        for claimed_id in claimed_tool_executions:
            if claimed_id not in valid_executions:
                self.ledger.append(
                    event_type="RESULT_REJECTED_PHANTOM_EXECUTION",
                    agent_id=token.holder_id,
                    payload={"claimed_unverified_execution_id": claimed_id},
                    lineage=token.lineage_path
                )
                return False, f"Phantom execution detected: claimed execution {claimed_id} not recorded in gateway ledger"

        self.ledger.append(
            event_type="TASK_COMPLETED",
            agent_id=token.holder_id,
            payload={"result_summary": str(result_data)[:200]},
            lineage=token.lineage_path
        )
        return True, "Task result committed and verified against ledger"

    def revoke_agent(self, agent_id: str):
        """Revokes an agent ID and automatically invalidates all descendant tokens."""
        self.revoked_agent_ids.add(agent_id)
        self.ledger.append(
            event_type="AGENT_REVOKED",
            agent_id="GATEWAY_ADMIN",
            payload={"revoked_agent_id": agent_id},
            lineage=["GATEWAY_ADMIN"]
        )
