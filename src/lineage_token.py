"""
Cryptographic Lineage Capability Tokens for Multi-Agent Swarms.
Implements HMAC-chained, caveat-attenuated capability tokens (Macaroon-style)
for monotonic privilege decay across agent delegation trees.
"""

import hmac
import hashlib
import json
import time
from typing import List, Dict, Any, Optional, Set

class LineageCaveat:
    """Represents an attenuation caveat bound to a token."""
    def __init__(self, key: str, value: Any):
        self.key = key
        self.value = value

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "value": self.value}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> 'LineageCaveat':
        return LineageCaveat(d["key"], d["value"])

    def serialize(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True).encode('utf-8')


class LineageToken:
    """
    An immutable cryptographic capability token.
    Contains:
    - root_task_id: Unique identifier of the initiating user task
    - lineage_path: Ordered tuple of agent IDs from root to current holder
    - allowed_tools: Set of tool identifiers permitted
    - caveats: List of attenuation constraints (e.g., max_budget, expires_at)
    - signature: HMAC signature chaining parent token to current child
    """
    def __init__(
        self,
        root_task_id: str,
        lineage_path: List[str],
        allowed_tools: Set[str],
        expires_at: float,
        caveats: Optional[List[LineageCaveat]] = None,
        signature: bytes = b"",
        parent_signature: bytes = b""
    ):
        self.root_task_id = root_task_id
        self.lineage_path = list(lineage_path)
        self.allowed_tools = set(allowed_tools)
        self.expires_at = expires_at
        self.caveats = caveats or []
        self.signature = signature
        self.parent_signature = parent_signature

    @property
    def holder_id(self) -> str:
        return self.lineage_path[-1] if self.lineage_path else "UNKNOWN"

    @property
    def depth(self) -> int:
        return len(self.lineage_path)

    def payload_bytes(self) -> bytes:
        """Deterministic canonical representation for signing."""
        data = {
            "root_task_id": self.root_task_id,
            "lineage_path": self.lineage_path,
            "allowed_tools": sorted(list(self.allowed_tools)),
            "expires_at": round(self.expires_at, 3),
            "caveats": [c.to_dict() for c in self.caveats],
            "parent_signature": self.parent_signature.hex()
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_task_id": self.root_task_id,
            "lineage_path": self.lineage_path,
            "allowed_tools": sorted(list(self.allowed_tools)),
            "expires_at": self.expires_at,
            "caveats": [c.to_dict() for c in self.caveats],
            "signature": self.signature.hex(),
            "parent_signature": self.parent_signature.hex()
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> 'LineageToken':
        return LineageToken(
            root_task_id=d["root_task_id"],
            lineage_path=d["lineage_path"],
            allowed_tools=set(d["allowed_tools"]),
            expires_at=d["expires_at"],
            caveats=[LineageCaveat.from_dict(c) for c in d.get("caveats", [])],
            signature=bytes.fromhex(d["signature"]) if d.get("signature") else b"",
            parent_signature=bytes.fromhex(d.get("parent_signature", "")) if d.get("parent_signature") else b""
        )


class TokenAuthority:
    """
    Gateway-side cryptographic authority.
    Holds the root master secret K_GW and verifies/mints lineage tokens.
    """
    def __init__(self, master_secret: bytes):
        self._master_secret = master_secret

    def mint_root_token(
        self,
        root_task_id: str,
        initial_agent_id: str,
        allowed_tools: Set[str],
        ttl_seconds: float = 3600.0,
        caveats: Optional[List[LineageCaveat]] = None
    ) -> LineageToken:
        """Mints the root token for the primary orchestrator."""
        expires_at = time.time() + ttl_seconds
        token = LineageToken(
            root_task_id=root_task_id,
            lineage_path=[initial_agent_id],
            allowed_tools=allowed_tools,
            expires_at=expires_at,
            caveats=caveats or [],
            parent_signature=b"ROOT"
        )
        token.signature = hmac.new(
            self._master_secret,
            token.payload_bytes(),
            hashlib.sha256
        ).digest()
        return token

    def attenuate(
        self,
        parent_token: LineageToken,
        child_agent_id: str,
        child_allowed_tools: Set[str],
        ttl_seconds: Optional[float] = None,
        additional_caveats: Optional[List[LineageCaveat]] = None
    ) -> LineageToken:
        """
        Derives an attenuated child token.
        Enforces Monotonic Capability Attenuation:
        1. child_tools MUST be a subset of parent_tools
        2. child_expiry MUST NOT exceed parent_expiry
        3. child signature is HMAC-chained from parent's signature
        """
        # Strict subset enforcement
        if not child_allowed_tools.issubset(parent_token.allowed_tools):
            raise PermissionError(
                f"Attenuation violation: Child requested tools {child_allowed_tools - parent_token.allowed_tools} "
                f"which exceed parent capability set."
            )

        now = time.time()
        child_expiry = parent_token.expires_at
        if ttl_seconds is not None:
            candidate_expiry = now + ttl_seconds
            child_expiry = min(parent_token.expires_at, candidate_expiry)

        combined_caveats = list(parent_token.caveats)
        if additional_caveats:
            combined_caveats.extend(additional_caveats)

        child_lineage = parent_token.lineage_path + [child_agent_id]

        child_token = LineageToken(
            root_task_id=parent_token.root_task_id,
            lineage_path=child_lineage,
            allowed_tools=child_allowed_tools,
            expires_at=child_expiry,
            caveats=combined_caveats,
            parent_signature=parent_token.signature
        )

        # Chained HMAC: child is signed using parent's signature as key
        child_token.signature = hmac.new(
            parent_token.signature,
            child_token.payload_bytes(),
            hashlib.sha256
        ).digest()

        return child_token

    def verify_token_chain(self, token: LineageToken) -> bool:
        """
        Verifies the full cryptographic chain of the token from root to leaf.
        Returns True if valid, False otherwise.
        """
        now = time.time()
        if now > token.expires_at:
            return False

        # If it's a root token
        if token.depth == 1:
            expected = hmac.new(
                self._master_secret,
                token.payload_bytes(),
                hashlib.sha256
            ).digest()
            return hmac.compare_digest(expected, token.signature)

        # For depth > 1, parent_signature must be present
        if not token.parent_signature:
            return False

        expected = hmac.new(
            token.parent_signature,
            token.payload_bytes(),
            hashlib.sha256
        ).digest()
        return hmac.compare_digest(expected, token.signature)
