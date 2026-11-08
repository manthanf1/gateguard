"""
Unit Test Suite for GateGuard Reference Monitor & Lineage Capability Tokens.
Run via: python3 -m unittest discover -s tests
"""

import unittest
import sys, os; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))); from lineage_token import LineageToken, TokenAuthority
from gateway_monitor import GatewayReferenceMonitor

class TestGateGuardSecurity(unittest.TestCase):
    def setUp(self):
        self.gw = GatewayReferenceMonitor()
        self.root_token = self.gw.init_task(
            root_task_id="test_task_01",
            orchestrator_id="root_orch",
            allowed_tools={"read_db", "write_db", "search_web"}
        )

    def test_valid_monotonic_delegation(self):
        ok, child_tok, msg = self.gw.delegate_subtask(
            parent_token=self.root_token,
            child_id="worker_1",
            child_tools={"read_db", "search_web"},
            task_description="subset task"
        )
        self.assertTrue(ok)
        self.assertIsNotNone(child_tok)
        self.assertEqual(child_tok.holder_id, "worker_1")
        self.assertEqual(child_tok.depth, 2)

    def test_downward_privilege_laundering_blocked(self):
        ok, worker_tok, _ = self.gw.delegate_subtask(
            parent_token=self.root_token,
            child_id="worker_1",
            child_tools={"search_web"},
            task_description="narrow task"
        )
        self.assertTrue(ok)
        # Worker 1 attempts to delegate read_db (which it does not hold) to sub_worker_2
        ok2, sub_tok, msg = self.gw.delegate_subtask(
            parent_token=worker_tok,
            child_id="sub_worker_2",
            child_tools={"search_web", "read_db"},
            task_description="escalated task"
        )
        self.assertFalse(ok2)
        self.assertIsNone(sub_tok)
        self.assertIn("Attenuation violation", msg)

    def test_identity_spoofing_blocked(self):
        ok, worker_tok, _ = self.gw.delegate_subtask(
            parent_token=self.root_token,
            child_id="worker_1",
            child_tools={"search_web"},
            task_description="web search"
        )
        # Worker 1 claims to be root_orch
        exec_ok, res, msg = self.gw.invoke_tool(
            token=worker_tok,
            claimed_agent_id="root_orch",
            tool_name="search_web",
            tool_args={"q": "test"}
        )
        self.assertFalse(exec_ok)
        self.assertIn("Identity mismatch", msg)

    def test_phantom_execution_blocked(self):
        ok, worker_tok, _ = self.gw.delegate_subtask(
            parent_token=self.root_token,
            child_id="worker_1",
            child_tools={"search_web"},
            task_description="web search"
        )
        # Worker fabricates an execution_id never logged by gateway
        commit_ok, msg = self.gw.commit_task_result(
            token=worker_tok,
            result_data={"status": "all checks passed"},
            claimed_tool_executions=["forged_exec_9999"]
        )
        self.assertFalse(commit_ok)
        self.assertIn("Phantom execution detected", msg)

    def test_audit_ledger_tamper_detection(self):
        self.gw.invoke_tool(
            token=self.root_token,
            claimed_agent_id="root_orch",
            tool_name="read_db",
            tool_args={"table": "users"}
        )
        self.assertTrue(self.gw.ledger.verify_integrity())
        # Tamper with an entry
        self.gw.ledger.entries[-1]["payload"]["args"]["table"] = "harmless_table"
        self.assertFalse(self.gw.ledger.verify_integrity())

if __name__ == "__main__":
    unittest.main()
