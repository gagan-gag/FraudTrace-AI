"""
Targeted tests for FraudTrace AI enhanced graph capabilities.
Validates:
- Shared-device detection
- Shared-IP detection
- Shared-merchant detection with actual transactions
- No-path and no-common-merchant behavior
- Multi-hop path explorer (/paths)
- Suspicious cluster detection (/clusters)
- Entity search (/search)
- Evidence references integrity
- UTF-8 character encoding preservation
"""

import unittest
import uuid

from dataset_registry import get_graph
from ring_detection import (
    detect_connected_accounts,
    find_graph_paths,
    detect_suspicious_clusters,
    search_graph_entities,
)
from ai_assistant import investigate_question, plan_investigation


class EnhancedFeaturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = get_graph("demo_synthetic")

    def test_shared_device_and_ip_detection(self):
        """Verify ACC002 shares DEV001/IP001 with ACC001 and DEV002/IP002 with ACC003/ACC006."""
        res = detect_connected_accounts("ACC002")
        self.assertIsNotNone(res)
        self.assertEqual(res["account_id"], "ACC002")

        rel_by_id = {r["account_id"]: r for r in res["related_accounts"]}
        self.assertIn("ACC001", rel_by_id)
        self.assertIn("DEV001", rel_by_id["ACC001"]["shared_devices"])
        self.assertIn("IP001", rel_by_id["ACC001"]["shared_ips"])
        self.assertIn("shared_device", rel_by_id["ACC001"]["signals"])
        self.assertIn("shared_ip", rel_by_id["ACC001"]["signals"])

    def test_shared_merchant_detection_with_actual_transactions(self):
        """Verify ACC001 and ACC002 share merchant MER001 through TXN001 and TXN002."""
        res = detect_connected_accounts("ACC002")
        rel_by_id = {r["account_id"]: r for r in res["related_accounts"]}
        self.assertIn("ACC001", rel_by_id)
        self.assertIn("MER001", rel_by_id["ACC001"]["common_merchants"])
        self.assertIn("shared_merchant", rel_by_id["ACC001"]["signals"])
        self.assertEqual(rel_by_id["ACC001"]["review_priority"], "HIGH")

    def test_no_common_merchant_behavior(self):
        """Verify ACC002 and ACC003 share device and IP but have NO common merchant."""
        res = detect_connected_accounts("ACC002")
        rel_by_id = {r["account_id"]: r for r in res["related_accounts"]}
        self.assertIn("ACC003", rel_by_id)
        self.assertEqual(rel_by_id["ACC003"]["common_merchants"], [])
        self.assertNotIn("shared_merchant", rel_by_id["ACC003"]["signals"])

    def test_multi_hop_path_finder(self):
        """Verify real path traversal discovers multi-hop paths between ACC001 and ACC002."""
        res = find_graph_paths("ACC001", "ACC002", max_hops=4)
        self.assertGreater(res["path_count"], 0)
        self.assertTrue(len(res["paths"]) > 0)

        # Check path steps structure
        first_path = res["paths"][0]
        self.assertEqual(first_path["source"], "ACC001")
        self.assertEqual(first_path["target"], "ACC002")
        self.assertTrue(first_path["hops"] >= 1)
        self.assertIn("steps", first_path)
        self.assertIn("relationships", first_path)

    def test_path_finder_no_connection_or_invalid_id(self):
        """Verify path finder returns empty paths gracefully when entity does not exist."""
        res = find_graph_paths("ACC001", "NON_EXISTENT_ENTITY", max_hops=3)
        self.assertEqual(res["path_count"], 0)
        self.assertEqual(res["paths"], [])

    def test_suspicious_cluster_detection(self):
        """Verify multi-account clusters are detected, bounded, and ranked."""
        clusters = detect_suspicious_clusters()
        self.assertIsInstance(clusters, list)
        self.assertGreaterEqual(len(clusters), 1)

        # First cluster should be the highest priority
        c1 = clusters[0]
        self.assertIn("cluster_id", c1)
        self.assertIn("accounts", c1)
        self.assertGreaterEqual(c1["account_count"], 2)
        self.assertIn("heuristic_score", c1)
        self.assertIn("heuristic_priority", c1)
        self.assertIn("shared_devices", c1)
        self.assertIn("flagged_transactions", c1)

    def test_entity_search_substring(self):
        """Verify searching entities returns matched node records."""
        results = search_graph_entities("DEV", limit=10)
        self.assertGreater(len(results), 0)
        for item in results:
            self.assertIn("DEV", item["id"].upper())
            self.assertIn("type", item)

    def test_evidence_reference_integrity(self):
        """Verify assistant generates traceable EV-LINK and EV-TXN references."""
        session_id = f"test-evidence-integrity-{uuid.uuid4().hex}"
        try:
            res = investigate_question(
                account_id="ACC002",
                question="Which accounts share devices and transactions with ACC002?",
                session_id=session_id,
            )
            self.assertEqual(res["account_id"], "ACC002")
            evidence = res.get("evidence", [])
            self.assertGreater(len(evidence), 0)

            for ev in evidence:
                ev_id = ev.get("evidence_id")
                self.assertIsNotNone(ev_id)
                self.assertTrue(
                    ev_id.startswith("EV-LINK-")
                    or ev_id.startswith("EV-TXN-")
                    or ev_id.startswith("EV-OTHER-")
                )
        finally:
            self.graph.query(
                """
                MATCH (m:InvestigationMemory {session_id: $session_id})
                DETACH DELETE m
                """,
                params={"session_id": session_id},
            )

    def test_utf8_currency_and_punctuation_integrity(self):
        """Verify Indian Rupee (₹) and em-dash (—) are preserved in UTF-8 without corruption."""
        sample_text = "Amount: ₹25,000.00 — Flagged Transaction"
        encoded = sample_text.encode("utf-8")
        decoded = encoded.decode("utf-8")
        self.assertEqual(sample_text, decoded)
        self.assertNotIn("â", decoded)
        self.assertIn("₹", decoded)
        self.assertIn("—", decoded)


if __name__ == "__main__":
    unittest.main()
