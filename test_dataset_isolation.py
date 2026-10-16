
"""
Integration and isolation tests for FraudTrace AI multi-dataset architecture.
Verifies that:
1. Both datasets exist simultaneously and are completely isolated.
2. The allowlist rejects unknown dataset IDs.
3. Node labels and IDs do not cross-contaminate.
4. Case memories saved under one dataset do not appear in another dataset.
5. Path queries and clusters respect the active dataset.
6. The investigation assistant routes to the requested dataset.
"""

import unittest
import uuid
from dataset_registry import (
    validate_dataset_id,
    get_graph,
    get_graph_stats,
    get_dataset_metadata,
    list_datasets,
    DATASET_ALLOWLIST,
)
from ring_detection import (
    detect_connected_accounts,
    find_graph_paths,
    detect_suspicious_clusters,
    search_graph_entities,
)
from case_memory import (
    save_investigation_memory,
    get_recent_investigation_memories,
)
from ai_assistant import (
    investigate_question,
    get_transaction_evidence,
    get_connected_account_evidence,
)


class DatasetIsolationTests(unittest.TestCase):
    def test_allowlist_validation(self):
        self.assertEqual(validate_dataset_id("demo_synthetic"), "demo_synthetic")
        self.assertEqual(validate_dataset_id("ibm_amlsim"), "ibm_amlsim")
        self.assertEqual(validate_dataset_id(None), "demo_synthetic")
        self.assertEqual(validate_dataset_id(""), "demo_synthetic")

        with self.assertRaises(ValueError):
            validate_dataset_id("malicious_graph_name")

        with self.assertRaises(ValueError):
            validate_dataset_id("system")

    def test_datasets_list_and_metadata(self):
        datasets = list_datasets()
        self.assertEqual(len(datasets), 2)
        ids = {d["dataset_id"] for d in datasets}
        self.assertEqual(ids, {"demo_synthetic", "ibm_amlsim"})

        demo_meta = get_dataset_metadata("demo_synthetic")
        self.assertTrue(demo_meta["has_device_ip"])
        self.assertTrue(demo_meta["has_merchant"])
        self.assertFalse(demo_meta["has_alerts"])

        aml_meta = get_dataset_metadata("ibm_amlsim")
        self.assertFalse(aml_meta["has_device_ip"])
        self.assertFalse(aml_meta["has_merchant"])
        self.assertTrue(aml_meta["has_alerts"])

    def test_graph_isolation_entities_never_cross(self):
        """Synthetic accounts must not exist in AMLSim; AML accounts must not exist in demo."""
        g_demo = get_graph("demo_synthetic")
        g_aml = get_graph("ibm_amlsim")

        # ACC001 in demo, NOT in AML
        demo_acc = g_demo.query("MATCH (a {id: 'ACC001'}) RETURN a.id")
        self.assertEqual(len(demo_acc.result_set), 1)

        aml_acc_check = g_aml.query("MATCH (a {id: 'ACC001'}) RETURN a.id")
        self.assertEqual(len(aml_acc_check.result_set), 0)

        # AML_ACC_0 in AML, NOT in demo
        aml_acc = g_aml.query("MATCH (a {id: 'AML_ACC_0'}) RETURN a.id")
        self.assertEqual(len(aml_acc.result_set), 1)

        demo_aml_check = g_demo.query("MATCH (a {id: 'AML_ACC_0'}) RETURN a.id")
        self.assertEqual(len(demo_aml_check.result_set), 0)

    def test_connected_accounts_dataset_awareness(self):
        # Demo account
        demo_res = detect_connected_accounts("ACC002", dataset_id="demo_synthetic")
        self.assertIsNotNone(demo_res)
        self.assertEqual(demo_res["account_id"], "ACC002")
        self.assertGreater(demo_res["related_account_count"], 0)
        self.assertIn("shared_devices", demo_res["related_accounts"][0])

        # AML account
        aml_res = detect_connected_accounts("AML_ACC_25", dataset_id="ibm_amlsim")
        self.assertIsNotNone(aml_res)
        self.assertEqual(aml_res["account_id"], "AML_ACC_25")
        self.assertGreater(aml_res["related_account_count"], 0)
        self.assertIn("sent_transactions", aml_res["related_accounts"][0])

        # Wrong dataset returns None
        wrong_1 = detect_connected_accounts("ACC002", dataset_id="ibm_amlsim")
        self.assertIsNone(wrong_1)
        wrong_2 = detect_connected_accounts("AML_ACC_25", dataset_id="demo_synthetic")
        self.assertIsNone(wrong_2)

    def test_path_finder_dataset_isolation(self):
        # Path in demo
        demo_paths = find_graph_paths("ACC001", "ACC002", max_hops=3, dataset_id="demo_synthetic")
        self.assertGreater(demo_paths["path_count"], 0)

        # Same query in AML should find 0 paths because ACC001 does not exist in AML
        aml_demo_paths = find_graph_paths("ACC001", "ACC002", max_hops=3, dataset_id="ibm_amlsim")
        self.assertEqual(aml_demo_paths["path_count"], 0)

        # Path in AML
        aml_paths = find_graph_paths("AML_ACC_24", "AML_ACC_25", max_hops=3, dataset_id="ibm_amlsim")
        self.assertGreater(aml_paths["path_count"], 0)

    def test_cluster_detection_both_datasets(self):
        demo_clusters = detect_suspicious_clusters(dataset_id="demo_synthetic")
        self.assertIsInstance(demo_clusters, list)
        self.assertGreaterEqual(len(demo_clusters), 1)
        self.assertTrue(any(len(c.get("shared_devices", [])) > 0 for c in demo_clusters))

        aml_clusters = detect_suspicious_clusters(dataset_id="ibm_amlsim")
        self.assertIsInstance(aml_clusters, list)
        self.assertGreaterEqual(len(aml_clusters), 1)
        self.assertTrue(all(len(c.get("shared_devices", [])) == 0 for c in aml_clusters))
        self.assertTrue(any(len(c.get("transactions", [])) > 0 for c in aml_clusters))

    def test_case_memory_isolation(self):
        """Memory saved for an AML account must be in AML graph and not in Demo graph."""
        uid = uuid.uuid4().hex[:8]
        test_q = f"AML ISOLATION TEST {uid}"

        # Save to AML
        saved = save_investigation_memory(
            account_id="AML_ACC_25",
            question=test_q,
            answer="Observation in AMLSim graph.",
            session_id=f"test-session-{uid}",
            dataset_id="ibm_amlsim",
        )
        self.assertTrue(saved["saved"])
        mem_id = saved["memory_id"]

        try:
            # Query AML graph memory
            aml_mem = get_recent_investigation_memories(
                account_id="AML_ACC_25",
                session_id=f"test-session-{uid}",
                dataset_id="ibm_amlsim",
            )
            matching = [m for m in aml_mem["memories"] if m["memory_id"] == mem_id]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0]["dataset_id"], "ibm_amlsim")

            # Demo graph must not have AML_ACC_25 memory (in fact, AML_ACC_25 does not exist in Demo)
            with self.assertRaises(LookupError):
                get_recent_investigation_memories(
                    account_id="AML_ACC_25",
                    dataset_id="demo_synthetic",
                )

        finally:
            # Clean up test node
            g_aml = get_graph("ibm_amlsim")
            g_aml.query(
                "MATCH (m:InvestigationMemory {memory_id: $mid}) DETACH DELETE m",
                params={"mid": mem_id},
            )

    def test_assistant_dataset_awareness(self):
        session_id = f"dataset-awareness-{uuid.uuid4().hex}"
        try:
            res_demo = investigate_question(
                "ACC002",
                "Why is this account suspicious?",
                session_id=session_id,
                dataset_id="demo_synthetic",
            )
            self.assertEqual(res_demo["dataset_id"], "demo_synthetic")
            self.assertIn("ACC002", res_demo["account_id"])

            res_aml = investigate_question(
                "AML_ACC_25",
                "Why is this account suspicious?",
                session_id=session_id,
                dataset_id="ibm_amlsim",
            )
            self.assertEqual(res_aml["dataset_id"], "ibm_amlsim")
            self.assertEqual(res_aml["account_id"], "AML_ACC_25")
            self.assertIn("AMLSim", res_aml["warning"])
        finally:
            for dataset_id in ("demo_synthetic", "ibm_amlsim"):
                get_graph(dataset_id).query(
                    """
                    MATCH (m:InvestigationMemory {session_id: $session_id})
                    DETACH DELETE m
                    """,
                    params={"session_id": session_id},
                )


if __name__ == "__main__":
    unittest.main()
