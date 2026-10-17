
"""
Unit tests for IBM AMLSim Importer pipeline.
Tests CSV parsing, column validation, dry-run mode, and idempotency.
"""

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dataset_registry import get_graph, get_graph_stats
from amlsim_importer import (
    run_import,
    _acc_id,
    _txn_id,
    _alert_id,
    _safe_float,
    _safe_int,
    _safe_bool,
    DATA_DIR,
)
from ai_assistant import get_transaction_evidence


class AMLSimImporterTests(unittest.TestCase):
    def test_id_prefix_helpers(self):
        self.assertEqual(_acc_id("0"), "AML_ACC_0")
        self.assertEqual(_acc_id("ACC123"), "AML_ACC_ACC123")
        self.assertEqual(_txn_id("42"), "AML_TXN_42")
        self.assertEqual(_alert_id("1"), "AML_ALERT_1")

    def test_safe_type_parsers(self):
        self.assertEqual(_safe_float("123.45"), 123.45)
        self.assertEqual(_safe_float("invalid", default=0.0), 0.0)
        self.assertEqual(_safe_int("99"), 99)
        self.assertEqual(_safe_int("invalid", default=-1), -1)
        self.assertTrue(_safe_bool("True"))
        self.assertTrue(_safe_bool("true"))
        self.assertTrue(_safe_bool("YES"))
        self.assertTrue(_safe_bool("1"))
        self.assertFalse(_safe_bool("False"))
        self.assertFalse(_safe_bool("0"))
        self.assertFalse(_safe_bool("NO"))

    def test_data_files_exist_and_not_empty(self):
        data_path = Path(DATA_DIR)
        self.assertTrue(data_path.exists(), f"Data directory {DATA_DIR} does not exist.")
        self.assertTrue((data_path / "accounts.csv").exists())
        self.assertTrue((data_path / "tx.csv").exists())
        self.assertTrue((data_path / "cash_tx.csv").exists())
        self.assertTrue((data_path / "alerts.csv").exists())
        self.assertGreater((data_path / "accounts.csv").stat().st_size, 0)
        self.assertGreater((data_path / "tx.csv").stat().st_size, 0)
        self.assertGreater((data_path / "cash_tx.csv").stat().st_size, 0)
        self.assertGreater((data_path / "alerts.csv").stat().st_size, 0)

    def test_dry_run_mode_returns_counts_without_errors(self):
        stats = run_import(dry_run=True, verbose=False)
        self.assertEqual(stats.accounts_read, 30)
        self.assertEqual(stats.tx_read, 45)
        self.assertEqual(stats.cash_transactions_read, 88)
        self.assertEqual(stats.alerts_read, 2)
        self.assertEqual(stats.total_read, 165)
        self.assertEqual(stats.total_rejected, 0)
        self.assertEqual(stats.accounts_created, 30)
        self.assertEqual(stats.tx_created, 45)
        self.assertEqual(stats.cash_transactions_created, 88)
        self.assertEqual(stats.alerts_created, 2)

    def test_missing_input_files_fail_before_database_access(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("amlsim_importer.get_graph") as get_graph_mock:
                result = run_import(
                    data_dir=Path(temp_dir),
                    dry_run=False,
                    verbose=False,
                )

        self.assertFalse(result["success"])
        self.assertTrue(result["validation_errors"])
        get_graph_mock.assert_not_called()

    def test_idempotent_live_import(self):
        """Live import should be idempotent; re-running it should not duplicate nodes."""
        stats_before = get_graph_stats("ibm_amlsim")
        nodes_before = stats_before["total_nodes"]
        rels_before = stats_before["total_relationships"]
        demo_before = get_graph_stats("demo_synthetic")

        # Run import again
        import_stats = run_import(dry_run=False, verbose=False)
        self.assertTrue(import_stats.success)
        self.assertEqual(import_stats.total_rejected, 0)
        self.assertEqual(import_stats.total_created, 0)
        self.assertEqual(import_stats.accounts_updated, 30)
        self.assertEqual(import_stats.tx_updated, 45)
        self.assertEqual(import_stats.cash_transactions_updated, 88)
        self.assertEqual(import_stats.alerts_updated, 2)

        stats_after = get_graph_stats("ibm_amlsim")
        self.assertEqual(stats_after["total_nodes"], nodes_before)
        self.assertEqual(stats_after["total_relationships"], rels_before)
        self.assertEqual(stats_after["node_counts"]["AMLAccount"], 30)
        self.assertEqual(stats_after["node_counts"]["AMLTransaction"], 133)
        self.assertEqual(stats_after["node_counts"]["AMLAlert"], 2)
        self.assertEqual(stats_after["node_counts"]["AMLBranch"], 14)
        self.assertEqual(stats_after["relationship_counts"]["AML_SENT"], 133)
        self.assertEqual(stats_after["relationship_counts"]["AML_RECEIVED"], 45)
        self.assertEqual(stats_after["relationship_counts"]["AML_AT_BRANCH"], 88)
        self.assertEqual(stats_after["relationship_counts"]["HAS_ALERT"], 2)
        self.assertEqual(
            get_graph_stats("demo_synthetic"),
            demo_before,
        )

    def test_aml_acc_25_has_its_source_alert(self):
        evidence = get_transaction_evidence("AML_ACC_25", "ibm_amlsim")
        self.assertTrue(evidence["found"])
        self.assertEqual(evidence["alert_count"], 1)
        self.assertEqual(evidence["alerts"][0]["alert_id"], "AML_ALERT_0")

    def test_fraud_labels_do_not_flag_simulated_transactions(self):
        sent_transactions = [
            {
                "transaction_id": "AML_TXN_1",
                "amount": 10,
                "status": "simulated",
                "direction": "sent",
                "counterparty": "AML_ACC_2",
            },
            {
                "transaction_id": "AML_TXN_2",
                "amount": 20,
                "status": "simulated",
                "direction": "sent",
                "counterparty": "AML_ACC_3",
            },
            {
                "transaction_id": "AML_TXN_3",
                "amount": 30,
                "status": "flagged",
                "direction": "sent",
                "counterparty": "AML_ACC_4",
            },
        ]
        graph = SimpleNamespace(
            query=Mock(
                side_effect=[
                    SimpleNamespace(
                        result_set=[
                            (
                                "AML_ACC_1",
                                True,
                                False,
                                sent_transactions,
                                [],
                            )
                        ]
                    ),
                    SimpleNamespace(
                        result_set=[
                            (
                                "AML_ALERT_0",
                                "0",
                                "1",
                                "25",
                                "cycle",
                                "cycle",
                                "2017-02-18",
                                "INDIVIDUAL",
                                True,
                            )
                        ]
                    ),
                ]
            )
        )

        with patch("ai_assistant.get_graph", return_value=graph):
            evidence = get_transaction_evidence(
                "AML_ACC_1",
                "ibm_amlsim",
            )

        self.assertEqual(
            [item["status"] for item in evidence["transactions"]],
            ["simulated", "simulated", "flagged"],
        )
        self.assertEqual(evidence["flagged_transaction_count"], 1)
        self.assertEqual(
            evidence["alerts"][0]["display_description"],
            "Cycle pattern alert",
        )
        self.assertEqual(evidence["alerts"][0]["alert_text"], "1")
        self.assertEqual(evidence["alerts"][0]["check_name"], "cycle")
        self.assertEqual(evidence["alerts"][0]["pattern"], "cycle")

        transaction_query = graph.query.call_args_list[0].args[0]
        self.assertIn("status: tx_out.status", transaction_query)
        self.assertIn("status: tx_in.status", transaction_query)
        self.assertNotIn("CASE WHEN", transaction_query)


if __name__ == "__main__":
    unittest.main()
