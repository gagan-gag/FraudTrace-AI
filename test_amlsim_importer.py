
"""
Unit tests for IBM AMLSim Importer pipeline.
Tests CSV parsing, column validation, dry-run mode, and idempotency.
"""

import unittest
from pathlib import Path

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
        self.assertTrue((data_path / "alerts.csv").exists())
        self.assertGreater((data_path / "accounts.csv").stat().st_size, 0)
        self.assertGreater((data_path / "tx.csv").stat().st_size, 0)
        self.assertGreater((data_path / "alerts.csv").stat().st_size, 0)

    def test_dry_run_mode_returns_counts_without_errors(self):
        stats = run_import(dry_run=True, verbose=False)
        self.assertEqual(stats.accounts_read, 30)
        self.assertEqual(stats.tx_read, 45)
        self.assertEqual(stats.alerts_read, 2)
        self.assertEqual(stats.total_rejected, 0)
        self.assertEqual(stats.accounts_created, 30)
        self.assertEqual(stats.tx_created, 45)
        self.assertEqual(stats.alerts_created, 2)

    def test_idempotent_live_import(self):
        """Live import should be idempotent; re-running it should not duplicate nodes."""
        stats_before = get_graph_stats("ibm_amlsim")
        nodes_before = stats_before["total_nodes"]
        rels_before = stats_before["total_relationships"]

        # Run import again
        import_stats = run_import(dry_run=False, verbose=False)
        self.assertEqual(import_stats.total_rejected, 0)

        stats_after = get_graph_stats("ibm_amlsim")
        self.assertEqual(stats_after["total_nodes"], nodes_before)
        self.assertEqual(stats_after["total_relationships"], rels_before)


if __name__ == "__main__":
    unittest.main()
