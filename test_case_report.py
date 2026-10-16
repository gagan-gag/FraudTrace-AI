
"""
FraudTrace AI — PDF Case Report Regression Tests

Tests PDF generation using synthetic fixtures without making API calls
or changing FalkorDB data.

Run:
    python -m unittest test_case_report -v
"""

import tempfile
import unittest
from pathlib import Path

from export_case_report import build_report


class CaseReportTests(unittest.TestCase):
    """Regression tests for the PDF case report exporter."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_path = (
            Path(self.temp_dir.name) / "ACC002_case_report.pdf"
        )

        self.investigation = {
            "account_id": "ACC002",
            "risk_label": "REVIEW",
            "related_accounts": ["ACC001", "ACC003", "ACC006"],
            "shared_devices": ["DEV001", "DEV002"],
            "multi_hop_paths": [
                {
                    "start_account": "ACC002",
                    "connected_account": "ACC001",
                    "intermediary_account": "DEV001",
                    "steps": ["ACC002", "DEV001", "ACC001"],
                    "evidence": [
                        "Both accounts use the same synthetic device."
                    ],
                }
            ],
            "multi_hop_path_count": 1,
            "finding": (
                "Several connected-account signals warrant manual review."
            ),
            "warning": (
                "Connections are investigation leads, not proof of fraud."
            ),
        }

        self.account_evidence = {
            "account_id": "ACC002",
            "risk_label": "REVIEW",
            "transaction_count": 2,
            "flagged_transaction_count": 1,
            "transactions": [
                {
                    "transaction_id": "TXN002",
                    "amount": 8700,
                    "status": "flagged",
                    "merchant_id": "MER001",
                },
                {
                    "transaction_id": "TXN003",
                    "amount": 1200,
                    "status": "normal",
                    "merchant_id": "MER002",
                },
            ],
            "warning": "Synthetic demonstration data.",
        }

        self.graph_data = {
            "hops": 3,
            "node_count": 4,
            "edge_count": 3,
            "nodes": [
                {
                    "id": "ACC002",
                    "labels": ["Account"],
                    "properties": {"id": "ACC002"},
                },
                {
                    "id": "DEV001",
                    "labels": ["Device"],
                    "properties": {"id": "DEV001"},
                },
                {
                    "id": "ACC001",
                    "labels": ["Account"],
                    "properties": {"id": "ACC001"},
                },
                {
                    "id": "TXN002",
                    "labels": ["Transaction"],
                    "properties": {"amount": 8700},
                },
            ],
            "edges": [
                {
                    "source": "ACC002",
                    "target": "DEV001",
                    "relationship": "USES_DEVICE",
                },
                {
                    "source": "ACC001",
                    "target": "DEV001",
                    "relationship": "USES_DEVICE",
                },
                {
                    "source": "ACC002",
                    "target": "TXN002",
                    "relationship": "MADE",
                },
            ],
        }

        self.assistant = {
            "account_id": "ACC002",
            "question": "Why is this account suspicious?",
            "answer": (
                "The account has connected-account signals and a "
                "flagged synthetic transaction that warrant review."
            ),
            "evidence": [
                {
                    "type": "connected_account",
                    "account_id": "ACC001",
                    "review_priority": "HIGH",
                    "signals": ["shared device"],
                }
            ],
            "warning": (
                "This is a demonstration assistant, not a fraud verdict."
            ),
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def generate_report(self):
        """Generate a report using the test fixtures."""
        build_report(
            output_path=self.output_path,
            account_id="ACC002",
            investigation=self.investigation,
            account_evidence=self.account_evidence,
            graph_data=self.graph_data,
            assistant=self.assistant,
            hops=3,
        )

    def test_generates_pdf_file(self):
        """The exporter creates a non-empty PDF."""
        self.generate_report()

        self.assertTrue(self.output_path.exists())
        self.assertGreater(self.output_path.stat().st_size, 1000)

    def test_output_has_pdf_signature(self):
        """The generated file begins with the PDF signature."""
        self.generate_report()

        with self.output_path.open("rb") as pdf_file:
            signature = pdf_file.read(5)

        self.assertEqual(signature, b"%PDF-")

    def test_output_has_pdf_end_marker(self):
        """The generated PDF contains its end-of-file marker."""
        self.generate_report()

        content = self.output_path.read_bytes()

        self.assertIn(b"%%EOF", content[-2048:])

    def test_report_creates_missing_parent_directory(self):
        """The exporter creates output directories when necessary."""
        nested_path = (
            Path(self.temp_dir.name)
            / "reports"
            / "nested"
            / "ACC002.pdf"
        )

        build_report(
            output_path=nested_path,
            account_id="ACC002",
            investigation=self.investigation,
            account_evidence=self.account_evidence,
            graph_data=self.graph_data,
            assistant=self.assistant,
            hops=3,
        )

        self.assertTrue(nested_path.exists())
        self.assertGreater(nested_path.stat().st_size, 1000)

    def test_report_generation_is_repeatable(self):
        """Repeated generation succeeds without modifying source data."""
        original_account = self.investigation["account_id"]
        original_transaction_count = (
            self.account_evidence["transaction_count"]
        )

        self.generate_report()
        first_size = self.output_path.stat().st_size

        self.generate_report()
        second_size = self.output_path.stat().st_size

        self.assertGreater(first_size, 1000)
        self.assertGreater(second_size, 1000)

        self.assertEqual(
            self.investigation["account_id"],
            original_account,
        )

        self.assertEqual(
            self.account_evidence["transaction_count"],
            original_transaction_count,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
