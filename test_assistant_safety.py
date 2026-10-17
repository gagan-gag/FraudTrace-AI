"""Isolated assistant evidence and error-sanitization regressions."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ai_assistant


class AssistantSafetyTests(unittest.TestCase):
    def test_alert_question_selects_detailed_transaction_evidence(self):
        plan = ai_assistant.plan_investigation(
            "Are there any AML alerts for this account?"
        )

        self.assertIn("transaction_evidence", plan["selected_tools"])
        self.assertEqual(plan["requested_sections"], ["alerts"])
        self.assertEqual(plan["intent"], "alert_review")

    def test_linked_account_questions_select_network_evidence(self):
        plan = ai_assistant.plan_investigation(
            "Show me the linked accounts."
        )

        self.assertEqual(
            plan["selected_tools"],
            ["connected_account_signals"],
        )
        self.assertEqual(
            plan["requested_sections"],
            ["connected_accounts"],
        )
        self.assertEqual(plan["intent"], "network_investigation")

    def test_risk_questions_keep_broad_evidence_and_risk_intent(self):
        plan = ai_assistant.plan_investigation(
            "Why should this account be reviewed?"
        )

        self.assertEqual(
            plan["selected_tools"],
            ["connected_account_signals", "transaction_evidence"],
        )
        self.assertEqual(
            plan["requested_sections"],
            ["connected_accounts", "transactions", "alerts"],
        )
        self.assertEqual(plan["intent"], "risk_review")

    def test_alert_records_are_returned_as_referenced_evidence(self):
        graph = Mock()
        graph.query.return_value = SimpleNamespace(
            result_set=[("AML_ACC_25", True, False)]
        )
        alert = {
            "alert_id": "AML_ALERT_0",
            "alert_text": "1",
            "check_name": "cycle",
            "display_description": "Cycle pattern alert",
            "pattern": "cycle",
            "event_date": "2017-02-18",
        }
        transaction_result = {
            "found": True,
            "account_id": "AML_ACC_25",
            "transactions": [],
            "transaction_count": 0,
            "flagged_transaction_count": 0,
            "alerts": [alert],
            "alert_count": 1,
            "source": "mocked AMLSim evidence",
        }

        with (
            patch("ai_assistant.get_graph", return_value=graph),
            patch(
                "ai_assistant.get_dataset_metadata",
                return_value={"disclaimer": "Synthetic simulation data."},
            ),
            patch(
                "ai_assistant.get_recent_investigation_memories",
                return_value={"memories": []},
            ),
            patch(
                "ai_assistant.get_connected_account_evidence",
                return_value={
                    "found": True,
                    "related_accounts": [],
                    "related_account_count": 0,
                },
            ),
            patch(
                "ai_assistant.get_transaction_evidence",
                return_value=transaction_result,
            ),
            patch("ai_assistant._answer_with_llm", return_value=("Alert found.", "test")),
            patch(
                "ai_assistant.save_investigation_memory",
                return_value={"saved": False},
            ),
        ):
            result = ai_assistant.investigate_question(
                account_id="AML_ACC_25",
                question="What alerts are linked to this account?",
                dataset_id="ibm_amlsim",
            )

        self.assertEqual(result["evidence"][0]["type"], "alert")
        self.assertEqual(result["evidence"][0]["alert_text"], "1")
        self.assertEqual(
            result["evidence"][0]["display_description"],
            "Cycle pattern alert",
        )
        self.assertEqual(
            result["evidence_references"][0]["evidence_id"],
            "EV-ALERT-AML_ALERT_0",
        )

    def test_memory_save_failure_does_not_expose_exception_details(self):
        graph = Mock()
        graph.query.return_value = SimpleNamespace(
            result_set=[("ACC002", "REVIEW")]
        )

        with (
            patch("ai_assistant.get_graph", return_value=graph),
            patch(
                "ai_assistant.get_dataset_metadata",
                return_value={"disclaimer": "Synthetic simulation data."},
            ),
            patch(
                "ai_assistant.get_recent_investigation_memories",
                return_value={"memories": []},
            ),
            patch(
                "ai_assistant.get_connected_account_evidence",
                return_value={
                    "found": True,
                    "related_accounts": [],
                    "related_account_count": 0,
                },
            ),
            patch(
                "ai_assistant.get_transaction_evidence",
                return_value={
                    "found": True,
                    "transactions": [],
                    "transaction_count": 0,
                    "flagged_transaction_count": 0,
                    "alerts": [],
                    "alert_count": 0,
                },
            ),
            patch("ai_assistant._answer_with_llm", return_value=("No findings.", "test")),
            patch(
                "ai_assistant.save_investigation_memory",
                side_effect=RuntimeError("private database detail"),
            ),
        ):
            result = ai_assistant.investigate_question(
                account_id="ACC002",
                question="Why should this account be reviewed?",
            )

        self.assertEqual(
            result["memory_save_error"],
            "Unable to save the investigation memory.",
        )
        self.assertNotIn("private database detail", str(result))

    def test_public_assistant_mode_skips_persistent_memory_reads(self):
        graph = Mock()
        graph.query.return_value = SimpleNamespace(
            result_set=[("ACC002", "medium")]
        )

        with (
            patch("ai_assistant.get_graph", return_value=graph),
            patch(
                "ai_assistant.get_dataset_metadata",
                return_value={"disclaimer": "Synthetic demonstration data."},
            ),
            patch(
                "ai_assistant.get_recent_investigation_memories"
            ) as get_memories,
            patch(
                "ai_assistant.get_connected_account_evidence",
                return_value={
                    "found": True,
                    "related_accounts": [],
                    "related_account_count": 0,
                },
            ),
            patch(
                "ai_assistant.get_transaction_evidence",
                return_value={
                    "found": True,
                    "transactions": [],
                    "transaction_count": 0,
                    "flagged_transaction_count": 0,
                    "alerts": [],
                    "alert_count": 0,
                },
            ),
            patch("ai_assistant._answer_with_llm", return_value=("Summary.", "test")),
            patch(
                "ai_assistant.save_investigation_memory",
                return_value={"saved": True},
            ),
        ):
            result = ai_assistant.investigate_question(
                account_id="ACC002",
                question="Summarize this account.",
                session_id="unverified-client-session",
                include_previous_memories=False,
            )

        get_memories.assert_not_called()
        self.assertEqual(result["previous_memories"], [])
        self.assertIn(
            {
                "step": "retrieve_previous_memories",
                "status": "skipped_unverified_identity",
            },
            result["investigation_steps"],
        )

    def test_graph_summary_explicitly_reports_empty_selected_evidence(self):
        context = {
            "dataset_id": "ibm_amlsim",
            "connected_account_evidence": {
                "found": True,
                "related_accounts": [],
            },
            "transaction_evidence": {
                "found": True,
                "transactions": [],
                "alerts": [],
            },
            "selected_tools": [
                "connected_account_signals",
                "transaction_evidence",
            ],
            "requested_sections": [
                "connected_accounts",
                "transactions",
                "alerts",
            ],
        }

        with patch("ai_assistant._llm_configuration", return_value=None):
            answer, method = ai_assistant._answer_with_llm(
                account_id="AML_ACC_25",
                question="Summarize the evidence.",
                session_id="test-session",
                evidence_context=context,
                previous_memories=[],
            )

        self.assertEqual(method, "graph_evidence_summary")
        self.assertIn("No connected AML counterparties were found.", answer)
        self.assertIn("No transactions were found for this account.", answer)
        self.assertIn("No alerts were found linked to this account.", answer)


if __name__ == "__main__":
    unittest.main()
