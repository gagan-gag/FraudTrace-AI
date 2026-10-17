"""Isolated regression tests for the AI investigation request flow."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

import ai_assistant
from app import AskRequest, ask_investigation


class LLMResponseTests(unittest.TestCase):
    def call_llm(self, response_json):
        response = Mock(status_code=200)
        response.json.return_value = response_json
        response.raise_for_status.return_value = None

        with patch.object(
            ai_assistant,
            "_llm_configuration",
            return_value=("test-key", "https://provider.invalid/v1", "test-model"),
        ), patch.object(ai_assistant.requests, "post", return_value=response):
            return ai_assistant._answer_with_llm(
                account_id="AML_ACC_25",
                question="Why is this account suspicious?",
                session_id="test-session",
                evidence_context={"dataset_id": "ibm_amlsim"},
                previous_memories=[],
            )

    def test_valid_provider_response(self):
        answer, answer_method = self.call_llm({
            "choices": [{"message": {"content": "Review transaction [EV-TXN-T1]."}}],
        })

        self.assertEqual(answer, "Review transaction [EV-TXN-T1].")
        self.assertEqual(answer_method, "llm_grounded_answer")

    def test_llm_prompt_receives_focus_and_markdown_requirements(self):
        response = Mock(status_code=200)
        response.json.return_value = {
            "choices": [{"message": {"content": "## AML Alerts\n- No alerts found."}}],
        }
        response.raise_for_status.return_value = None
        evidence_context = {
            "dataset_id": "ibm_amlsim",
            "intent": "alert_review",
            "selected_tools": ["transaction_evidence"],
            "requested_sections": ["alerts"],
            "transaction_evidence": {"alerts": [], "transactions": []},
            "evidence_references": [],
            "warning": "Simulated labels are not proof of real-world fraud.",
        }

        with patch.object(
            ai_assistant,
            "_llm_configuration",
            return_value=("test-key", "https://provider.invalid/v1", "test-model"),
        ), patch.object(
            ai_assistant.requests,
            "post",
            return_value=response,
        ) as post:
            ai_assistant._answer_with_llm(
                account_id="AML_ACC_25",
                question="Are there any AML alerts?",
                session_id="test-session",
                evidence_context=evidence_context,
                previous_memories=[],
            )

        messages = post.call_args.kwargs["json"]["messages"]
        system_prompt = messages[0]["content"]
        user_prompt = messages[1]["content"]
        self.assertIn('"investigation_intent":"alert_review"', user_prompt)
        self.assertIn('"selected_evidence_tools":["transaction_evidence"]', user_prompt)
        self.assertIn('"requested_response_sections":["alerts"]', user_prompt)
        self.assertIn("headings and short bullets", system_prompt)
        self.assertIn("check name, event date, and evidence ID", system_prompt)

    def test_string_and_unexpected_nested_values_are_controlled(self):
        malformed_responses = [
            "provider error",
            {"choices": ["unexpected choice"]},
            {"choices": [{"message": "unexpected message"}]},
            {"choices": [{"message": {"content": ["not", "text"]}}]},
        ]

        for payload in malformed_responses:
            with self.subTest(payload=payload):
                answer, answer_method = self.call_llm(payload)
                self.assertIn("could not be processed", answer)
                self.assertEqual(answer_method, "llm_request_failed")

    def test_missing_empty_and_blank_choices_are_controlled(self):
        for payload in (
            {},
            {"choices": []},
            {"choices": [{"message": {"content": "  "}}]},
        ):
            with self.subTest(payload=payload):
                answer, answer_method = self.call_llm(payload)
                self.assertTrue(answer)
                self.assertEqual(answer_method, "llm_request_failed")


class InvestigationFlowTests(unittest.TestCase):
    def setUp(self):
        self.graph = Mock()
        self.graph.query.return_value = SimpleNamespace(
            result_set=[["AML_ACC_25", False, True]],
        )
        self.related_account = {
            "account_id": "AML_ACC_24",
            "signals": ["sent_transactions"],
            "sent_transactions": ["TX1"],
            "received_transactions": [],
            "shared_alerts": [],
            "counterparty_is_fraud": False,
            "review_priority": "MEDIUM",
        }
        self.transaction = {
            "transaction_id": "TX1",
            "amount": 125.0,
            "status": "flagged",
            "direction": "sent",
            "counterparty": "AML_ACC_24",
        }
        self.alert = {
            "alert_id": "AML_ALERT_0",
            "display_description": "Cycle pattern alert",
            "check_name": "cycle",
            "event_date": "2017-02-18",
            "pattern": "cycle",
            "alert_text": "Source alert record",
        }
        self.memories = [{
            "question": "Previous question",
            "answer": "Previous observation",
            "created_at": "2026-01-01T00:00:00+00:00",
            "verification_status": "unverified",
            "record_type": "historical_observation",
        }]

    def investigate(
        self,
        question="Why is this account suspicious?",
        alerts=None,
        save_return_value=None,
        save_side_effect=None,
    ):
        if save_return_value is None and save_side_effect is None:
            save_return_value = {"saved": True}

        with patch.object(ai_assistant, "get_graph", return_value=self.graph), \
                patch.object(ai_assistant, "get_dataset_metadata", return_value={
                    "disclaimer": "AMLSim is simulated data, not proof of fraud.",
                }), \
                patch.object(ai_assistant, "get_recent_investigation_memories", return_value={
                    "memories": self.memories,
                }) as get_memories, \
                patch.object(ai_assistant, "get_connected_account_evidence", return_value={
                    "found": True,
                    "related_accounts": [self.related_account],
                    "related_account_count": 1,
                    "source": "mock graph evidence",
                }) as get_connections, \
                patch.object(ai_assistant, "get_transaction_evidence", return_value={
                    "found": True,
                    "transactions": [self.transaction],
                    "transaction_count": 1,
                    "flagged_transaction_count": 1,
                    "alerts": alerts or [],
                    "alert_count": len(alerts or []),
                    "source": "mock graph evidence",
                }) as get_transactions, \
                patch.object(
                    ai_assistant,
                    "save_investigation_memory",
                    return_value=save_return_value,
                    side_effect=save_side_effect,
                ) as save_memory:
            result = ai_assistant.investigate_question(
                account_id="AML_ACC_25",
                question=question,
                session_id="test-session",
                dataset_id="ibm_amlsim",
            )

        return result, get_memories, save_memory, get_connections, get_transactions

    def test_specific_alert_domain_overrides_generic_explanation_wording(self):
        plan = ai_assistant.plan_investigation(
            "Please explain the AML alerts for AML_ACC_25."
        )

        self.assertEqual(plan["intent"], "alert_review")
        self.assertEqual(plan["selected_tools"], ["transaction_evidence"])
        self.assertEqual(plan["requested_sections"], ["alerts"])

    def test_graph_evidence_fallback_and_persistent_memory(self):
        saved_result = {
            "saved": True,
            "memory_id": "memory-1",
            "account_id": "AML_ACC_25",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(ai_assistant, "_llm_configuration", return_value=None), \
                patch.object(ai_assistant.requests, "post") as post:
            result, get_memories, save_memory, _, _ = self.investigate(
                save_return_value=saved_result,
            )

        post.assert_not_called()
        get_memories.assert_called_once()
        save_memory.assert_called_once()
        self.assertTrue(result["memory_saved"])
        self.assertEqual(result["memory_count"], 1)
        self.assertIn("AML_ACC_25", result["answer"])
        self.assertIn("simulated data", result["answer"])
        self.assertIn("not proof of fraud", result["warning"])
        self.assertIn("## 1. Investigation Overview", result["answer"])
        self.assertIn("Connected Accounts", result["answer"])
        self.assertIn("Transaction Analysis", result["answer"])
        self.assertIn("AML Alerts", result["answer"])
        self.assertEqual(result["evidence"][0]["evidence_id"], "EV-LINK-AML_ACC_24")
        self.assertEqual(result["evidence"][1]["evidence_id"], "EV-TXN-TX1")
        self.assertTrue(result["investigation_steps"])

    def test_memory_save_failure_preserves_valid_answer(self):
        with patch.object(ai_assistant, "_llm_configuration", return_value=None), \
                self.assertLogs(ai_assistant.logger, level="WARNING"):
            result, _, _, _, _ = self.investigate(
                save_side_effect=RuntimeError("mock database unavailable"),
            )

        self.assertIn("Investigation Overview", result["answer"])
        self.assertFalse(result["memory_saved"])
        self.assertEqual(result["investigation_steps"][-1]["status"], "failed")
        self.assertEqual(
            result["memory_save_error"],
            "Unable to save the investigation memory.",
        )
        self.assertNotIn(
            "mock database unavailable",
            result["memory_save_error"],
        )

    def test_alert_question_routes_and_renders_alert_fields_only(self):
        question = "Are there any AML alerts for AML_ACC_25?"
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, get_connections, get_transactions = self.investigate(
                question=question,
                alerts=[self.alert],
            )

        self.assertEqual(result["intent"], "alert_review")
        self.assertEqual(result["selected_tools"], ["transaction_evidence"])
        get_connections.assert_not_called()
        get_transactions.assert_called_once()
        answer = result["answer"]
        self.assertIn("## 2. AML Alerts", answer)
        self.assertIn("AML_ALERT_0", answer)
        self.assertIn("Cycle pattern alert", answer)
        self.assertIn("**Check name:** cycle", answer)
        self.assertIn("**Event date:** 2017-02-18", answer)
        self.assertIn("[EV-ALERT-AML_ALERT_0]", answer)
        self.assertNotIn("Connected Accounts", answer)
        self.assertNotIn("Transaction Analysis", answer)
        self.assertIn("Data Disclaimer", answer)
        self.assertIn("not proof of real-world fraud", answer)
        self.assertIn("\n\n## ", answer)

    def test_alert_question_states_when_no_alerts_were_retrieved(self):
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, get_connections, _ = self.investigate(
                question="Are there any AML alerts for AML_ACC_25?",
                alerts=[],
            )

        self.assertEqual(result["intent"], "alert_review")
        self.assertIn(
            "No linked AML alerts were found in the retrieved evidence.",
            result["answer"],
        )
        self.assertNotIn("AML_ALERT_0", result["answer"])
        get_connections.assert_not_called()

    def test_alert_records_remain_available_with_connected_account_results(self):
        question = "Show AML alerts and connected accounts for AML_ACC_25."
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, get_connections, get_transactions = self.investigate(
                question=question,
                alerts=[self.alert],
            )

        self.assertEqual(result["intent"], "combined_investigation")
        get_connections.assert_called_once()
        get_transactions.assert_called_once()
        self.assertIn("AML Alerts", result["answer"])
        self.assertIn("AML_ALERT_0", result["answer"])
        self.assertIn("[EV-ALERT-AML_ALERT_0]", result["answer"])
        self.assertIn("AML_ACC_24", result["answer"])
        self.assertNotIn("Transaction Analysis", result["answer"])

    def test_transaction_question_is_transaction_focused(self):
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, get_connections, _ = self.investigate(
                question="What transactions are linked to AML_ACC_25?",
                alerts=[self.alert],
            )

        self.assertEqual(result["intent"], "transaction_review")
        answer = result["answer"]
        self.assertIn("## 2. Transaction Analysis", answer)
        self.assertIn("TX1", answer)
        self.assertIn("**Direction:** sent", answer)
        self.assertIn("**Amount:** 125.0", answer)
        self.assertIn("**Stored status:** flagged", answer)
        self.assertIn("[EV-TXN-TX1]", answer)
        self.assertNotIn("Connected Accounts", answer)
        self.assertNotIn("AML Alerts", answer)
        get_connections.assert_not_called()

    def test_connected_account_question_is_relationship_focused(self):
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, _, get_transactions = self.investigate(
                question="Which accounts are connected to AML_ACC_25?",
                alerts=[self.alert],
            )

        self.assertEqual(result["intent"], "network_investigation")
        answer = result["answer"]
        self.assertIn("## 2. Connected Accounts", answer)
        self.assertIn("AML_ACC_24", answer)
        self.assertIn("MEDIUM", answer)
        self.assertIn("sent_transactions", answer)
        self.assertIn("[EV-LINK-AML_ACC_24]", answer)
        self.assertNotIn("Transaction Analysis", answer)
        self.assertNotIn("AML Alerts", answer)
        get_transactions.assert_not_called()

    def test_missing_transaction_fields_are_not_invented(self):
        self.transaction = {
            "transaction_id": "TX-MISSING",
            "amount": None,
            "status": None,
        }
        with patch.object(ai_assistant, "_llm_configuration", return_value=None):
            result, _, _, _, _ = self.investigate(
                question="What transactions are linked to AML_ACC_25?",
            )

        self.assertIn("Not available in retrieved evidence", result["answer"])
        self.assertNotIn("$0", result["answer"])


class AskEndpointTests(unittest.TestCase):
    def test_success_returns_investigation_schema(self):
        expected = {
            "account_id": "AML_ACC_25",
            "dataset_id": "ibm_amlsim",
            "answer": "Review transaction [EV-TXN-T1].",
            "evidence": [{"evidence_id": "EV-TXN-T1"}],
            "investigation_steps": [{"step": "natural_language_answer", "status": "llm_grounded_answer"}],
            "warning": "Simulation data, not proof of fraud.",
        }
        request = AskRequest(
            account_id="aml_acc_25",
            question="Why is this account suspicious?",
            session_id="test-session",
            dataset_id="ibm_amlsim",
        )

        with patch("app.investigate_question", return_value=expected):
            result = ask_investigation(request)

        self.assertEqual(result, expected)

    def test_investigation_error_becomes_controlled_503(self):
        request = AskRequest(
            account_id="AML_ACC_25",
            question="Why is this account suspicious?",
            session_id="test-session",
            dataset_id="ibm_amlsim",
        )

        with patch("app.investigate_question", return_value={"error": "provider response invalid"}):
            with self.assertRaises(HTTPException) as raised:
                ask_investigation(request)

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(
            raised.exception.detail,
            "The investigation assistant is temporarily unavailable.",
        )
        self.assertNotIn("provider response invalid", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()