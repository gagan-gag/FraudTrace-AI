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
        self.memories = [{
            "question": "Previous question",
            "answer": "Previous observation",
            "created_at": "2026-01-01T00:00:00+00:00",
            "verification_status": "unverified",
            "record_type": "historical_observation",
        }]

    def investigate(self, save_return_value=None, save_side_effect=None):
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
                }), \
                patch.object(ai_assistant, "get_transaction_evidence", return_value={
                    "found": True,
                    "transactions": [self.transaction],
                    "transaction_count": 1,
                    "flagged_transaction_count": 1,
                    "alerts": [],
                    "alert_count": 0,
                    "source": "mock graph evidence",
                }), \
                patch.object(
                    ai_assistant,
                    "save_investigation_memory",
                    return_value=save_return_value,
                    side_effect=save_side_effect,
                ) as save_memory:
            result = ai_assistant.investigate_question(
                account_id="AML_ACC_25",
                question="Why is this account suspicious?",
                session_id="test-session",
                dataset_id="ibm_amlsim",
            )

        return result, get_memories, save_memory

    def test_graph_evidence_fallback_and_persistent_memory(self):
        saved_result = {
            "saved": True,
            "memory_id": "memory-1",
            "account_id": "AML_ACC_25",
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(ai_assistant, "_llm_configuration", return_value=None), \
                patch.object(ai_assistant.requests, "post") as post:
            result, get_memories, save_memory = self.investigate(
                save_return_value=saved_result,
            )

        post.assert_not_called()
        get_memories.assert_called_once()
        save_memory.assert_called_once()
        self.assertTrue(result["memory_saved"])
        self.assertEqual(result["memory_count"], 1)
        self.assertIn("AML_ACC_25", result["answer"])
        self.assertIn("simulation data", result["answer"])
        self.assertIn("not proof of fraud", result["warning"])
        self.assertEqual(result["evidence"][0]["evidence_id"], "EV-LINK-AML_ACC_24")
        self.assertEqual(result["evidence"][1]["evidence_id"], "EV-TXN-TX1")
        self.assertTrue(result["investigation_steps"])

    def test_memory_save_failure_preserves_valid_answer(self):
        with patch.object(ai_assistant, "_llm_configuration", return_value=None), \
                self.assertLogs(ai_assistant.logger, level="WARNING"):
            result, _, _ = self.investigate(
                save_side_effect=RuntimeError("mock database unavailable"),
            )

        self.assertIn("Investigation findings", result["answer"])
        self.assertFalse(result["memory_saved"])
        self.assertEqual(result["investigation_steps"][-1]["status"], "failed")
        self.assertIn("mock database unavailable", result["memory_save_error"])


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
        self.assertIn("provider response invalid", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()