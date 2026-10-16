
"""Integration tests for FraudTrace AI persistent case memory."""

import json
import uuid
import unittest

from falkordb import FalkorDB
from case_memory import (
    save_investigation_memory,
    get_recent_investigation_memories,
)


class CaseMemoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = FalkorDB(host="localhost", port=6379)
        cls.graph = cls.db.select_graph("FraudTrace")

        account_check = cls.graph.query(
            "MATCH (a:Account {id: $account_id}) RETURN a.id",
            params={"account_id": "ACC002"},
        )
        if not account_check.result_set:
            raise unittest.SkipTest(
                "ACC002 is not present in the FraudTrace graph. "
                "Run the project graph seeding process first."
            )

    def test_memory_can_be_saved_and_retrieved(self):
        unique_question = f"MEMORY TEST {uuid.uuid4()}"
        memory_id = None

        try:
            saved = save_investigation_memory(
                account_id="ACC002",
                question=unique_question,
                answer="Temporary integration-test observation.",
                intent="memory_integration_test",
                evidence=[
                    {
                        "type": "test_evidence",
                        "source": "test_case_memory.py",
                        "verification_status": "unverified",
                    }
                ],
                session_id="automated-test",
            )

            self.assertTrue(saved["saved"])
            self.assertEqual(saved["account_id"], "ACC002")
            self.assertEqual(
                saved["verification_status"], "unverified"
            )
            memory_id = saved["memory_id"]

            retrieved = get_recent_investigation_memories(
                account_id="ACC002",
                limit=50,
                session_id="automated-test",
            )

            matching = [
                item for item in retrieved["memories"]
                if item["memory_id"] == memory_id
            ]

            self.assertEqual(len(matching), 1)
            record = matching[0]

            self.assertEqual(record["question"], unique_question)
            self.assertEqual(
                record["answer"],
                "Temporary integration-test observation.",
            )
            self.assertEqual(record["intent"], "memory_integration_test")
            self.assertEqual(record["evidence"][0]["type"], "test_evidence")
            self.assertEqual(
                record["verification_status"], "unverified"
            )

        finally:
            if memory_id:
                self.graph.query(
                    """
                    MATCH (m:InvestigationMemory {memory_id: $memory_id})
                    DETACH DELETE m
                    """,
                    params={"memory_id": memory_id},
                )

    def test_unknown_account_does_not_create_memory(self):
        with self.assertRaises(LookupError):
            save_investigation_memory(
                account_id="ACC_DOES_NOT_EXIST_TEST",
                question="This record must not be created",
                answer="This is a test.",
                session_id="automated-test",
            )

    def test_invalid_memory_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            get_recent_investigation_memories(
                account_id="ACC002",
                limit=1000,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
