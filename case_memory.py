
"""
FraudTrace AI — persistent investigation memory.

Stores investigation history in FalkorDB so it survives process restarts.
Historical investigation results are observations, not verified facts.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from falkordb import FalkorDB


# ============================================================
# DATABASE CONNECTION
# ============================================================

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("FraudTrace")

MAX_EVIDENCE_ITEMS = 100
MAX_QUESTION_LENGTH = 2000
MAX_ANSWER_LENGTH = 8000


# ============================================================
# MEMORY WRITE
# ============================================================

def save_investigation_memory(
    account_id: str,
    question: str,
    answer: str,
    intent: str = "general_investigation",
    evidence: list[dict[str, Any]] | None = None,
    session_id: str = "default",
) -> dict[str, Any]:
    """
    Save a completed investigation linked to an existing account.

    Evidence is serialized as JSON because graph properties should use
    simple supported property values rather than nested Python objects.
    """

    account_id = account_id.strip().upper()
    question = question.strip()
    answer = answer.strip()
    session_id = session_id.strip() or "default"

    if not account_id:
        raise ValueError("account_id must not be empty")

    if not question:
        raise ValueError("question must not be empty")

    if not answer:
        raise ValueError("answer must not be empty")

    if len(question) > MAX_QUESTION_LENGTH:
        raise ValueError("question exceeds the allowed length")

    if len(answer) > MAX_ANSWER_LENGTH:
        raise ValueError("answer exceeds the allowed length")

    safe_evidence = (evidence or [])[:MAX_EVIDENCE_ITEMS]
    evidence_json = json.dumps(
        safe_evidence,
        ensure_ascii=False,
        default=str,
    )

    memory_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    # MATCH ensures we never create an account merely because a caller
    # supplied an arbitrary account ID.
    query = """
        MATCH (a:Account {id: $account_id})
        CREATE (m:InvestigationMemory {
            memory_id: $memory_id,
            account_id: $account_id,
            question: $question,
            answer: $answer,
            intent: $intent,
            session_id: $session_id,
            evidence_json: $evidence_json,
            created_at: $created_at,
            record_type: 'historical_observation',
            verification_status: 'unverified'
        })
        CREATE (a)-[:HAS_INVESTIGATION_MEMORY]->(m)
        RETURN
            m.memory_id AS memory_id,
            m.account_id AS account_id,
            m.created_at AS created_at
    """

    result = graph.query(
        query,
        params={
            "account_id": account_id,
            "memory_id": memory_id,
            "question": question,
            "answer": answer,
            "intent": intent,
            "session_id": session_id,
            "evidence_json": evidence_json,
            "created_at": created_at,
        },
    )

    if not result.result_set:
        raise LookupError(
            f"Account {account_id} does not exist; memory was not saved."
        )

    row = result.result_set[0]

    return {
        "saved": True,
        "memory_id": row[0],
        "account_id": row[1],
        "created_at": row[2],
        "record_type": "historical_observation",
        "verification_status": "unverified",
    }


# ============================================================
# MEMORY READ
# ============================================================

def get_recent_investigation_memories(
    account_id: str,
    limit: int = 10,
    session_id: str | None = None,
) -> dict[str, Any]:
    """
    Retrieve recent historical investigations for an existing account.

    A session filter is optional. Without it, history is retrieved across
    sessions, enabling persistent recall.
    """

    account_id = account_id.strip().upper()

    if not account_id:
        raise ValueError("account_id must not be empty")

    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")

    session_id = session_id.strip() if session_id else None

    if session_id:
        query = """
            MATCH (a:Account {id: $account_id})
                  -[:HAS_INVESTIGATION_MEMORY]->(m:InvestigationMemory)
            WHERE m.session_id = $session_id
            RETURN
                m.memory_id AS memory_id,
                m.account_id AS account_id,
                m.question AS question,
                m.answer AS answer,
                m.intent AS intent,
                m.session_id AS session_id,
                m.evidence_json AS evidence_json,
                m.created_at AS created_at,
                m.record_type AS record_type,
                m.verification_status AS verification_status
            ORDER BY m.created_at DESC
            LIMIT $limit
        """
        params = {
            "account_id": account_id,
            "session_id": session_id,
            "limit": limit,
        }
    else:
        query = """
            MATCH (a:Account {id: $account_id})
                  -[:HAS_INVESTIGATION_MEMORY]->(m:InvestigationMemory)
            RETURN
                m.memory_id AS memory_id,
                m.account_id AS account_id,
                m.question AS question,
                m.answer AS answer,
                m.intent AS intent,
                m.session_id AS session_id,
                m.evidence_json AS evidence_json,
                m.created_at AS created_at,
                m.record_type AS record_type,
                m.verification_status AS verification_status
            ORDER BY m.created_at DESC
            LIMIT $limit
        """
        params = {
            "account_id": account_id,
            "limit": limit,
        }

    result = graph.query(query, params=params)

    memories = []

    for row in result.result_set or []:
        try:
            evidence = json.loads(row[6] or "[]")
        except (json.JSONDecodeError, TypeError):
            evidence = []

        memories.append({
            "memory_id": row[0],
            "account_id": row[1],
            "question": row[2],
            "answer": row[3],
            "intent": row[4],
            "session_id": row[5],
            "evidence": evidence,
            "created_at": row[7],
            "record_type": row[8] or "historical_observation",
            "verification_status": row[9] or "unverified",
        })

    return {
        "account_id": account_id,
        "memories": memories,
        "memory_count": len(memories),
        "source": "FalkorDB persistent investigation history",
        "warning": (
            "Historical responses may be outdated. Their presence in memory "
            "does not make their claims verified facts."
        ),
    }
