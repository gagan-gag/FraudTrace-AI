
"""
FraudTrace AI — persistent investigation memory.

Stores investigation history in FalkorDB so it survives process restarts.
Historical investigation results are observations, not verified facts.
Supports dataset isolation across demo_synthetic and ibm_amlsim.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from dataset_registry import get_graph, validate_dataset_id

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
    dataset_id: str = "demo_synthetic",
) -> dict[str, Any]:
    """
    Save a completed investigation linked to an existing account.

    Evidence is serialized as JSON because graph properties should use
    simple supported property values rather than nested Python objects.
    """
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

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

    acc_label = "AMLAccount" if dataset_id == "ibm_amlsim" else "Account"

    # MATCH ensures we never create an account merely because a caller
    # supplied an arbitrary account ID.
    query = f"""
        MATCH (a:{acc_label} {{id: $account_id}})
        CREATE (m:InvestigationMemory {{
            memory_id: $memory_id,
            account_id: $account_id,
            question: $question,
            answer: $answer,
            intent: $intent,
            session_id: $session_id,
            evidence_json: $evidence_json,
            created_at: $created_at,
            dataset_id: $dataset_id,
            record_type: 'historical_observation',
            verification_status: 'unverified'
        }})
        CREATE (a)-[:HAS_INVESTIGATION_MEMORY]->(m)
        RETURN
            m.memory_id AS memory_id,
            m.account_id AS account_id,
            m.created_at AS created_at
    """

    result = target_graph.query(
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
            "dataset_id": dataset_id,
        },
    )

    if not result.result_set:
        raise LookupError(
            f"Account {account_id} does not exist in dataset '{dataset_id}'; memory was not saved."
        )

    row = result.result_set[0]

    return {
        "saved": True,
        "memory_id": row[0],
        "account_id": row[1],
        "created_at": row[2],
        "dataset_id": dataset_id,
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
    dataset_id: str = "demo_synthetic",
) -> dict[str, Any]:
    """
    Retrieve recent historical investigations for an existing account.

    A session filter is optional. Without it, history is retrieved across
    sessions, enabling persistent recall.
    """
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

    account_id = account_id.strip().upper()

    if not account_id:
        raise ValueError("account_id must not be empty")

    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")

    session_id = session_id.strip() if session_id else None

    acc_label = "AMLAccount" if dataset_id == "ibm_amlsim" else "Account"

    # Confirm account exists first to distinguish 404 from empty memory
    acc_check = target_graph.query(
        f"MATCH (a:{acc_label} {{id: $account_id}}) RETURN a.id",
        params={"account_id": account_id},
    )
    if not acc_check.result_set:
        raise LookupError(f"Account {account_id} does not exist in dataset '{dataset_id}'.")

    if session_id:
        query = f"""
            MATCH (a:{acc_label} {{id: $account_id}})
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
                m.verification_status AS verification_status,
                m.dataset_id AS dataset_id
            ORDER BY m.created_at DESC
            LIMIT $limit
        """
        params = {
            "account_id": account_id,
            "session_id": session_id,
            "limit": limit,
        }
    else:
        query = f"""
            MATCH (a:{acc_label} {{id: $account_id}})
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
                m.verification_status AS verification_status,
                m.dataset_id AS dataset_id
            ORDER BY m.created_at DESC
            LIMIT $limit
        """
        params = {
            "account_id": account_id,
            "limit": limit,
        }

    result = target_graph.query(query, params=params)

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
            "dataset_id": row[10] if len(row) > 10 and row[10] else dataset_id,
        })

    return {
        "account_id": account_id,
        "dataset_id": dataset_id,
        "memories": memories,
        "memory_count": len(memories),
        "source": f"FalkorDB persistent investigation history ({dataset_id})",
        "warning": (
            "Historical responses may be outdated. Their presence in memory "
            "does not make their claims verified facts."
        ),
    }
