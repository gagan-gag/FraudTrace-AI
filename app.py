
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from falkordb import FalkorDB

from ai_assistant import investigate_question
from case_memory import get_recent_investigation_memories


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = FastAPI(
    title="FraudTrace AI",
    description=(
        "Graph-powered fraud investigation using FalkorDB. "
        "Uses synthetic demonstration data and persistent "
        "investigation memory."
    ),
    version="0.6.1",
)


# ============================================================
# FALKORDB CONNECTION
# ============================================================

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("FraudTrace")


# ============================================================
# REQUEST MODELS
# ============================================================

class AskRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(
        default="default",
        min_length=1,
        max_length=100,
    )


# ============================================================
# HEALTH CHECK AND API INFORMATION
# ============================================================

@app.get("/")
def home():
    return {
        "project": "FraudTrace AI",
        "status": "running",
        "database": "FalkorDB",
        "version": "0.6.1",
        "endpoints": [
            "/",
            "/health",
            "/investigate/{account_id}",
            "/account-evidence/{account_id}",
            "/graph/{account_id}?hops=2",
            "/case-history/{account_id}?limit=10",
            "/ask",
            "/docs",
        ],
    }


@app.get("/health")
def health():
    try:
        db.connection.ping()
        return {
            "status": "healthy",
            "database": "FalkorDB",
            "graph": "FraudTrace",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB is not reachable.",
        ) from exc


# ============================================================
# ACCOUNT INVESTIGATION
# ============================================================

@app.get("/investigate/{account_id}")
def investigate(account_id: str):
    account_id = account_id.strip().upper()

    direct_query = """
        MATCH (target:Account {id: $account_id})
        OPTIONAL MATCH
            (target)-[:USES_DEVICE]->(d:Device)
            <-[:USES_DEVICE]-(related:Account)
        WHERE related.id <> target.id
        RETURN
            target.id AS account_id,
            target.risk AS risk_label,
            collect(DISTINCT related.id) AS related_accounts,
            collect(DISTINCT d.id) AS shared_devices
    """

    path_query = """
        MATCH
            (a:Account {id: $account_id})
            -[:USES_DEVICE]->(d:Device)
            <-[:USES_DEVICE]-(b:Account)
            -[:CONNECTS_FROM]->(ip:IPAddress)
            <-[:CONNECTS_FROM]-(c:Account)
        WHERE a.id <> b.id
          AND b.id <> c.id
          AND a.id <> c.id
        RETURN DISTINCT
            a.id AS start_account,
            d.id AS shared_device,
            b.id AS intermediary_account,
            ip.id AS shared_ip,
            c.id AS connected_account
        ORDER BY connected_account
    """

    try:
        direct_result = graph.query(
            direct_query,
            params={"account_id": account_id},
        )

        if not direct_result.result_set:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found.",
            )

        row = direct_result.result_set[0]

        path_result = graph.query(
            path_query,
            params={"account_id": account_id},
        )

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to query FalkorDB.",
        ) from exc

    paths = []

    for path_row in path_result.result_set:
        start, device, intermediary, shared_ip, connected = path_row

        paths.append({
            "start_account": start,
            "shared_device": device,
            "intermediary_account": intermediary,
            "shared_ip": shared_ip,
            "connected_account": connected,
            "steps": [
                start,
                device,
                intermediary,
                shared_ip,
                connected,
            ],
            "evidence": [
                f"{start} and {intermediary} share device {device}",
                (
                    f"{intermediary} and {connected} share "
                    f"IP address {shared_ip}"
                ),
            ],
        })

    return {
        "account_id": row[0],
        "risk_label": row[1] or "UNKNOWN",
        "related_accounts": row[2] or [],
        "shared_devices": row[3] or [],
        "multi_hop_paths": paths,
        "multi_hop_path_count": len(paths),
        "finding": (
            "Multi-hop connected-account pattern found"
            if paths
            else (
                "Shared-device connection found"
                if row[2]
                else "No shared-device connection found"
            )
        ),
        "warning": (
            "Connections are investigation leads, not proof of fraud. "
            "Shared devices and IP addresses can have legitimate explanations."
        ),
    }


# ============================================================
# TRANSACTION EVIDENCE
# ============================================================

@app.get("/account-evidence/{account_id}")
def account_evidence(account_id: str):
    account_id = account_id.strip().upper()

    query = """
        MATCH (a:Account {id: $account_id})
        OPTIONAL MATCH (a)-[:MADE]->(t:Transaction)
        OPTIONAL MATCH (t)-[:PAID_TO]->(m:Merchant)
        RETURN
            a.id AS account_id,
            a.risk AS risk_label,
            collect(DISTINCT {
                transaction_id: t.id,
                amount: t.amount,
                status: t.status,
                merchant_id: m.id
            }) AS transactions
    """

    try:
        result = graph.query(
            query,
            params={"account_id": account_id},
        )

        if not result.result_set:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found.",
            )

        row = result.result_set[0]

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to query transaction evidence.",
        ) from exc

    transactions = [
        item
        for item in (row[2] or [])
        if item and item.get("transaction_id") is not None
    ]

    flagged_count = sum(
        1
        for item in transactions
        if str(item.get("status", "")).lower() == "flagged"
    )

    return {
        "account_id": row[0],
        "risk_label": row[1] or "UNKNOWN",
        "transactions": transactions,
        "transaction_count": len(transactions),
        "flagged_transaction_count": flagged_count,
        "warning": (
            "Transaction flags in this synthetic dataset are "
            "investigation clues, not proof of fraud."
        ),
    }


# ============================================================
# MULTI-HOP GRAPH EXPLORER
# ============================================================

@app.get("/graph/{account_id}")
def get_account_graph(
    account_id: str,
    hops: int = Query(default=2, ge=1, le=3),
):
    """Return graph nodes and relationships within the requested hop limit."""

    account_id = account_id.strip().upper()

    try:
        check = graph.query(
            """
            MATCH (a:Account {id: $account_id})
            RETURN a.id
            """,
            params={"account_id": account_id},
        )

        if not check.result_set:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found.",
            )

        query = """
            MATCH (root:Account {id: $account_id})
            MATCH path = (root)-[*1..3]-(neighbor)
            WHERE length(path) <= $hops
            WITH collect(path) AS paths
            UNWIND paths AS p
            UNWIND nodes(p) AS n
            WITH collect(DISTINCT n) AS graph_nodes, paths
            UNWIND paths AS p
            UNWIND relationships(p) AS r
            WITH graph_nodes, collect(DISTINCT r) AS graph_edges
            RETURN
                [
                    n IN graph_nodes |
                    {
                        id: n.id,
                        labels: labels(n),
                        properties: properties(n)
                    }
                ] AS nodes,
                [
                    r IN graph_edges |
                    {
                        source: startNode(r).id,
                        target: endNode(r).id,
                        relationship: type(r)
                    }
                ] AS edges
        """

        result = graph.query(
            query,
            params={
                "account_id": account_id,
                "hops": hops,
            },
        )

        if not result.result_set:
            return {
                "account_id": account_id,
                "hops": hops,
                "nodes": [
                    {"id": account_id, "label": "Account"}
                ],
                "edges": [],
                "node_count": 1,
                "edge_count": 0,
                "source": "FalkorDB stored relationships",
            }

        raw_nodes, raw_edges = result.result_set[0]
        nodes_by_id = {}

        for item in raw_nodes or []:
            if not item:
                continue

            node_id = item.get("id")
            if not node_id:
                continue

            labels = item.get("labels") or []

            nodes_by_id[node_id] = {
                "id": node_id,
                "label": labels[0] if labels else "Unknown",
                "labels": labels,
                "properties": item.get("properties") or {},
            }

        edges = []
        seen_edges = set()

        for item in raw_edges or []:
            if not item:
                continue

            source = item.get("source")
            target = item.get("target")
            relationship = item.get("relationship")

            if not source or not target or not relationship:
                continue

            edge_key = (source, target, relationship)

            if edge_key in seen_edges:
                continue

            seen_edges.add(edge_key)

            edges.append({
                "source": source,
                "target": target,
                "relationship": relationship,
            })

        return {
            "account_id": account_id,
            "hops": hops,
            "nodes": list(nodes_by_id.values()),
            "edges": edges,
            "node_count": len(nodes_by_id),
            "edge_count": len(edges),
            "source": "FalkorDB stored relationships",
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve the multi-hop graph from FalkorDB.",
        ) from exc


# ============================================================
# CASE HISTORY — PERSISTENT INVESTIGATION MEMORY
# ============================================================

@app.get("/case-history/{account_id}")
def get_case_history(
    account_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    session_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
    ),
):
    """
    Retrieve historical investigation observations.

    Memories are unverified context, not independently verified evidence.
    """

    account_id = account_id.strip().upper()

    if session_id is not None:
        session_id = session_id.strip()

        if not session_id:
            raise HTTPException(
                status_code=422,
                detail="session_id cannot be blank.",
            )

    try:
        result = get_recent_investigation_memories(
            account_id=account_id,
            limit=limit,
            session_id=session_id,
        )

        if not isinstance(result, dict):
            raise HTTPException(
                status_code=503,
                detail="The case-history service returned an invalid response.",
            )

        return {
            **result,
            "warning": (
                "Historical investigation memories are unverified "
                "observations. Review current graph evidence before "
                "drawing conclusions."
            ),
        }

    except HTTPException:
        raise
    except LookupError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve case history from FalkorDB.",
        ) from exc


# ============================================================
# INVESTIGATION ASSISTANT
# ============================================================

@app.post("/ask")
def ask_investigation(request: AskRequest):
    account_id = request.account_id.strip().upper()
    question = request.question.strip()
    session_id = request.session_id.strip()

    if not account_id or not question:
        raise HTTPException(
            status_code=422,
            detail="Account ID and question cannot be blank.",
        )

    if not session_id:
        raise HTTPException(
            status_code=422,
            detail="Session ID cannot be blank.",
        )

    try:
        result = investigate_question(
            account_id=account_id,
            question=question,
            session_id=session_id,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found.",
            )

        return result

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="The investigation assistant could not complete the request.",
        ) from exc
