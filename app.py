
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from falkordb import FalkorDB

from dataset_registry import (
    validate_dataset_id,
    get_graph,
    get_graph_stats,
    get_dataset_metadata,
    list_datasets,
)
from ai_assistant import (
    investigate_question,
    get_transaction_evidence,
)
from case_memory import get_recent_investigation_memories
from ring_detection import (
    find_graph_paths,
    detect_suspicious_clusters,
    search_graph_entities,
    detect_connected_accounts,
)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = FastAPI(
    title="FraudTrace AI",
    description=(
        "Graph-powered fraud investigation using FalkorDB. "
        "Supports multiple isolated datasets (FraudTrace synthetic demo & IBM AMLSim) "
        "and persistent investigation memory."
    ),
    version="0.7.0",
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
    dataset_id: str = Field(
        default="demo_synthetic",
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
        "version": "0.7.0",
        "endpoints": [
            "/",
            "/health",
            "/datasets",
            "/dataset-stats/{dataset_id}",
            "/investigate/{account_id}?dataset=demo_synthetic",
            "/account-evidence/{account_id}?dataset=demo_synthetic",
            "/graph/{account_id}?hops=2&dataset=demo_synthetic",
            "/case-history/{account_id}?limit=10&dataset=demo_synthetic",
            "/ask",
            "/paths?source={id}&target={id}&hops=4&dataset=demo_synthetic",
            "/clusters?dataset=demo_synthetic",
            "/search?q={term}&dataset=demo_synthetic",
            "/import-amlsim",
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
            "graphs": ["FraudTrace", "ibm_amlsim"],
        }
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="FalkorDB is not reachable.",
        ) from exc


# ============================================================
# DATASET MANAGEMENT
# ============================================================

@app.get("/datasets")
def get_datasets():
    """List all available datasets with metadata and node/relationship statistics."""
    try:
        return {
            "datasets": list_datasets(),
            "default_dataset": "demo_synthetic",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to retrieve dataset list: {exc}",
        ) from exc


@app.get("/dataset-stats/{dataset_id}")
def get_stats_for_dataset(dataset_id: str):
    """Retrieve detailed statistics for a specific dataset."""
    try:
        valid_id = validate_dataset_id(dataset_id)
        return get_graph_stats(valid_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to query dataset stats: {exc}",
        ) from exc


@app.post("/import-amlsim")
def import_amlsim_dataset(dry_run: bool = Query(default=False)):
    """Trigger the IBM AMLSim CSV import pipeline (dry-run or live)."""
    try:
        from amlsim_importer import run_import
        stats = run_import(dry_run=dry_run)
        return {
            "status": "success",
            "dry_run": dry_run,
            "target_graph": "ibm_amlsim",
            "stats": {
                "accounts_read": stats.accounts_read,
                "accounts_created": stats.accounts_created,
                "tx_read": stats.tx_read,
                "tx_created": stats.tx_created,
                "alerts_read": stats.alerts_read,
                "alerts_created": stats.alerts_created,
                "total_rejected": stats.total_rejected,
            },
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"AMLSim import failed: {exc}",
        ) from exc


# ============================================================
# ACCOUNT INVESTIGATION
# ============================================================

@app.get("/investigate/{account_id}")
def investigate(
    account_id: str,
    dataset: str = Query(default="demo_synthetic"),
):
    try:
        dataset_id = validate_dataset_id(dataset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    account_id = account_id.strip().upper()
    target_graph = get_graph(dataset_id)

    if dataset_id == "demo_synthetic":
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
            direct_result = target_graph.query(
                direct_query,
                params={"account_id": account_id},
            )

            if not direct_result.result_set:
                raise HTTPException(
                    status_code=404,
                    detail=f"Account {account_id} was not found in dataset '{dataset_id}'.",
                )

            row = direct_result.result_set[0]

            path_result = target_graph.query(
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
            "dataset_id": dataset_id,
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

    elif dataset_id == "ibm_amlsim":
        conn_result = detect_connected_accounts(account_id, dataset_id="ibm_amlsim")
        if conn_result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found in IBM AMLSim dataset.",
            )

        related = [r["account_id"] for r in conn_result.get("related_accounts", [])]
        return {
            "account_id": account_id,
            "dataset_id": dataset_id,
            "risk_label": conn_result["risk_label"],
            "related_accounts": related,
            "shared_devices": [],
            "multi_hop_paths": [],
            "multi_hop_path_count": 0,
            "finding": (
                f"IBM AMLSim account with {conn_result['related_account_count']} counterparty connection(s)."
                if related
                else "No counterparty or alert connections found."
            ),
            "warning": conn_result["warning"],
            "details": conn_result.get("related_accounts", []),
        }


# ============================================================
# TRANSACTION EVIDENCE
# ============================================================

@app.get("/account-evidence/{account_id}")
def account_evidence(
    account_id: str,
    dataset: str = Query(default="demo_synthetic"),
):
    try:
        dataset_id = validate_dataset_id(dataset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    account_id = account_id.strip().upper()

    try:
        ev = get_transaction_evidence(account_id, dataset_id=dataset_id)
        if not ev["found"]:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found in dataset '{dataset_id}'.",
            )

        meta = get_dataset_metadata(dataset_id)
        return {
            "account_id": ev["account_id"],
            "dataset_id": dataset_id,
            "risk_label": ev["risk_label"],
            "transactions": ev["transactions"],
            "transaction_count": ev["transaction_count"],
            "flagged_transaction_count": ev["flagged_transaction_count"],
            "source": ev.get("source"),
            "warning": meta.get("disclaimer", ""),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to query transaction evidence: {exc}",
        ) from exc


# ============================================================
# MULTI-HOP GRAPH EXPLORER
# ============================================================

@app.get("/graph/{account_id}")
def get_account_graph(
    account_id: str,
    hops: int = Query(default=2, ge=1, le=3),
    dataset: str = Query(default="demo_synthetic"),
):
    """Return graph nodes and relationships within the requested hop limit."""
    try:
        dataset_id = validate_dataset_id(dataset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    account_id = account_id.strip().upper()
    target_graph = get_graph(dataset_id)
    acc_label = "AMLAccount" if dataset_id == "ibm_amlsim" else "Account"

    try:
        check = target_graph.query(
            f"MATCH (a:{acc_label} {{id: $account_id}}) RETURN a.id",
            params={"account_id": account_id},
        )

        if not check.result_set:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found in dataset '{dataset_id}'.",
            )

        query = f"""
            MATCH (root:{acc_label} {{id: $account_id}})
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
                    {{
                        id: n.id,
                        labels: labels(n),
                        properties: properties(n)
                    }}
                ] AS nodes,
                [
                    r IN graph_edges |
                    {{
                        source: startNode(r).id,
                        target: endNode(r).id,
                        relationship: type(r)
                    }}
                ] AS edges
        """

        result = target_graph.query(
            query,
            params={
                "account_id": account_id,
                "hops": hops,
            },
        )

        if not result.result_set:
            return {
                "account_id": account_id,
                "dataset_id": dataset_id,
                "hops": hops,
                "nodes": [
                    {"id": account_id, "label": acc_label}
                ],
                "edges": [],
                "node_count": 1,
                "edge_count": 0,
                "source": f"FalkorDB stored relationships ({dataset_id})",
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
            "dataset_id": dataset_id,
            "hops": hops,
            "nodes": list(nodes_by_id.values()),
            "edges": edges,
            "node_count": len(nodes_by_id),
            "edge_count": len(edges),
            "source": f"FalkorDB stored relationships ({dataset_id})",
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to retrieve the multi-hop graph from FalkorDB: {exc}",
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
    dataset: str = Query(default="demo_synthetic"),
):
    """Retrieve historical investigation observations for an account."""
    try:
        dataset_id = validate_dataset_id(dataset)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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
            dataset_id=dataset_id,
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
            detail=f"Unable to retrieve case history from FalkorDB: {exc}",
        ) from exc


# ============================================================
# INVESTIGATION ASSISTANT
# ============================================================

@app.post("/ask")
def ask_investigation(request: AskRequest):
    account_id = request.account_id.strip().upper()
    question = request.question.strip()
    session_id = request.session_id.strip()

    try:
        dataset_id = validate_dataset_id(request.dataset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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
            dataset_id=dataset_id,
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
            detail=f"The investigation assistant could not complete the request: {exc}",
        ) from exc


# ============================================================
# PATH EXPLORER AND GRAPH SEARCH
# ============================================================

@app.get("/paths")
def get_graph_paths(
    source: str = Query(min_length=1, max_length=100),
    target: str = Query(min_length=1, max_length=100),
    hops: int = Query(default=4, ge=1, le=6),
    dataset: str = Query(default="demo_synthetic"),
):
    """Discover real graph paths between any two entities in FalkorDB."""
    try:
        dataset_id = validate_dataset_id(dataset)
        return find_graph_paths(
            source_id=source,
            target_id=target,
            max_hops=hops,
            dataset_id=dataset_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to query graph paths: {exc}",
        ) from exc


@app.get("/clusters")
def get_clusters(dataset: str = Query(default="demo_synthetic")):
    """Discover connected account rings and suspicious clusters."""
    try:
        dataset_id = validate_dataset_id(dataset)
        clusters = detect_suspicious_clusters(dataset_id=dataset_id)
        meta = get_dataset_metadata(dataset_id)
        return {
            "dataset_id": dataset_id,
            "cluster_count": len(clusters),
            "clusters": clusters,
            "warning": meta.get("disclaimer", ""),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to query suspicious clusters: {exc}",
        ) from exc


@app.get("/search")
def search_entities(
    q: str = Query(min_length=1, max_length=100),
    limit: int = Query(default=15, ge=1, le=50),
    dataset: str = Query(default="demo_synthetic"),
):
    """Search graph entities by ID substring."""
    try:
        dataset_id = validate_dataset_id(dataset)
        results = search_graph_entities(
            query_text=q,
            limit=limit,
            dataset_id=dataset_id,
        )
        return {
            "dataset_id": dataset_id,
            "query": q,
            "count": len(results),
            "results": results,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to search graph entities: {exc}",
        ) from exc
