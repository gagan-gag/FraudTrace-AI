import hmac
import os
import threading
import time
from collections import deque

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import Request
from starlette.responses import JSONResponse

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
        "Supports multiple isolated datasets "
        "(FraudTrace synthetic demo & IBM AMLSim) "
        "and persistent investigation memory."
    ),
    version="0.7.0",
)

ASK_RATE_LIMIT = 60
ASK_RATE_WINDOW_SECONDS = 60
ASK_MAX_BODY_BYTES = 16 * 1024

PUBLIC_GRAPH_PROPERTIES = {
    "Account": frozenset({"id"}),
    "AMLAccount": frozenset({"id"}),
    "Device": frozenset({"id"}),
    "IPAddress": frozenset({"id"}),
    "Merchant": frozenset({"id"}),
    "Transaction": frozenset({"id", "amount", "status"}),
    "AMLTransaction": frozenset({"id", "amount", "status"}),
    "AMLAlert": frozenset({
        "id",
        "check_name",
        "pattern",
        "event_date",
        "alert_text",
        "escalated",
    }),
    "AMLBranch": frozenset({"id"}),
}


def _filter_public_graph_properties(
    label: str,
    properties: dict | None,
) -> dict:
    allowed_properties = PUBLIC_GRAPH_PROPERTIES.get(label, frozenset())
    source = properties or {}
    return {
        key: source[key]
        for key in allowed_properties
        if key in source
    }


class SlidingWindowRateLimiter:
    """Process-local rolling-window limiter for the public assistant route."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_times: deque[float] = deque()
        self._lock = threading.Lock()

    def retry_after(self) -> int | None:
        now = time.monotonic()
        with self._lock:
            while (
                self._request_times
                and now - self._request_times[0] >= self.window_seconds
            ):
                self._request_times.popleft()

            if len(self._request_times) >= self.max_requests:
                wait = self.window_seconds - (
                    now - self._request_times[0]
                )
                return max(1, int(wait + 0.999))

            self._request_times.append(now)
            return None

_ask_rate_limiter = SlidingWindowRateLimiter(
    max_requests=ASK_RATE_LIMIT,
    window_seconds=ASK_RATE_WINDOW_SECONDS,
)


class AskProtectionMiddleware:
    """Apply bounded request-size and process-local rate limits to /ask."""

    def __init__(self, app):
        self.downstream_app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or scope["path"] != "/ask"
        ):
            await self.downstream_app(scope, receive, send)
            return

        retry_after = _ask_rate_limiter.retry_after()
        if retry_after is not None:
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        "Too many assistant requests. "
                        "Please try again shortly."
                    )
                },
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > ASK_MAX_BODY_BYTES:
                    await self._body_too_large(scope, receive, send)
                    return
            except ValueError:
                pass

        request_body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return

            chunk = message.get("body", b"")
            if len(request_body) + len(chunk) > ASK_MAX_BODY_BYTES:
                await self._body_too_large(scope, receive, send)
                return
            request_body.extend(chunk)
            if not message.get("more_body", False):
                break

        body_sent = False

        async def replay_body():
            nonlocal body_sent
            if body_sent:
                return {"type": "http.disconnect"}
            body_sent = True
            return {
                "type": "http.request",
                "body": bytes(request_body),
                "more_body": False,
            }

        await self.downstream_app(scope, replay_body, send)

    @staticmethod
    async def _body_too_large(scope, receive, send):
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body exceeds the allowed size."},
        )
        await response(scope, receive, send)


app.add_middleware(AskProtectionMiddleware)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request,
    exc: RequestValidationError,
):
    if request.url.path == "/ask":
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid assistant request."},
        )
    return await request_validation_exception_handler(request, exc)


_import_bearer = HTTPBearer(auto_error=False)


def require_import_authorization(
    credentials: HTTPAuthorizationCredentials | None = Depends(_import_bearer),
) -> None:
    """Require a server-configured bearer token before running data imports."""
    expected_token = os.getenv("FRAUDTRACE_IMPORT_API_KEY")
    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="AMLSim import authentication is not configured.",
        )

    provided_token = (
        credentials.credentials
        if credentials is not None and credentials.scheme.lower() == "bearer"
        else ""
    )
    if not hmac.compare_digest(
        provided_token.encode("utf-8"),
        expected_token.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


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
        demo_graph = get_graph("demo_synthetic")
        demo_graph.query("RETURN 1")

        return {
            "status": "healthy",
            "database": "FalkorDB",
            "graphs": ["FraudTrace", "ibm_amlsim"],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"FalkorDB is not reachable: {exc}",
        ) from exc


# ============================================================
# DATASET MANAGEMENT
# ============================================================

@app.get("/datasets")
def get_datasets():
    """List available datasets and their metadata."""
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
    """Retrieve statistics for a specific dataset."""
    try:
        valid_id = validate_dataset_id(dataset_id)
        stats = get_graph_stats(valid_id)
        if "error" in stats:
            raise HTTPException(
                status_code=503,
                detail=f"Unable to query dataset stats: {stats['error']}",
            )
        return stats

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to query dataset stats: {exc}",
        ) from exc


@app.post("/import-amlsim")
def import_amlsim_dataset(
    dry_run: bool = Query(default=False),
    _: None = Depends(require_import_authorization),
):
    """Trigger the IBM AMLSim CSV import pipeline."""
    try:
        from amlsim_importer import run_import

        stats = run_import(dry_run=dry_run)
        if not stats.get("success"):
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "AMLSim import validation or row processing failed.",
                    "validation_errors": stats.get("validation_errors", []),
                    "total_rejected": stats.get("total_rejected", 0),
                },
            )

        return {
            "status": "success",
            "dry_run": dry_run,
            "target_graph": "ibm_amlsim",
            "stats": {
                "accounts_read": stats.accounts_read,
                "accounts_created": stats.accounts_created,
                "accounts_updated": stats.accounts_updated,
                "tx_read": stats.tx_read,
                "tx_created": stats.tx_created,
                "tx_updated": stats.tx_updated,
                "cash_transactions_read": stats.cash_transactions_read,
                "cash_transactions_created": stats.cash_transactions_created,
                "cash_transactions_updated": stats.cash_transactions_updated,
                "alerts_read": stats.alerts_read,
                "alerts_created": stats.alerts_created,
                "alerts_updated": stats.alerts_updated,
                "total_created": stats.total_created,
                "total_updated": stats.total_updated,
                "total_rejected": stats.total_rejected,
            },
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="AMLSim import failed.",
        )


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
    try:
        target_graph = get_graph(dataset_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to connect to dataset '{dataset_id}': {exc}",
        ) from exc

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
                    detail=(
                        f"Account {account_id} was not found "
                        f"in dataset '{dataset_id}'."
                    ),
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

        try:
            connection_details = detect_connected_accounts(
                account_id,
                dataset_id=dataset_id,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Unable to retrieve connected-account details: {exc}",
            ) from exc

        return {
            "account_id": row[0],
            "dataset_id": dataset_id,
            "risk_label": row[1] or "UNKNOWN",
            "related_accounts": row[2] or [],
            "details": (
                connection_details.get("related_accounts", [])
                if connection_details
                else []
            ),
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
        try:
            conn_result = detect_connected_accounts(
                account_id,
                dataset_id="ibm_amlsim",
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Unable to query IBM AMLSim account evidence: {exc}",
            ) from exc

        if conn_result is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Account {account_id} was not found "
                    "in IBM AMLSim dataset."
                ),
            )

        related = [
            r["account_id"]
            for r in conn_result.get("related_accounts", [])
        ]

        return {
            "account_id": account_id,
            "dataset_id": dataset_id,
            "risk_label": conn_result["risk_label"],
            "related_accounts": related,
            "shared_devices": [],
            "multi_hop_paths": [],
            "multi_hop_path_count": 0,
            "finding": (
                f"IBM AMLSim account with "
                f"{conn_result['related_account_count']} "
                "counterparty connection(s)."
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
        ev = get_transaction_evidence(
            account_id,
            dataset_id=dataset_id,
        )

        if not ev["found"]:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Account {account_id} was not found "
                    f"in dataset '{dataset_id}'."
                ),
            )

        meta = get_dataset_metadata(dataset_id)

        return {
            "account_id": ev["account_id"],
            "dataset_id": dataset_id,
            "risk_label": ev["risk_label"],
            "transactions": ev["transactions"],
            "transaction_count": ev["transaction_count"],
            "flagged_transaction_count": ev["flagged_transaction_count"],
            "alerts": ev.get("alerts", []),
            "alert_count": ev.get("alert_count", 0),
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
    """Return graph nodes and relationships within the hop limit."""
    try:
        dataset_id = validate_dataset_id(dataset)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    account_id = account_id.strip().upper()
    try:
        target_graph = get_graph(dataset_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to connect to dataset '{dataset_id}': {exc}",
        ) from exc

    acc_label = (
        "AMLAccount"
        if dataset_id == "ibm_amlsim"
        else "Account"
    )

    try:
        check = target_graph.query(
            f"MATCH (a:{acc_label} {{id: $account_id}}) RETURN a.id",
            params={"account_id": account_id},
        )

        if not check.result_set:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Account {account_id} was not found "
                    f"in dataset '{dataset_id}'."
                ),
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
                "source": (
                    f"FalkorDB stored relationships ({dataset_id})"
                ),
            }

        raw_nodes, raw_edges = result.result_set[0]
        nodes_by_id = {}
        hidden_node_ids = set()

        for item in raw_nodes or []:
            if not item:
                continue

            node_id = item.get("id")

            if not node_id:
                continue

            labels = item.get("labels") or []
            if "InvestigationMemory" in labels:
                hidden_node_ids.add(node_id)
                continue

            label = labels[0] if labels else "Unknown"

            nodes_by_id[node_id] = {
                "id": node_id,
                "label": label,
                "labels": labels,
                "properties": _filter_public_graph_properties(
                    label,
                    item.get("properties"),
                ),
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

            if (
                source in hidden_node_ids
                or target in hidden_node_ids
                or source not in nodes_by_id
                or target not in nodes_by_id
            ):
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
            "source": (
                f"FalkorDB stored relationships ({dataset_id})"
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Unable to retrieve the multi-hop graph "
                f"from FalkorDB: {exc}"
            ),
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
    """Deny history access until verified identities and case grants exist."""
    raise HTTPException(
        status_code=403,
        detail=(
            "Case history requires authenticated identity and "
            "case-specific authorization."
        ),
    )


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
            include_previous_memories=False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Account {account_id} was not found.",
            )
        if result.get("error"):
            raise HTTPException(
                status_code=503,
                detail="The investigation assistant is temporarily unavailable.",
            )
        if any(
            step.get("step") == "account_lookup"
            and step.get("status") == "account_not_found"
            for step in result.get("investigation_steps", [])
        ):
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Account {account_id} was not found in dataset "
                    f"'{dataset_id}'."
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="The investigation assistant is temporarily unavailable.",
        )


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
    """Discover graph paths between two entities."""
    try:
        dataset_id = validate_dataset_id(dataset)

        result = find_graph_paths(
            source_id=source,
            target_id=target,
            max_hops=hops,
            dataset_id=dataset_id,
        )
        public_paths = [
            path
            for path in result.get("paths", [])
            if not any(
                node.get("label") == "InvestigationMemory"
                for node in path.get("nodes", [])
            )
        ]
        result["paths"] = public_paths
        result["path_count"] = len(public_paths)
        max_hops = result.get("max_hops", hops)
        if public_paths:
            result["message"] = (
                f"Discovered {len(public_paths)} path(s) within "
                f"{max_hops} hop(s)."
            )
        else:
            result["message"] = (
                f"No public graph connection found between {source} and "
                f"{target} within {max_hops} hop(s)."
            )
        for path in public_paths:
            path["nodes"] = [
                {
                    **node,
                    "properties": _filter_public_graph_properties(
                        node.get("label", "Unknown"),
                        node.get("properties"),
                    ),
                }
                for node in path.get("nodes", [])
            ]
        return result

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to query graph paths: {exc}",
        ) from exc


@app.get("/clusters")
def get_clusters(
    dataset: str = Query(default="demo_synthetic"),
):
    """Discover connected account rings and suspicious clusters."""
    try:
        dataset_id = validate_dataset_id(dataset)

        clusters = detect_suspicious_clusters(
            dataset_id=dataset_id,
        )

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
        results = [
            result
            for result in results
            if result.get("type") != "InvestigationMemory"
        ]
        for result in results:
            result["properties"] = _filter_public_graph_properties(
                result.get("type", "Unknown"),
                result.get("properties"),
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