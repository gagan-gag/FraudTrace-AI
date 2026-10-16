"""Read-only AMLSim API checks, except for a temporary cleaned-up AI memory."""

import os
import uuid

import requests

from dataset_registry import get_graph

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")
ACCOUNT_ID = "AML_ACC_25"
DATASET_ID = "ibm_amlsim"
REQUEST_TIMEOUT = 20


def get_json(session: requests.Session, path: str) -> dict:
    response = session.get(
        f"{API_BASE_URL}{path}",
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError(f"{path} did not return a JSON object.")
    return result


def test_endpoints():
    session_id = f"verify-amlsim-{uuid.uuid4().hex}"
    with requests.Session() as session:
        try:
            health = get_json(session, "/health")
            if health.get("status") != "healthy":
                raise AssertionError("Backend health check failed.")

            stats = get_json(session, f"/dataset-stats/{DATASET_ID}")
            if stats.get("node_counts", {}).get("AMLAccount") != 30:
                raise AssertionError("AMLSim account count is not 30.")
            if stats.get("node_counts", {}).get("AMLTransaction") != 133:
                raise AssertionError("AMLSim transaction count is not 133.")

            search = get_json(
                session,
                f"/search?q={ACCOUNT_ID}&dataset={DATASET_ID}",
            )
            if not any(
                item.get("id") == ACCOUNT_ID
                for item in search.get("results", [])
            ):
                raise AssertionError(f"{ACCOUNT_ID} was not searchable.")

            graph = get_json(
                session,
                f"/graph/{ACCOUNT_ID}?hops=2&dataset={DATASET_ID}",
            )
            if not any(
                item.get("id") == ACCOUNT_ID
                for item in graph.get("nodes", [])
            ):
                raise AssertionError(f"{ACCOUNT_ID} was absent from its graph.")

            investigation = get_json(
                session,
                f"/investigate/{ACCOUNT_ID}?dataset={DATASET_ID}",
            )
            evidence = get_json(
                session,
                f"/account-evidence/{ACCOUNT_ID}?dataset={DATASET_ID}",
            )
            if not any(
                item.get("alert_id") == "AML_ALERT_0"
                for item in evidence.get("alerts", [])
            ):
                raise AssertionError(
                    f"AML_ALERT_0 was not returned for {ACCOUNT_ID}."
                )

            paths = get_json(
                session,
                f"/paths?source=AML_ACC_24&target={ACCOUNT_ID}"
                f"&hops=4&dataset={DATASET_ID}",
            )
            if paths.get("path_count", 0) == 0:
                raise AssertionError("No expected AMLSim account path found.")

            clusters = get_json(session, f"/clusters?dataset={DATASET_ID}")
            ask_response = session.post(
                f"{API_BASE_URL}/ask",
                json={
                    "account_id": ACCOUNT_ID,
                    "question": (
                        "What AML alerts and transactions are associated "
                        "with this account?"
                    ),
                    "session_id": session_id,
                    "dataset_id": DATASET_ID,
                },
                timeout=REQUEST_TIMEOUT,
            )
            ask_response.raise_for_status()
            assistant = ask_response.json()
            if not any(
                item.get("type") == "alert"
                and item.get("alert_id") == "AML_ALERT_0"
                for item in assistant.get("evidence", [])
            ):
                raise AssertionError(
                    "The assistant did not return the linked AML alert evidence."
                )

            print("Health: healthy")
            print(
                f"AMLSim graph: {stats['total_nodes']} nodes, "
                f"{stats['total_relationships']} relationships"
            )
            print(
                f"{ACCOUNT_ID}: {len(graph.get('nodes', []))} graph nodes, "
                f"{evidence.get('transaction_count', 0)} transactions, "
                f"{evidence.get('alert_count', 0)} linked alerts"
            )
            print(
                f"Account search: {search.get('count', 0)} result(s); "
                f"related accounts: {len(investigation.get('related_accounts', []))}"
            )
            print(
                f"Paths: {paths.get('path_count', 0)}; "
                f"clusters: {clusters.get('cluster_count', 0)}; "
                f"assistant evidence: {len(assistant.get('evidence', []))} item(s)"
            )
        finally:
            get_graph(DATASET_ID).query(
                """
                MATCH (m:InvestigationMemory {session_id: $session_id})
                DETACH DELETE m
                """,
                params={"session_id": session_id},
            )


if __name__ == "__main__":
    test_endpoints()
