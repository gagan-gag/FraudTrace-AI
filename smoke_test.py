
"""
FraudTrace AI — API Smoke Tests
--------------------------------
Checks the running FastAPI service and its FalkorDB-backed
investigation endpoints without modifying graph data.

Run:
    python smoke_test.py

Requirements:
    FastAPI backend running on http://127.0.0.1:8010
    FalkorDB running with the FraudTrace graph seeded
"""

import sys
import os
import uuid
from typing import Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import requests
from dataset_registry import get_graph

BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8010").rstrip("/")
TEST_ACCOUNT = "ACC002"
TIMEOUT_SECONDS = 10

passed = 0
failed = 0


def check(
    name: str,
    condition: bool,
    details: str = "",
) -> None:
    """Record and print one test result."""
    global passed, failed

    if condition:
        passed += 1
        print(f"[PASS] {name}")
        if details:
            print(f"       {details}")
    else:
        failed += 1
        print(f"[FAIL] {name}")
        if details:
            print(f"       {details}")


def get_json(path: str) -> tuple[int, Any]:
    """Make a GET request and return status code and JSON."""
    response = requests.get(
        f"{BASE_URL}{path}",
        timeout=TIMEOUT_SECONDS,
    )

    try:
        data = response.json()
    except ValueError:
        data = {"raw_response": response.text[:500]}

    return response.status_code, data


def post_json(path: str, payload: dict) -> tuple[int, Any]:
    """Make a POST request and return status code and JSON."""
    response = requests.post(
        f"{BASE_URL}{path}",
        json=payload,
        timeout=TIMEOUT_SECONDS,
    )

    try:
        data = response.json()
    except ValueError:
        data = {"raw_response": response.text[:500]}

    return response.status_code, data


def run_tests() -> None:
    print("=" * 60)
    print("       FRAUDTRACE AI — AUTOMATED SMOKE TESTS")
    print("=" * 60)
    print(f"API: {BASE_URL}")
    print(f"Test account: {TEST_ACCOUNT}")
    print()

    # ---------------------------------------------------------
    # 1. API availability
    # ---------------------------------------------------------
    print("--- 1. API Availability ---")

    try:
        status, data = get_json("/")

        check(
            "Root endpoint responds",
            status == 200,
            f"HTTP {status}",
        )

        status, health = get_json("/health")

        check(
            "Health endpoint responds",
            status == 200,
            f"HTTP {status}",
        )

        if status == 200 and isinstance(health, dict):
            check(
                "Health response is JSON",
                bool(health),
                f"Response keys: {list(health.keys())}",
            )

    except requests.RequestException as exc:
        check(
            "API is reachable",
            False,
            f"{exc}\nStart the backend on port 8010 and rerun.",
        )
        print_summary()
        return

    # ---------------------------------------------------------
    # 2. Account investigation
    # ---------------------------------------------------------
    print("\n--- 2. Account Investigation ---")

    try:
        status, investigation = get_json(
            f"/investigate/{TEST_ACCOUNT}"
        )

        check(
            "Investigation endpoint returns HTTP 200",
            status == 200,
            f"HTTP {status}",
        )

        if status == 200 and isinstance(investigation, dict):
            check(
                "Investigation response contains data",
                bool(investigation),
                f"Response keys: {list(investigation.keys())}",
            )

        status, evidence = get_json(
            f"/account-evidence/{TEST_ACCOUNT}"
        )

        check(
            "Account evidence endpoint returns HTTP 200",
            status == 200,
            f"HTTP {status}",
        )

        if status == 200 and isinstance(evidence, dict):
            check(
                "Account evidence response contains data",
                bool(evidence),
                f"Response keys: {list(evidence.keys())}",
            )

    except requests.RequestException as exc:
        check("Investigation endpoints are reachable", False, str(exc))

    # ---------------------------------------------------------
    # 3. FalkorDB multi-hop graph
    # ---------------------------------------------------------
    print("\n--- 3. FalkorDB Graph Traversal ---")

    graph_results = {}

    for depth in (1, 2, 3):
        try:
            status, result = get_json(
                f"/graph/{TEST_ACCOUNT}?hops={depth}"
            )

            check(
                f"Graph traversal at depth {depth}",
                status == 200,
                f"HTTP {status}",
            )

            if status != 200 or not isinstance(result, dict):
                continue

            nodes = result.get("nodes")
            edges = result.get("edges")

            valid_shape = isinstance(nodes, list) and isinstance(
                edges, list
            )

            check(
                f"Depth {depth} returns node and edge lists",
                valid_shape,
            )

            if valid_shape:
                graph_results[depth] = {
                    "nodes": nodes,
                    "edges": edges,
                }

                check(
                    f"Depth {depth} includes the requested account",
                    any(
                        isinstance(node, dict)
                        and str(node.get("id", "")).upper()
                        == TEST_ACCOUNT
                        for node in nodes
                    ),
                )

                check(
                    f"Depth {depth} returns graph nodes",
                    len(nodes) > 0,
                    f"{len(nodes)} nodes, {len(edges)} edges",
                )

                # Validate that graph edges refer to returned nodes.
                node_ids = {
                    node.get("id")
                    for node in nodes
                    if isinstance(node, dict)
                }

                valid_edges = all(
                    isinstance(edge, dict)
                    and edge.get("source") in node_ids
                    and edge.get("target") in node_ids
                    for edge in edges
                )

                check(
                    f"Depth {depth} edges reference returned nodes",
                    valid_edges,
                )

        except requests.RequestException as exc:
            check(
                f"Graph traversal at depth {depth}",
                False,
                str(exc),
            )

    # Larger traversal depths should not lose previously reachable
    # nodes or edges for the same root account.
    if 1 in graph_results and 2 in graph_results:
        ids_1 = {
            node.get("id")
            for node in graph_results[1]["nodes"]
            if isinstance(node, dict)
        }
        ids_2 = {
            node.get("id")
            for node in graph_results[2]["nodes"]
            if isinstance(node, dict)
        }

        check(
            "Depth 2 preserves depth 1 nodes",
            ids_1.issubset(ids_2),
            f"Depth 1: {len(ids_1)} unique nodes; "
            f"depth 2: {len(ids_2)} unique nodes",
        )

    if 2 in graph_results and 3 in graph_results:
        ids_2 = {
            node.get("id")
            for node in graph_results[2]["nodes"]
            if isinstance(node, dict)
        }
        ids_3 = {
            node.get("id")
            for node in graph_results[3]["nodes"]
            if isinstance(node, dict)
        }

        check(
            "Depth 3 preserves depth 2 nodes",
            ids_2.issubset(ids_3),
            f"Depth 2: {len(ids_2)} unique nodes; "
            f"depth 3: {len(ids_3)} unique nodes",
        )

    # ---------------------------------------------------------
    # 4. AI Investigation Assistant
    # ---------------------------------------------------------
    print("\n--- 4. Investigation Assistant ---")

    session_id = f"smoke-test-{uuid.uuid4().hex}"
    try:
        status, answer = post_json(
            "/ask",
            {
                "account_id": TEST_ACCOUNT,
                "question": "Why is this account suspicious?",
                "session_id": session_id,
            },
        )

        check(
            "Assistant endpoint returns HTTP 200",
            status == 200,
            f"HTTP {status}",
        )

        if status == 200 and isinstance(answer, dict):
            check(
                "Assistant returns a structured response",
                bool(answer),
                f"Response keys: {list(answer.keys())}",
            )

            # Do not require a specific schema: check that some
            # response field contains a non-empty answer.
            has_text = any(
                isinstance(value, str) and value.strip()
                for value in answer.values()
            )

            check(
                "Assistant provides a non-empty text response",
                has_text,
            )

    except requests.RequestException as exc:
        check("Assistant endpoint is reachable", False, str(exc))
    finally:
        try:
            get_graph("demo_synthetic").query(
                """
                MATCH (m:InvestigationMemory {session_id: $session_id})
                DETACH DELETE m
                """,
                params={"session_id": session_id},
            )
        except Exception as exc:
            print(f"[WARN] Could not clean up smoke-test memory: {exc}")

    # ---------------------------------------------------------
    # 5. Input validation
    # ---------------------------------------------------------
    print("\n--- 5. Input Validation ---")

    try:
        status, _ = get_json(
            f"/graph/{TEST_ACCOUNT}?hops=99"
        )

        check(
            "Invalid graph depth is rejected",
            status == 422,
            f"Expected HTTP 422, received HTTP {status}",
        )

    except requests.RequestException as exc:
        check("Graph depth validation test", False, str(exc))

    print_summary()


def print_summary() -> None:
    """Print totals and return a failing process exit code."""
    total = passed + failed

    print("\n" + "=" * 60)
    print("                 TEST SUMMARY")
    print("=" * 60)
    print(f"Total checks: {total}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")

    if failed == 0:
        print("\nRESULT: ALL CHECKS PASSED")
        print("FraudTrace AI passed the configured API smoke tests.")
    else:
        print("\nRESULT: SOME CHECKS FAILED")
        print("Review the failing checks before your next demo.")

    print("=" * 60)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    try:
        run_tests()
    except KeyboardInterrupt:
        print("\nTests interrupted.")
        sys.exit(130)
