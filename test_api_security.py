"""HTTP-level tests for API security controls without graph writes."""

import asyncio
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from amlsim_importer import ImportResult
import app as api_module
import ring_detection

app = api_module.app

ROUTE_SECURITY_CLASSES = {
    ("GET", "/"): "public_metadata",
    ("GET", "/health"): "public_metadata",
    ("GET", "/datasets"): "public_metadata",
    ("GET", "/dataset-stats/{dataset_id}"): "public_metadata",
    ("POST", "/import-amlsim"): "backend_bearer",
    ("GET", "/investigate/{account_id}"): "public_synthetic_demo",
    ("GET", "/account-evidence/{account_id}"): "public_synthetic_demo",
    ("GET", "/graph/{account_id}"): "public_synthetic_demo_filtered",
    ("GET", "/case-history/{account_id}"): "denied_until_case_auth",
    ("POST", "/ask"): "public_synthetic_demo_rate_limited",
    ("GET", "/paths"): "public_synthetic_demo_filtered",
    ("GET", "/clusters"): "public_synthetic_demo",
    ("GET", "/search"): "public_synthetic_demo_filtered",
    ("GET", "/openapi.json"): "public_api_schema",
    ("HEAD", "/openapi.json"): "public_api_schema",
    ("GET", "/docs"): "public_api_schema",
    ("HEAD", "/docs"): "public_api_schema",
    ("GET", "/docs/oauth2-redirect"): "public_api_schema",
    ("HEAD", "/docs/oauth2-redirect"): "public_api_schema",
    ("GET", "/redoc"): "public_api_schema",
    ("HEAD", "/redoc"): "public_api_schema",
}


class ApiSecurityTests(unittest.TestCase):
    """Verify protected import access and public read-only routes."""

    def request(self, method, path, headers=None, body=b""):
        async def send_request():
            body_chunks = body if isinstance(body, list) else [body]
            request_events = [
                {
                    "type": "http.request",
                    "body": chunk,
                    "more_body": index < len(body_chunks) - 1,
                }
                for index, chunk in enumerate(body_chunks)
            ]
            response_events = []

            async def receive():
                if request_events:
                    return request_events.pop(0)
                return {"type": "http.disconnect"}

            async def send(message):
                response_events.append(message)

            request_headers = dict(headers or {})
            raw_headers = [
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in request_headers.items()
            ]
            await app(
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": method,
                    "scheme": "http",
                    "path": path.split("?", 1)[0],
                    "raw_path": path.split("?", 1)[0].encode("ascii"),
                    "query_string": (
                        path.split("?", 1)[1].encode("ascii")
                        if "?" in path
                        else b""
                    ),
                    "root_path": "",
                    "headers": raw_headers,
                    "client": ("testclient", 12345),
                    "server": ("testserver", 80),
                },
                receive,
                send,
            )
            start = next(
                event for event in response_events
                if event["type"] == "http.response.start"
            )
            response_body = b"".join(
                event.get("body", b"")
                for event in response_events
                if event["type"] == "http.response.body"
            )
            return (
                start["status"],
                dict(start["headers"]),
                json.loads(response_body) if response_body else None,
            )

        return asyncio.run(send_request())

    def setUp(self):
        self.rate_limiter_patch = patch(
            "app._ask_rate_limiter",
            api_module.SlidingWindowRateLimiter(
                max_requests=2,
                window_seconds=60,
            ),
        )
        self.rate_limiter_patch.start()
        self.addCleanup(self.rate_limiter_patch.stop)

    @staticmethod
    def successful_import_result():
        return ImportResult(
            success=True,
            accounts_read=0,
            accounts_created=0,
            accounts_updated=0,
            tx_read=0,
            tx_created=0,
            tx_updated=0,
            cash_transactions_read=0,
            cash_transactions_created=0,
            cash_transactions_updated=0,
            alerts_read=0,
            alerts_created=0,
            alerts_updated=0,
            total_created=0,
            total_updated=0,
            total_rejected=0,
        )

    def test_every_registered_route_has_a_security_classification(self):
        registered_routes = {
            (method, route.path)
            for route in app.routes
            for method in (getattr(route, "methods", None) or set())
        }

        self.assertEqual(registered_routes, set(ROUTE_SECURITY_CLASSES))

    def test_public_path_and_search_queries_exclude_case_memory_nodes(self):
        graph = Mock()
        graph.query.return_value = SimpleNamespace(result_set=[])

        with patch("ring_detection.get_graph", return_value=graph):
            ring_detection.find_graph_paths("ACC002", "TXN002")
            path_query = graph.query.call_args.args[0]
            ring_detection.search_graph_entities("ACC")
            search_query = graph.query.call_args.args[0]

        self.assertIn(
            "all(n IN nodes(path) WHERE NOT 'InvestigationMemory' IN labels(n))",
            path_query,
        )
        self.assertIn(
            "NOT 'InvestigationMemory' IN labels(n)",
            search_query,
        )

    def test_import_rejects_missing_or_invalid_bearer_token(self):
        with patch.dict(
            os.environ,
            {"FRAUDTRACE_IMPORT_API_KEY": "test-only-import-token-1234567890"},
        ), patch("amlsim_importer.run_import") as run_import:
            missing_status, missing_headers, _ = self.request(
                "POST",
                "/import-amlsim",
            )
            invalid_status, _, _ = self.request(
                "POST",
                "/import-amlsim",
                {"Authorization": "Bearer invalid-token"},
            )

        self.assertEqual(missing_status, 401)
        self.assertEqual(missing_headers[b"www-authenticate"], b"Bearer")
        self.assertEqual(invalid_status, 401)
        run_import.assert_not_called()

    def test_import_accepts_configured_bearer_token(self):
        token = "test-only-import-token-1234567890"
        with patch.dict(
            os.environ,
            {"FRAUDTRACE_IMPORT_API_KEY": token},
        ), patch(
            "amlsim_importer.run_import",
            return_value=self.successful_import_result(),
        ) as run_import:
            status, _, body = self.request(
                "POST",
                "/import-amlsim?dry_run=true",
                {"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(status, 200)
        self.assertTrue(body["dry_run"])
        run_import.assert_called_once_with(dry_run=True)

    def test_import_failure_does_not_expose_internal_details(self):
        token = "test-only-import-token-1234567890"
        with patch.dict(
            os.environ,
            {"FRAUDTRACE_IMPORT_API_KEY": token},
        ), patch(
            "amlsim_importer.run_import",
            side_effect=RuntimeError("private database connection detail"),
        ):
            status, _, body = self.request(
                "POST",
                "/import-amlsim?dry_run=true",
                {"Authorization": f"Bearer {token}"},
            )

        self.assertEqual(status, 500)
        self.assertEqual(body["detail"], "AMLSim import failed.")
        self.assertNotIn(
            "private database connection detail",
            json.dumps(body),
        )

    def test_import_fails_closed_when_token_is_not_configured(self):
        with patch.dict(os.environ):
            os.environ.pop("FRAUDTRACE_IMPORT_API_KEY", None)
            with patch("amlsim_importer.run_import") as run_import:
                status, _, body = self.request(
                    "POST",
                    "/import-amlsim",
                    {"Authorization": "Bearer any-token"},
                )

        self.assertEqual(status, 503)
        self.assertIn("not configured", body["detail"])
        run_import.assert_not_called()

    def test_dataset_list_remains_public(self):
        status, _, body = self.request("GET", "/datasets")

        self.assertEqual(status, 200)
        self.assertEqual(
            {dataset["dataset_id"] for dataset in body["datasets"]},
            {"demo_synthetic", "ibm_amlsim"},
        )

    def test_case_history_denies_unverified_callers_without_reading_memory(self):
        with patch("app.get_graph") as get_graph:
            responses = [
                self.request("GET", "/case-history/ACC002"),
                self.request(
                    "GET",
                    "/case-history/ACC002?dataset=ibm_amlsim",
                    {"Authorization": "Bearer arbitrary-client-value"},
                ),
            ]

        for status, _, body in responses:
            self.assertEqual(status, 403)
            self.assertEqual(
                body["detail"],
                "Case history requires authenticated identity and "
                "case-specific authorization.",
            )
        get_graph.assert_not_called()

    def test_public_paths_and_search_filter_memory_and_sensitive_properties(self):
        path_response = {
            "path_count": 2,
            "paths": [
                {
                    "nodes": [
                        {
                            "id": "ACC002",
                            "label": "Account",
                            "properties": {
                                "id": "ACC002",
                                "risk": "medium",
                                "customer_id": "private-customer",
                            },
                        },
                        {
                            "id": "MEMORY_1",
                            "label": "InvestigationMemory",
                            "properties": {
                                "question": "private saved question",
                            },
                        },
                    ],
                },
                {
                    "nodes": [
                        {
                            "id": "ACC002",
                            "label": "Account",
                            "properties": {
                                "id": "ACC002",
                                "risk": "medium",
                                "customer_id": "private-customer",
                            },
                        },
                        {
                            "id": "TXN002",
                            "label": "Transaction",
                            "properties": {
                                "id": "TXN002",
                                "amount": 8700,
                                "status": "flagged",
                                "private_note": "private",
                            },
                        },
                    ],
                },
            ],
        }
        search_results = [
            {
                "id": "MEMORY_1",
                "type": "InvestigationMemory",
                "properties": {"question": "private saved question"},
            },
            {
                "id": "ACC002",
                "type": "Account",
                "properties": {
                    "id": "ACC002",
                    "risk": "medium",
                    "customer_id": "private-customer",
                },
            },
        ]

        with (
            patch("app.find_graph_paths", return_value=path_response),
            patch("app.search_graph_entities", return_value=search_results),
        ):
            paths_status, _, paths_body = self.request(
                "GET",
                "/paths?source=ACC002&target=TXN002",
            )
            search_status, _, search_body = self.request(
                "GET",
                "/search?q=ACC",
            )

        self.assertEqual((paths_status, search_status), (200, 200))
        self.assertEqual(paths_body["path_count"], 1)
        self.assertEqual(len(paths_body["paths"]), 1)
        self.assertEqual(
            paths_body["message"],
            "Discovered 1 path(s) within 4 hop(s).",
        )
        self.assertNotIn(
            "MEMORY_1",
            json.dumps(paths_body),
        )
        self.assertEqual(
            paths_body["paths"][0]["nodes"][0]["properties"],
            {"id": "ACC002"},
        )
        self.assertEqual(
            paths_body["paths"][0]["nodes"][1]["properties"],
            {"id": "TXN002", "amount": 8700, "status": "flagged"},
        )
        self.assertEqual(search_body["count"], 1)
        self.assertEqual(
            search_body["results"][0]["properties"],
            {"id": "ACC002"},
        )
        self.assertNotIn("private", json.dumps(paths_body))
        self.assertNotIn("private", json.dumps(search_body))

    def test_public_graph_filters_memory_and_sensitive_properties_by_dataset(self):
        def graph_for(nodes, edges):
            graph = Mock()
            graph.query.side_effect = [
                SimpleNamespace(result_set=[("root",)]),
                SimpleNamespace(result_set=[(nodes, edges)]),
            ]
            return graph

        demo_graph = graph_for(
            [
                {
                    "id": "ACC002",
                    "labels": ["Account"],
                    "properties": {
                        "id": "ACC002",
                        "risk": "medium",
                        "customer_id": "private-customer",
                        "is_fraud": True,
                    },
                },
                {
                    "id": "TXN002",
                    "labels": ["Transaction"],
                    "properties": {
                        "id": "TXN002",
                        "amount": 8700,
                        "status": "flagged",
                        "private_note": "private transaction note",
                    },
                },
                {
                    "id": "MEMORY_DEMO",
                    "labels": ["InvestigationMemory"],
                    "properties": {
                        "id": "MEMORY_DEMO",
                        "question": "private saved question",
                        "answer": "private saved answer",
                        "evidence_json": "private saved evidence",
                    },
                },
            ],
            [
                {
                    "source": "ACC002",
                    "target": "TXN002",
                    "relationship": "MADE",
                },
                {
                    "source": "ACC002",
                    "target": "MEMORY_DEMO",
                    "relationship": "HAS_INVESTIGATION_MEMORY",
                },
            ],
        )
        aml_graph = graph_for(
            [
                {
                    "id": "AML_ACC_25",
                    "labels": ["AMLAccount"],
                    "properties": {
                        "id": "AML_ACC_25",
                        "customer_id": "private-aml-customer",
                        "is_fraud": True,
                    },
                },
                {
                    "id": "AML_ALERT_0",
                    "labels": ["AMLAlert"],
                    "properties": {
                        "id": "AML_ALERT_0",
                        "check_name": "cycle",
                        "pattern": "cycle",
                        "alert_text": "1",
                        "event_date": "2017-02-18",
                        "customer_id": "private-aml-customer",
                    },
                },
                {
                    "id": "MEMORY_AML",
                    "labels": ["InvestigationMemory"],
                    "properties": {
                        "id": "MEMORY_AML",
                        "question": "private AML question",
                    },
                },
            ],
            [
                {
                    "source": "AML_ACC_25",
                    "target": "AML_ALERT_0",
                    "relationship": "HAS_ALERT",
                },
                {
                    "source": "AML_ACC_25",
                    "target": "MEMORY_AML",
                    "relationship": "HAS_INVESTIGATION_MEMORY",
                },
            ],
        )

        with patch(
            "app.get_graph",
            side_effect=[demo_graph, aml_graph],
        ) as get_graph:
            demo_status, _, demo_body = self.request(
                "GET",
                "/graph/ACC002?dataset=demo_synthetic",
            )
            aml_status, _, aml_body = self.request(
                "GET",
                "/graph/AML_ACC_25?dataset=ibm_amlsim",
            )

        self.assertEqual((demo_status, aml_status), (200, 200))
        get_graph.assert_any_call("demo_synthetic")
        get_graph.assert_any_call("ibm_amlsim")

        demo_nodes = {node["id"]: node for node in demo_body["nodes"]}
        self.assertEqual(
            demo_nodes["ACC002"]["properties"],
            {"id": "ACC002"},
        )
        self.assertEqual(
            demo_nodes["TXN002"]["properties"],
            {"id": "TXN002", "amount": 8700, "status": "flagged"},
        )
        self.assertNotIn("MEMORY_DEMO", demo_nodes)
        self.assertEqual(
            [edge["relationship"] for edge in demo_body["edges"]],
            ["MADE"],
        )

        aml_nodes = {node["id"]: node for node in aml_body["nodes"]}
        self.assertEqual(
            aml_nodes["AML_ACC_25"]["properties"],
            {"id": "AML_ACC_25"},
        )
        self.assertEqual(
            aml_nodes["AML_ALERT_0"]["properties"],
            {
                "id": "AML_ALERT_0",
                "check_name": "cycle",
                "pattern": "cycle",
                "alert_text": "1",
                "event_date": "2017-02-18",
            },
        )
        self.assertNotIn("MEMORY_AML", aml_nodes)
        self.assertEqual(
            [edge["relationship"] for edge in aml_body["edges"]],
            ["HAS_ALERT"],
        )

        self.assertNotIn("private", json.dumps(demo_body))
        self.assertNotIn("private", json.dumps(aml_body))

    def test_ask_accepts_requests_within_rate_limit(self):
        payload = json.dumps(
            {
                "account_id": "ACC002",
                "question": "Summarize the account evidence.",
                "session_id": "test-session",
            }
        ).encode("utf-8")

        with patch("app.investigate_question", return_value={"answer": "ok"}) as ask:
            first_status, _, _ = self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                payload,
            )
            second_status, _, _ = self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                payload,
            )

        self.assertEqual(first_status, 200)
        self.assertEqual(second_status, 200)
        self.assertEqual(ask.call_count, 2)
        self.assertFalse(
            ask.call_args.kwargs["include_previous_memories"]
        )

    def test_ask_rejects_requests_exceeding_rate_limit(self):
        payload = json.dumps(
            {
                "account_id": "ACC002",
                "question": "Summarize the account evidence.",
                "session_id": "test-session",
            }
        ).encode("utf-8")

        with patch("app.investigate_question", return_value={"answer": "ok"}) as ask:
            allowed_statuses = [
                self.request(
                    "POST",
                    "/ask",
                    {"Content-Type": "application/json"},
                    payload,
                )[0]
                for _ in range(2)
            ]
            limited_status, headers, body = self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                payload,
            )

        self.assertEqual(allowed_statuses, [200, 200])
        self.assertEqual(limited_status, 429)
        self.assertIn(b"retry-after", headers)
        retry_after = int(headers[b"retry-after"])
        self.assertGreater(retry_after, 0)
        self.assertLessEqual(retry_after, api_module.ASK_RATE_WINDOW_SECONDS)
        self.assertEqual(ask.call_count, 2)
        self.assertNotIn("test-session", json.dumps(body))

    def test_ask_rejects_oversized_body_for_all_content_length_forms(self):
        oversized_body = b"x" * (api_module.ASK_MAX_BODY_BYTES + 1)
        cases = [
            ({}, oversized_body),
            (
                {"Content-Length": str(len(oversized_body))},
                oversized_body,
            ),
            ({"Content-Length": "invalid"}, oversized_body),
            ({"Content-Length": "-1"}, oversized_body),
            (
                {"Transfer-Encoding": "chunked"},
                [
                    b"x" * api_module.ASK_MAX_BODY_BYTES,
                    b"x",
                ],
            ),
        ]
        with patch(
            "app._ask_rate_limiter",
            api_module.SlidingWindowRateLimiter(
                max_requests=len(cases),
                window_seconds=60,
            ),
        ), patch("app.investigate_question") as ask:
            responses = [
                self.request(
                    "POST",
                    "/ask",
                    {
                        "Content-Type": "application/json",
                        **headers,
                    },
                    body,
                )
                for headers, body in cases
            ]

        for status, _, body in responses:
            self.assertEqual(status, 413)
            self.assertEqual(
                body["detail"],
                "Request body exceeds the allowed size.",
            )
        ask.assert_not_called()

    def test_ask_returns_generic_error_without_internal_details(self):
        payload = json.dumps(
            {
                "account_id": "ACC002",
                "question": "Summarize the account evidence.",
                "session_id": "test-session",
            }
        ).encode("utf-8")

        with patch(
            "app.investigate_question",
            side_effect=RuntimeError("sensitive internal details"),
        ):
            status, _, body = self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                payload,
            )

        self.assertEqual(status, 503)
        self.assertEqual(
            body["detail"],
            "The investigation assistant is temporarily unavailable.",
        )
        self.assertNotIn("sensitive internal details", json.dumps(body))

    def test_ask_validation_errors_do_not_echo_submitted_prompt(self):
        marker = "SAFE-TEST-PROMPT-MARKER"
        invalid_question = json.dumps(
            {
                "account_id": "ACC002",
                "question": marker + ("x" * 2001),
                "session_id": "test-session",
            }
        ).encode("utf-8")
        malformed_json = (
            b'{"account_id":"ACC002","question":"' + marker.encode("ascii")
        )

        responses = [
            self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                invalid_question,
            ),
            self.request(
                "POST",
                "/ask",
                {"Content-Type": "application/json"},
                malformed_json,
            ),
        ]

        for status, _, body in responses:
            self.assertEqual(status, 422)
            self.assertEqual(body["detail"], "Invalid assistant request.")
            self.assertNotIn(marker, json.dumps(body))


if __name__ == "__main__":
    unittest.main()
