
"""
FraudTrace AI — Dataset Registry

Server-side allowlist for available datasets.
Provides validated graph connections and metadata.
Never accepts arbitrary graph names from user input.

Database configuration:
    Local development:
        FALKORDB_HOST=localhost
        FALKORDB_PORT=6379

    Cloud deployment:
        Configure FALKORDB_HOST, FALKORDB_PORT,
        and optional FALKORDB_USERNAME/FALKORDB_PASSWORD
        using your hosting provider's environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv(Path(__file__).resolve().parent / ".env")


# ============================================================
# SERVER-SIDE DATASET ALLOWLIST
# ============================================================

DATASET_DEMO_SYNTHETIC = "demo_synthetic"
DATASET_IBM_AMLSIM = "ibm_amlsim"

# Dataset identifier -> FalkorDB graph name.
# Never accept arbitrary graph names directly from user input.
_GRAPH_NAMES: dict[str, str] = {
    DATASET_DEMO_SYNTHETIC: "FraudTrace",
    DATASET_IBM_AMLSIM: "ibm_amlsim",
}

DATASET_ALLOWLIST: frozenset[str] = frozenset(_GRAPH_NAMES.keys())


# ============================================================
# DATASET METADATA
# ============================================================

DATASET_METADATA: dict[str, dict[str, Any]] = {
    DATASET_DEMO_SYNTHETIC: {
        "id": DATASET_DEMO_SYNTHETIC,
        "display_name": "FraudTrace AI Synthetic Demo",
        "source": "FraudTrace AI (synthetic, generated for demonstration)",
        "graph_name": "FraudTrace",
        "description": (
            "Synthetic fraud-investigation graph with accounts, devices, "
            "IP addresses, merchants, and transactions. "
            "6 accounts, 3 devices, 3 IPs, 3 merchants, 5 transactions."
        ),
        "node_labels": [
            "Account",
            "Transaction",
            "Device",
            "IPAddress",
            "Merchant",
            "InvestigationMemory",
        ],
        "relationship_types": [
            "MADE",
            "PAID_TO",
            "USES_DEVICE",
            "CONNECTS_FROM",
            "HAS_INVESTIGATION_MEMORY",
        ],
        "has_device_ip": True,
        "has_merchant": True,
        "has_alerts": False,
        "account_id_prefix": "ACC",
        "transaction_id_prefix": "TXN",
        "disclaimer": (
            "Synthetic demonstration data. Shared devices, IP addresses, "
            "merchants, and flagged transactions are investigation leads, "
            "not proof of fraud."
        ),
    },
    DATASET_IBM_AMLSIM: {
        "id": DATASET_IBM_AMLSIM,
        "display_name": "IBM AMLSim Sample Dataset",
        "source": (
            "IBM AMLSim "
            "(https://github.com/IBM/AMLSim) — synthetic AML simulation"
        ),
        "graph_name": "ibm_amlsim",
        "description": (
            "Synthetic anti-money-laundering simulation data from IBM AMLSim. "
            "Contains accounts, account transfers, cash transactions, "
            "branches, and suspicious-activity alerts. "
            "No device or IP address relationships are present in this dataset."
        ),
        "node_labels": [
            "AMLAccount",
            "AMLTransaction",
            "AMLAlert",
            "AMLBranch",
        ],
        "relationship_types": [
            "AML_SENT",
            "AML_RECEIVED",
            "AML_AT_BRANCH",
            "HAS_ALERT",
            "HAS_INVESTIGATION_MEMORY",
        ],
        "has_device_ip": False,
        "has_merchant": False,
        "has_alerts": True,
        "account_id_prefix": "AML_ACC_",
        "transaction_id_prefix": "AML_TXN_",
        "disclaimer": (
            "IBM AMLSim synthetic data. Suspicious and isFraud labels are "
            "simulation flags, not confirmed criminal findings. "
            "Graph connectivity does not prove a coordinated fraud ring."
        ),
    },
}


# ============================================================
# VALIDATION
# ============================================================

def validate_dataset_id(dataset_id: str | None = None) -> str:
    """
    Validate dataset_id against the server-side allowlist.

    Returns the canonical dataset ID or raises ValueError.
    Missing IDs default to the synthetic demonstration dataset.
    """
    if not dataset_id:
        return DATASET_DEMO_SYNTHETIC

    cleaned = str(dataset_id).strip()

    if not cleaned or cleaned.lower() == "none":
        return DATASET_DEMO_SYNTHETIC

    if cleaned not in _GRAPH_NAMES:
        allowed = ", ".join(sorted(DATASET_ALLOWLIST))
        raise ValueError(
            f"Unknown dataset '{dataset_id}'. "
            f"Allowed values: {allowed}."
        )

    return cleaned


def get_graph_name(dataset_id: str) -> str:
    """Return the graph name associated with a validated dataset ID."""
    dataset_id = validate_dataset_id(dataset_id)
    return _GRAPH_NAMES[dataset_id]


def get_dataset_metadata(dataset_id: str) -> dict[str, Any]:
    """Return metadata for a validated dataset."""
    dataset_id = validate_dataset_id(dataset_id)
    metadata = dict(DATASET_METADATA[dataset_id])
    metadata["dataset_id"] = dataset_id
    return metadata


def list_datasets() -> list[dict[str, Any]]:
    """Return all allowed datasets with metadata."""
    result: list[dict[str, Any]] = []

    for dataset_id in sorted(_GRAPH_NAMES):
        metadata = dict(DATASET_METADATA[dataset_id])
        metadata["dataset_id"] = dataset_id
        result.append(metadata)

    return result


# ============================================================
# GRAPH CONNECTION FACTORY
# ============================================================

_db: FalkorDB | None = None


def _get_db() -> FalkorDB:
    """
    Return a shared, lazy-initialized FalkorDB connection.

    Environment variables:
        FALKORDB_HOST       Hostname; defaults to localhost.
        FALKORDB_PORT       Port; defaults to 6379.
        FALKORDB_USERNAME   Optional username.
        FALKORDB_PASSWORD   Optional password.

    For hosted deployments, configure these variables in the
    backend hosting provider. Do not commit credentials to Git.
    """
    global _db

    if _db is None:
        host = os.getenv("FALKORDB_HOST", "localhost").strip()
        port_value = os.getenv("FALKORDB_PORT", "6379").strip()

        if not host:
            raise ValueError("FALKORDB_HOST cannot be empty.")

        try:
            port = int(port_value)
        except ValueError as exc:
            raise ValueError(
                "FALKORDB_PORT must be a valid integer."
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                "FALKORDB_PORT must be between 1 and 65535."
            )

        username = os.getenv("FALKORDB_USERNAME")
        password = os.getenv("FALKORDB_PASSWORD")

        connection_options: dict[str, Any] = {
            "host": host,
            "port": port,
        }

        if username:
            connection_options["username"] = username

        if password:
            connection_options["password"] = password

        _db = FalkorDB(**connection_options)

    return _db


def get_graph(dataset_id: str | None = None):
    """
    Return a FalkorDB graph for an allowed dataset.

    Dataset identifiers are validated before selecting a graph.
    """
    validated_id = validate_dataset_id(dataset_id)
    graph_name = _GRAPH_NAMES[validated_id]

    return _get_db().select_graph(graph_name)


# ============================================================
# DATASET STATS
# ============================================================

def get_graph_stats(dataset_id: str | None = None) -> dict[str, Any]:
    """
    Query live node and relationship counts for a dataset.

    If a database query fails, return zero counts and include
    the error message for diagnosis.
    """
    validated_id = validate_dataset_id(dataset_id)
    metadata = DATASET_METADATA[validated_id]

    base_result: dict[str, Any] = {
        "dataset_id": validated_id,
        "graph_name": metadata["graph_name"],
        "display_name": metadata["display_name"],
        "total_nodes": 0,
        "total_relationships": 0,
        "node_counts": {},
        "relationship_counts": {},
        "is_empty": True,
        "has_device_ip": metadata["has_device_ip"],
        "has_merchant": metadata["has_merchant"],
        "has_alerts": metadata["has_alerts"],
        "source": metadata["source"],
    }

    try:
        graph = get_graph(validated_id)

        node_result = graph.query(
            "MATCH (n) "
            "RETURN labels(n)[0] AS label, count(n) AS cnt "
            "ORDER BY label"
        )

        node_counts: dict[str, int] = {}
        total_nodes = 0

        for row in node_result.result_set:
            label = row[0] or "Unknown"
            count = int(row[1] or 0)
            node_counts[label] = count
            total_nodes += count

        relationship_result = graph.query(
            "MATCH ()-[r]->() "
            "RETURN type(r) AS t, count(r) AS cnt "
            "ORDER BY t"
        )

        relationship_counts: dict[str, int] = {}
        total_relationships = 0

        for row in relationship_result.result_set:
            relationship_type = row[0] or "Unknown"
            count = int(row[1] or 0)
            relationship_counts[relationship_type] = count
            total_relationships += count

        base_result.update(
            {
                "total_nodes": total_nodes,
                "total_relationships": total_relationships,
                "node_counts": node_counts,
                "relationship_counts": relationship_counts,
                "is_empty": total_nodes == 0 and total_relationships == 0,
            }
        )

        if base_result["is_empty"]:
            base_result["diagnostic"] = (
                f"Dataset '{validated_id}' is connected but currently empty."
            )

        return base_result

    except Exception as exc:
        base_result["error"] = str(exc)
        return base_result
