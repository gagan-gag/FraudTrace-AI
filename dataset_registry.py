"""
FraudTrace AI — Dataset Registry

Server-side allowlist for available datasets.
Provides validated graph connections and metadata.
Never accepts arbitrary graph names from user input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from falkordb import FalkorDB


# ============================================================
# SERVER-SIDE DATASET ALLOWLIST
# ============================================================

DATASET_DEMO_SYNTHETIC = "demo_synthetic"
DATASET_IBM_AMLSIM = "ibm_amlsim"

# Map dataset identifier → FalkorDB graph name
# This mapping lives server-side only; user input is validated against it.
_GRAPH_NAMES: dict[str, str] = {
    DATASET_DEMO_SYNTHETIC: "FraudTrace",
    DATASET_IBM_AMLSIM: "ibm_amlsim",
}

DATASET_ALLOWLIST: frozenset[str] = frozenset(_GRAPH_NAMES.keys())

# Human-readable dataset metadata
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
        "node_labels": ["Account", "Transaction", "Device", "IPAddress", "Merchant", "InvestigationMemory"],
        "relationship_types": ["MADE", "PAID_TO", "USES_DEVICE", "CONNECTS_FROM", "HAS_INVESTIGATION_MEMORY"],
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
        "source": "IBM AMLSim (https://github.com/IBM/AMLSim) — synthetic AML simulation",
        "graph_name": "ibm_amlsim",
        "description": (
            "Synthetic anti-money-laundering simulation data from IBM AMLSim. "
            "Contains accounts, transactions, and suspicious-activity alerts. "
            "No device or IP address relationships are present in this dataset."
        ),
        "node_labels": ["AMLAccount", "AMLTransaction", "AMLAlert"],
        "relationship_types": ["AML_SENT", "AML_RECEIVED", "HAS_ALERT", "HAS_INVESTIGATION_MEMORY"],
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
    Returns the canonical dataset_id or raises ValueError.
    Never returns an arbitrary graph name from untrusted input.
    """
    if not dataset_id:
        return DATASET_DEMO_SYNTHETIC
    cleaned = str(dataset_id).strip()
    if not cleaned or cleaned.lower() == "none":
        return DATASET_DEMO_SYNTHETIC
    if cleaned not in _GRAPH_NAMES:
        allowed = ", ".join(sorted(_GRAPH_NAMES.keys()))
        raise ValueError(
            f"Unknown dataset '{dataset_id}'. "
            f"Allowed values: {allowed}."
        )
    return cleaned


def get_graph_name(dataset_id: str) -> str:
    """Return the FalkorDB graph name for a validated dataset ID."""
    dataset_id = validate_dataset_id(dataset_id)
    return _GRAPH_NAMES[dataset_id]


def get_dataset_metadata(dataset_id: str) -> dict[str, Any]:
    """Return display metadata for a validated dataset."""
    dataset_id = validate_dataset_id(dataset_id)
    meta = dict(DATASET_METADATA[dataset_id])
    meta["dataset_id"] = dataset_id
    return meta


def list_datasets() -> list[dict[str, Any]]:
    """Return all allowed datasets with metadata."""
    result = []
    for ds_id in sorted(_GRAPH_NAMES.keys()):
        meta = dict(DATASET_METADATA[ds_id])
        meta["dataset_id"] = ds_id
        result.append(meta)
    return result


# ============================================================
# GRAPH CONNECTION FACTORY
# ============================================================

_db: FalkorDB | None = None


def _get_db() -> FalkorDB:
    """Return a shared FalkorDB connection (lazy-initialized)."""
    global _db
    if _db is None:
        _db = FalkorDB(host="localhost", port=6379)
    return _db


def get_graph(dataset_id: str):
    """
    Return a FalkorDB graph object for the validated dataset.
    This is the ONLY entry point for graph connections; it enforces
    the server-side allowlist and never accepts raw graph names.
    """
    validate_dataset_id(dataset_id)
    graph_name = _GRAPH_NAMES[dataset_id]
    return _get_db().select_graph(graph_name)


# ============================================================
# DATASET STATS
# ============================================================

def get_graph_stats(dataset_id: str) -> dict[str, Any]:
    """
    Query live node/relationship counts for a dataset.
    Returns counts per label and total.
    """
    validate_dataset_id(dataset_id)
    g = get_graph(dataset_id)
    meta = DATASET_METADATA[dataset_id]

    try:
        node_result = g.query(
            "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY label"
        )
        node_counts: dict[str, int] = {}
        total_nodes = 0
        for row in node_result.result_set:
            lbl = row[0] or "Unknown"
            cnt = int(row[1] or 0)
            node_counts[lbl] = cnt
            total_nodes += cnt

        rel_result = g.query(
            "MATCH ()-[r]->() RETURN type(r) AS t, count(r) AS cnt ORDER BY t"
        )
        rel_counts: dict[str, int] = {}
        total_rels = 0
        for row in rel_result.result_set:
            t = row[0] or "Unknown"
            cnt = int(row[1] or 0)
            rel_counts[t] = cnt
            total_rels += cnt

        return {
            "dataset_id": dataset_id,
            "graph_name": meta["graph_name"],
            "display_name": meta["display_name"],
            "total_nodes": total_nodes,
            "total_relationships": total_rels,
            "node_counts": node_counts,
            "relationship_counts": rel_counts,
            "has_device_ip": meta["has_device_ip"],
            "has_merchant": meta["has_merchant"],
            "has_alerts": meta["has_alerts"],
            "source": meta["source"],
        }
    except Exception as exc:
        return {
            "dataset_id": dataset_id,
            "graph_name": meta["graph_name"],
            "display_name": meta["display_name"],
            "total_nodes": 0,
            "total_relationships": 0,
            "node_counts": {},
            "relationship_counts": {},
            "error": str(exc),
            "has_device_ip": meta["has_device_ip"],
            "has_merchant": meta["has_merchant"],
            "has_alerts": meta["has_alerts"],
            "source": meta["source"],
        }
