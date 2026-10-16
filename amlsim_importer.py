"""
FraudTrace AI — IBM AMLSim Graph Importer

Imports IBM AMLSim sample CSVs into the separate 'ibm_amlsim' FalkorDB graph.
- Validates all required columns before touching the graph.
- Normalizes data types and missing values.
- Uses idempotent MERGE upserts to avoid duplicates on repeated runs.
- Prefixes all entity IDs with AML_ACC_ / AML_TXN_ to prevent collisions.
- Preserves original source identifiers as properties for traceability.
- Never imports device or IP relationships (not in AMLSim schema).
- Supports dry-run mode (--dry-run) that does not write to FalkorDB.
- Provides per-category counts: read, created, updated, skipped, rejected.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from falkordb import FalkorDB

# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = Path(__file__).parent / "amlsim_data"
ACCOUNTS_FILE = DATA_DIR / "accounts.csv"
TX_FILE = DATA_DIR / "tx.csv"
ALERTS_FILE = DATA_DIR / "alerts.csv"

GRAPH_NAME = "ibm_amlsim"
BATCH_SIZE = 50

# Required columns per file (validated before import)
REQUIRED_ACCOUNTS_COLS = {
    "ACCOUNT_ID", "PRIMARY_CUSTOMER_ID", "init_balance",
    "suspicious", "isFraud",
}
REQUIRED_TX_COLS = {
    "TXN_ID", "ACCOUNT_ID", "COUNTER_PARTY_ACCOUNT_NUM",
    "TXN_SOURCE_TYPE_CODE", "TXN_AMOUNT_ORIG",
}
REQUIRED_ALERTS_COLS = {
    "ALERT_KEY", "ACCOUNT_ID", "CHECK_NAME", "EVENT_DATE",
}


# ============================================================
# IMPORT STATISTICS
# ============================================================

@dataclass
class ImportStats:
    category: str
    read: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "read": self.read,
            "created": self.created,
            "updated": self.updated,
            "skipped": self.skipped,
            "rejected": self.rejected,
            "error_count": len(self.errors),
            "errors_sample": self.errors[:5],
        }


class ImportResult(dict):
    """Dictionary subclass supporting dot attribute access."""
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


# ============================================================
# HELPERS
# ============================================================

def _acc_id(raw: str) -> str:
    """Namespace-prefix account ID to avoid collisions with synthetic data."""
    return f"AML_ACC_{str(raw).strip()}"


def _txn_id(raw: str) -> str:
    """Namespace-prefix transaction ID."""
    return f"AML_TXN_{str(raw).strip()}"


def _alert_id(raw: str) -> str:
    """Namespace-prefix alert ID."""
    return f"AML_ALERT_{str(raw).strip()}"


def _safe_float(value: str, default: float = 0.0) -> float:
    """Parse a float, returning default on failure."""
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return default


def _safe_int(value: str, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


_safe_bool = _parse_bool


def _parse_date(value: str) -> str:
    """Normalize YYYYMMDD or step-number timestamps to ISO string."""
    v = str(value).strip()
    if len(v) == 8 and v.isdigit():
        try:
            return datetime.strptime(v, "%Y%m%d").date().isoformat()
        except ValueError:
            pass
    return v  # Return as-is for step numbers (1, 2, 3...)


def _load_csv(path: Path, required_cols: set[str]) -> tuple[list[dict], list[str]]:
    """
    Load a CSV file and validate required columns.
    Returns (rows, errors). rows is [] if validation fails.
    """
    if not path.exists():
        return [], [f"File not found: {path}"]

    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return [], [f"Empty or unreadable CSV: {path}"]
            actual_cols = set(reader.fieldnames)
            missing = required_cols - actual_cols
            if missing:
                return [], [f"Missing required columns in {path.name}: {sorted(missing)}"]
            rows = list(reader)
        return rows, []
    except Exception as exc:
        return [], [f"Failed to read {path}: {exc}"]


# ============================================================
# IMPORT PHASES
# ============================================================

def import_accounts(graph, rows: list[dict], dry_run: bool) -> ImportStats:
    """
    MERGE AMLAccount nodes. Idempotent on ACCOUNT_ID.
    Properties: id (namespaced), source_account_id, customer_id,
    init_balance, country, business, suspicious, is_fraud, model_id.
    """
    stats = ImportStats("accounts")
    batch: list[dict] = []

    for row in rows:
        stats.read += 1
        raw_id = str(row.get("ACCOUNT_ID", "")).strip()
        if not raw_id:
            stats.rejected += 1
            stats.errors.append(f"Row {stats.read}: missing ACCOUNT_ID")
            continue

        node_id = _acc_id(raw_id)
        props = {
            "id": node_id,
            "source_account_id": raw_id,
            "customer_id": str(row.get("PRIMARY_CUSTOMER_ID", "")).strip(),
            "init_balance": _safe_float(row.get("init_balance", "0")),
            "country": str(row.get("country", "")).strip(),
            "business": str(row.get("business", "")).strip(),
            "suspicious": _parse_bool(row.get("suspicious", "False")),
            "is_fraud": _parse_bool(row.get("isFraud", "false")),
            "model_id": _safe_int(row.get("modelID", "0")),
            "dataset": "ibm_amlsim",
            "source_label": (
                "suspicious" if _parse_bool(row.get("suspicious", "False"))
                else "normal"
            ),
        }
        batch.append(props)

        if len(batch) >= BATCH_SIZE or stats.read == len(rows):
            if not dry_run and batch:
                _flush_account_batch(graph, batch, stats)
            elif dry_run and batch:
                stats.created += len(batch)
            batch = []

    if not dry_run and batch:
        _flush_account_batch(graph, batch, stats)
    elif dry_run and batch:
        stats.created += len(batch)

    return stats


def _flush_account_batch(graph, batch: list[dict], stats: ImportStats) -> None:
    for props in batch:
        try:
            result = graph.query(
                """
                MERGE (a:AMLAccount {id: $id})
                ON CREATE SET
                    a.source_account_id = $source_account_id,
                    a.customer_id = $customer_id,
                    a.init_balance = $init_balance,
                    a.country = $country,
                    a.business = $business,
                    a.suspicious = $suspicious,
                    a.is_fraud = $is_fraud,
                    a.model_id = $model_id,
                    a.dataset = $dataset,
                    a.source_label = $source_label,
                    a.created_at = $created_at
                ON MATCH SET
                    a.suspicious = $suspicious,
                    a.is_fraud = $is_fraud,
                    a.source_label = $source_label
                RETURN a.id AS id, 1 AS created
                """,
                params={
                    **props,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            if result.result_set:
                stats.created += 1
            else:
                stats.updated += 1
        except Exception as exc:
            stats.rejected += 1
            stats.errors.append(f"Account {props.get('id')}: {exc}")


def import_transactions(graph, rows: list[dict], dry_run: bool) -> ImportStats:
    """
    Import AML_SENT / AML_RECEIVED transaction relationships.
    Each tx row: originator (ACCOUNT_ID) -[AML_SENT]-> (AMLTransaction) -[AML_RECEIVED]-> counterparty.
    Idempotent MERGE on TXN_ID.
    """
    stats = ImportStats("transactions")

    for row in rows:
        stats.read += 1
        raw_txn_id = str(row.get("TXN_ID", "")).strip()
        raw_src = str(row.get("ACCOUNT_ID", "")).strip()
        raw_dst = str(row.get("COUNTER_PARTY_ACCOUNT_NUM", "")).strip()

        if not raw_txn_id:
            stats.rejected += 1
            stats.errors.append(f"Row {stats.read}: missing TXN_ID")
            continue
        if not raw_src:
            stats.rejected += 1
            stats.errors.append(f"Row {stats.read}: missing ACCOUNT_ID in tx {raw_txn_id}")
            continue

        txn_id = _txn_id(raw_txn_id)
        src_id = _acc_id(raw_src)
        dst_id = _acc_id(raw_dst) if raw_dst else None
        amount = _safe_float(row.get("TXN_AMOUNT_ORIG", "0"))
        tx_type = str(row.get("TXN_SOURCE_TYPE_CODE", "UNKNOWN")).strip().upper()
        step_start = str(row.get("start", "")).strip()

        if amount < 0:
            stats.rejected += 1
            stats.errors.append(f"Tx {raw_txn_id}: negative amount {amount}")
            continue

        if dry_run:
            stats.created += 1
            continue

        try:
            graph.query(
                """
                MERGE (t:AMLTransaction {id: $txn_id})
                ON CREATE SET
                    t.source_txn_id = $raw_txn_id,
                    t.amount = $amount,
                    t.tx_type = $tx_type,
                    t.step_start = $step_start,
                    t.dataset = 'ibm_amlsim',
                    t.status = 'simulated'
                """,
                params={
                    "txn_id": txn_id,
                    "raw_txn_id": raw_txn_id,
                    "amount": amount,
                    "tx_type": tx_type,
                    "step_start": step_start,
                },
            )

            # Link originator → transaction (ensure account exists)
            graph.query(
                """
                MERGE (a:AMLAccount {id: $src_id})
                ON CREATE SET a.dataset = 'ibm_amlsim', a.source_account_id = $raw_src
                WITH a
                MATCH (t:AMLTransaction {id: $txn_id})
                MERGE (a)-[:AML_SENT]->(t)
                """,
                params={"src_id": src_id, "raw_src": raw_src, "txn_id": txn_id},
            )

            if dst_id:
                graph.query(
                    """
                    MERGE (b:AMLAccount {id: $dst_id})
                    ON CREATE SET b.dataset = 'ibm_amlsim', b.source_account_id = $raw_dst
                    WITH b
                    MATCH (t:AMLTransaction {id: $txn_id})
                    MERGE (t)-[:AML_RECEIVED]->(b)
                    """,
                    params={"dst_id": dst_id, "raw_dst": raw_dst, "txn_id": txn_id},
                )

            stats.created += 1
        except Exception as exc:
            stats.rejected += 1
            stats.errors.append(f"Tx {raw_txn_id}: {exc}")

    return stats


def import_alerts(graph, rows: list[dict], dry_run: bool) -> ImportStats:
    """
    Import AMLAlert nodes linked to AMLAccount by HAS_ALERT.
    Idempotent on ALERT_KEY.
    """
    stats = ImportStats("alerts")

    for row in rows:
        stats.read += 1
        raw_key = str(row.get("ALERT_KEY", "")).strip()
        raw_acc = str(row.get("ACCOUNT_ID", "")).strip()

        if not raw_key:
            stats.rejected += 1
            stats.errors.append(f"Row {stats.read}: missing ALERT_KEY")
            continue

        alert_id = f"AML_ALERT_{raw_key}"
        acc_id = _acc_id(raw_acc) if raw_acc else None
        pattern = str(row.get("CHECK_NAME", "unknown")).strip()
        event_date = _parse_date(row.get("EVENT_DATE", ""))
        escalated = str(row.get("Escalated_To_Case_Investigation", "")).strip().upper() == "YES"

        if dry_run:
            stats.created += 1
            continue

        try:
            graph.query(
                """
                MERGE (al:AMLAlert {id: $alert_id})
                ON CREATE SET
                    al.source_alert_key = $raw_key,
                    al.pattern = $pattern,
                    al.event_date = $event_date,
                    al.escalated = $escalated,
                    al.dataset = 'ibm_amlsim'
                """,
                params={
                    "alert_id": alert_id,
                    "raw_key": raw_key,
                    "pattern": pattern,
                    "event_date": event_date,
                    "escalated": escalated,
                },
            )

            if acc_id:
                graph.query(
                    """
                    MERGE (a:AMLAccount {id: $acc_id})
                    ON CREATE SET a.dataset = 'ibm_amlsim'
                    WITH a
                    MATCH (al:AMLAlert {id: $alert_id})
                    MERGE (a)-[:HAS_ALERT]->(al)
                    """,
                    params={"acc_id": acc_id, "alert_id": alert_id},
                )

            stats.created += 1
        except Exception as exc:
            stats.rejected += 1
            stats.errors.append(f"Alert {raw_key}: {exc}")

    return stats


# ============================================================
# MAIN IMPORT ENTRY POINT
# ============================================================

def run_import(
    data_dir: Path | None = None,
    dry_run: bool = False,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Execute the full AMLSim import pipeline.

    Parameters
    ----------
    data_dir  : Path to directory containing accounts.csv, tx.csv, alerts.csv.
                Defaults to ./amlsim_data/
    dry_run   : If True, validate and count without writing to FalkorDB.
    verbose   : Print progress if True.

    Returns
    -------
    dict with per-category ImportStats summaries and overall totals.
    """
    if data_dir is None:
        data_dir = DATA_DIR

    data_dir = Path(data_dir)

    if verbose:
        mode = "DRY RUN (no writes)" if dry_run else "LIVE IMPORT"
        print(f"\n{'='*60}")
        print(f"IBM AMLSim Import — {mode}")
        print(f"Data directory: {data_dir}")
        print(f"Target graph:   {GRAPH_NAME}")
        print(f"{'='*60}\n")

    # ---- 1. Load and validate all CSVs ----
    acc_rows, acc_errors = _load_csv(data_dir / "accounts.csv", REQUIRED_ACCOUNTS_COLS)
    tx_rows, tx_errors = _load_csv(data_dir / "tx.csv", REQUIRED_TX_COLS)
    alert_rows, alert_errors = _load_csv(data_dir / "alerts.csv", REQUIRED_ALERTS_COLS)

    validation_errors: list[str] = acc_errors + tx_errors + alert_errors
    if validation_errors:
        for e in validation_errors:
            print(f"  VALIDATION ERROR: {e}", file=sys.stderr)
        return {
            "success": False,
            "dry_run": dry_run,
            "validation_errors": validation_errors,
        }

    if verbose:
        print(f"[1/4] Files validated:")
        print(f"      accounts.csv : {len(acc_rows)} rows")
        print(f"      tx.csv       : {len(tx_rows)} rows")
        print(f"      alerts.csv   : {len(alert_rows)} rows\n")

    # ---- 2. Connect to graph ----
    if not dry_run:
        db = FalkorDB(host="localhost", port=6379)
        graph = db.select_graph(GRAPH_NAME)
    else:
        graph = None

    # ---- 3. Import phases ----
    if verbose:
        print("[2/4] Importing accounts ...")
    acc_stats = import_accounts(graph, acc_rows, dry_run)
    if verbose:
        print(f"      read={acc_stats.read} created={acc_stats.created} "
              f"rejected={acc_stats.rejected}")

    if verbose:
        print("[3/4] Importing transactions ...")
    tx_stats = import_transactions(graph, tx_rows, dry_run)
    if verbose:
        print(f"      read={tx_stats.read} created={tx_stats.created} "
              f"rejected={tx_stats.rejected}")

    if verbose:
        print("[4/4] Importing alerts ...")
    alert_stats = import_alerts(graph, alert_rows, dry_run)
    if verbose:
        print(f"      read={alert_stats.read} created={alert_stats.created} "
              f"rejected={alert_stats.rejected}")

    # ---- 4. Summary ----
    total_read = acc_stats.read + tx_stats.read + alert_stats.read
    total_created = acc_stats.created + tx_stats.created + alert_stats.created
    total_rejected = acc_stats.rejected + tx_stats.rejected + alert_stats.rejected

    result = ImportResult({
        "success": True,
        "dry_run": dry_run,
        "graph_name": GRAPH_NAME,
        "import_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_read": total_read,
        "total_created": total_created,
        "total_rejected": total_rejected,
        "accounts_read": acc_stats.read,
        "accounts_created": acc_stats.created,
        "tx_read": tx_stats.read,
        "tx_created": tx_stats.created,
        "alerts_read": alert_stats.read,
        "alerts_created": alert_stats.created,
        "accounts": acc_stats.summary(),
        "transactions": tx_stats.summary(),
        "alerts": alert_stats.summary(),
    })

    if verbose:
        print(f"\n{'='*60}")
        status = "DRY RUN COMPLETE" if dry_run else "IMPORT COMPLETE"
        print(f"{status}")
        print(f"  Total records read:    {total_read}")
        print(f"  Total created/upserted:{total_created}")
        print(f"  Total rejected:        {total_rejected}")
        if not dry_run:
            print(f"  Graph: {GRAPH_NAME}")
        print(f"{'='*60}\n")

    return result


# ============================================================
# CLI ENTRY POINT
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Import IBM AMLSim sample data into FraudTrace AI (ibm_amlsim graph)."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DATA_DIR),
        help=f"Directory containing AMLSim CSV files (default: {DATA_DIR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and count records without writing to FalkorDB.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output.",
    )
    args = parser.parse_args()

    result = run_import(
        data_dir=Path(args.data_dir),
        dry_run=args.dry_run,
        verbose=not args.quiet,
    )

    if not result.get("success"):
        sys.exit(1)


if __name__ == "__main__":
    main()
