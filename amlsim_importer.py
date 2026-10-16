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
import math
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dataset_registry import DATASET_IBM_AMLSIM, get_graph

# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = Path(__file__).parent / "amlsim_data"
ACCOUNTS_FILE = DATA_DIR / "accounts.csv"
TX_FILE = DATA_DIR / "tx.csv"
CASH_TX_FILE = DATA_DIR / "cash_tx.csv"
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
REQUIRED_CASH_TX_COLS = {
    "TXN_ID", "ACCOUNT_ID", "BRANCH_ID",
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
            "start": str(row.get("start", "")).strip(),
            "end": str(row.get("end", "")).strip(),
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
    rows = [
        {
            **props,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        for props in batch
    ]

    try:
        existing_result = graph.query(
            "MATCH (a:AMLAccount) WHERE a.id IN $ids RETURN a.id",
            params={"ids": [row["id"] for row in rows]},
        )
        existing_ids = {
            row[0] for row in existing_result.result_set if row and row[0]
        }

        graph.query(
            """
            UNWIND $rows AS row
            MERGE (a:AMLAccount {id: row.id})
            ON CREATE SET a.created_at = row.created_at
            SET
                a.source_account_id = row.source_account_id,
                a.customer_id = row.customer_id,
                a.init_balance = row.init_balance,
                a.start = row.start,
                a.end = row.end,
                a.country = row.country,
                a.business = row.business,
                a.suspicious = row.suspicious,
                a.is_fraud = row.is_fraud,
                a.model_id = row.model_id,
                a.dataset = row.dataset,
                a.source_label = row.source_label
            """,
            params={"rows": rows},
        )
        stats.updated += sum(row["id"] in existing_ids for row in rows)
        stats.created += sum(row["id"] not in existing_ids for row in rows)
    except Exception as exc:
        stats.rejected += len(rows)
        stats.errors.extend(
            f"Account {row['id']}: {exc}" for row in rows[:5]
        )


def import_transactions(graph, rows: list[dict], dry_run: bool) -> ImportStats:
    """
    Import account-to-account AMLTransaction records.
    """
    stats = ImportStats("transactions")
    prepared = _prepare_transaction_rows(rows, stats, cash=False)
    _write_transaction_batches(graph, prepared, stats, dry_run)
    return stats


def import_cash_transactions(
    graph,
    rows: list[dict],
    dry_run: bool,
) -> ImportStats:
    """Import cash transactions as AMLTransaction nodes with branch links."""
    stats = ImportStats("cash_transactions")
    prepared = _prepare_transaction_rows(rows, stats, cash=True)
    _write_transaction_batches(graph, prepared, stats, dry_run)
    return stats


def _prepare_transaction_rows(
    rows: list[dict],
    stats: ImportStats,
    cash: bool,
) -> list[dict]:
    prepared = []
    for row in rows:
        stats.read += 1
        raw_txn_id = str(row.get("TXN_ID", "")).strip()
        raw_src = str(row.get("ACCOUNT_ID", "")).strip()
        raw_dst = str(row.get("COUNTER_PARTY_ACCOUNT_NUM", "")).strip()
        raw_branch = str(row.get("BRANCH_ID", "")).strip() if cash else ""
        raw_amount = str(row.get("TXN_AMOUNT_ORIG", "")).strip()

        problem = None
        if not raw_txn_id:
            problem = "missing TXN_ID"
        elif not raw_src:
            problem = "missing ACCOUNT_ID"
        elif cash and not raw_branch:
            problem = "missing BRANCH_ID"

        try:
            amount = float(raw_amount)
            if not math.isfinite(amount):
                raise ValueError("amount is not finite")
            if amount < 0:
                raise ValueError("amount is negative")
        except (TypeError, ValueError) as exc:
            problem = problem or f"invalid TXN_AMOUNT_ORIG ({exc})"
            amount = 0.0

        if problem:
            stats.rejected += 1
            stats.errors.append(f"Row {stats.read}: {problem}")
            continue

        tx_type = str(
            row.get("TXN_SOURCE_TYPE_CODE", "UNKNOWN")
        ).strip().upper() or "UNKNOWN"
        prepared.append({
            "id": _txn_id(raw_txn_id),
            "raw_txn_id": raw_txn_id,
            "src_id": _acc_id(raw_src),
            "raw_src": raw_src,
            "dst_id": _acc_id(raw_dst) if raw_dst else None,
            "raw_dst": raw_dst,
            "amount": amount,
            "source_type": tx_type,
            "tx_count": _safe_int(row.get("tx_count", "1"), default=1),
            "step_start": str(row.get("start", "")).strip(),
            "step_end": str(row.get("end", "")).strip(),
            "run_date": str(row.get("RUN_DATE", "")).strip(),
            "branch_id": raw_branch or None,
            "branch_node_id": f"AML_BRANCH_{raw_branch}" if raw_branch else None,
            "cash_transaction": cash,
            "source_file": "cash_tx.csv" if cash else "tx.csv",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return prepared


def _write_transaction_batches(
    graph,
    rows: list[dict],
    stats: ImportStats,
    dry_run: bool,
) -> None:
    if dry_run:
        stats.created += len(rows)
        return

    for offset in range(0, len(rows), BATCH_SIZE):
        batch = rows[offset:offset + BATCH_SIZE]
        ids = [row["id"] for row in batch]
        try:
            existing_result = graph.query(
                "MATCH (t:AMLTransaction) WHERE t.id IN $ids RETURN t.id",
                params={"ids": ids},
            )
            existing_ids = {
                row[0] for row in existing_result.result_set if row and row[0]
            }

            graph.query(
                """
                UNWIND $rows AS row
                MERGE (t:AMLTransaction {id: row.id})
                ON CREATE SET t.created_at = row.created_at
                SET
                    t.source_txn_id = row.raw_txn_id,
                    t.amount = row.amount,
                    t.source_type = row.source_type,
                    t.tx_type = row.source_type,
                    t.tx_count = row.tx_count,
                    t.step_start = row.step_start,
                    t.step_end = row.step_end,
                    t.run_date = row.run_date,
                    t.branch_id = row.branch_id,
                    t.cash_transaction = row.cash_transaction,
                    t.source_file = row.source_file,
                    t.dataset = 'ibm_amlsim',
                    t.status = 'simulated'
                MERGE (src:AMLAccount {id: row.src_id})
                ON CREATE SET
                    src.dataset = 'ibm_amlsim',
                    src.source_account_id = row.raw_src
                MERGE (src)-[:AML_SENT]->(t)
                FOREACH (_ IN CASE WHEN row.dst_id IS NULL THEN [] ELSE [1] END |
                    MERGE (dst:AMLAccount {id: row.dst_id})
                    ON CREATE SET
                        dst.dataset = 'ibm_amlsim',
                        dst.source_account_id = row.raw_dst
                    MERGE (t)-[:AML_RECEIVED]->(dst)
                )
                FOREACH (_ IN CASE WHEN row.branch_node_id IS NULL THEN [] ELSE [1] END |
                    MERGE (branch:AMLBranch {id: row.branch_node_id})
                    ON CREATE SET
                        branch.dataset = 'ibm_amlsim',
                        branch.source_branch_id = row.branch_id
                    MERGE (t)-[:AML_AT_BRANCH]->(branch)
                )
                """,
                params={"rows": batch},
            )
            stats.updated += sum(row["id"] in existing_ids for row in batch)
            stats.created += sum(row["id"] not in existing_ids for row in batch)
        except Exception as exc:
            stats.rejected += len(batch)
            stats.errors.extend(
                f"Transaction {row['raw_txn_id']}: {exc}"
                for row in batch[:5]
            )


def import_alerts(graph, rows: list[dict], dry_run: bool) -> ImportStats:
    """
    Import AMLAlert nodes linked to AMLAccount by HAS_ALERT.
    Idempotent on ALERT_KEY.
    """
    stats = ImportStats("alerts")
    prepared = []

    for row in rows:
        stats.read += 1
        raw_key = str(row.get("ALERT_KEY", "")).strip()
        raw_acc = str(row.get("ACCOUNT_ID", "")).strip()
        if not raw_key or not raw_acc:
            stats.rejected += 1
            stats.errors.append(
                f"Row {stats.read}: missing ALERT_KEY or ACCOUNT_ID"
            )
            continue

        prepared.append({
            "id": _alert_id(raw_key),
            "source_alert_key": raw_key,
            "account_id": _acc_id(raw_acc),
            "source_account_id": raw_acc,
            "customer_id": str(row.get("CUSTOMER_ID", "")).strip(),
            "alert_text": str(row.get("ALERT_TEXT", "")).strip(),
            "check_name": str(row.get("CHECK_NAME", "unknown")).strip(),
            "pattern": str(row.get("CHECK_NAME", "unknown")).strip(),
            "event_date": _parse_date(row.get("EVENT_DATE", "")),
            "organization_type": str(row.get("Organization_Type", "")).strip(),
            "escalated": (
                str(row.get("Escalated_To_Case_Investigation", ""))
                .strip().upper() in ("YES", "TRUE", "1")
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    if dry_run:
        stats.created += len(prepared)
        return stats

    for offset in range(0, len(prepared), BATCH_SIZE):
        batch = prepared[offset:offset + BATCH_SIZE]
        ids = [row["id"] for row in batch]
        try:
            existing_result = graph.query(
                "MATCH (al:AMLAlert) WHERE al.id IN $ids RETURN al.id",
                params={"ids": ids},
            )
            existing_ids = {
                row[0] for row in existing_result.result_set if row and row[0]
            }

            graph.query(
                """
                UNWIND $rows AS row
                MERGE (al:AMLAlert {id: row.id})
                ON CREATE SET al.created_at = row.created_at
                SET
                    al.source_alert_key = row.source_alert_key,
                    al.pattern = row.pattern,
                    al.check_name = row.check_name,
                    al.alert_text = row.alert_text,
                    al.customer_id = row.customer_id,
                    al.event_date = row.event_date,
                    al.organization_type = row.organization_type,
                    al.escalated = row.escalated,
                    al.dataset = 'ibm_amlsim'
                MERGE (a:AMLAccount {id: row.account_id})
                ON CREATE SET
                    a.dataset = 'ibm_amlsim',
                    a.source_account_id = row.source_account_id
                MERGE (a)-[:HAS_ALERT]->(al)
                """,
                params={"rows": batch},
            )
            stats.updated += sum(row["id"] in existing_ids for row in batch)
            stats.created += sum(row["id"] not in existing_ids for row in batch)
        except Exception as exc:
            stats.rejected += len(batch)
            stats.errors.extend(
                f"Alert {row['source_alert_key']}: {exc}"
                for row in batch[:5]
            )

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
    data_dir  : Path to directory containing all four AMLSim CSV files.
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

    # ---- 1. Load and validate all CSVs before opening the graph ----
    acc_rows, acc_errors = _load_csv(data_dir / "accounts.csv", REQUIRED_ACCOUNTS_COLS)
    tx_rows, tx_errors = _load_csv(data_dir / "tx.csv", REQUIRED_TX_COLS)
    cash_rows, cash_errors = _load_csv(
        data_dir / "cash_tx.csv",
        REQUIRED_CASH_TX_COLS,
    )
    alert_rows, alert_errors = _load_csv(data_dir / "alerts.csv", REQUIRED_ALERTS_COLS)

    file_errors: list[str] = (
        acc_errors + tx_errors + cash_errors + alert_errors
    )

    if verbose:
        print(f"[1/5] Files validated:")
        print(f"      accounts.csv : {len(acc_rows)} rows")
        print(f"      tx.csv       : {len(tx_rows)} rows")
        print(f"      cash_tx.csv  : {len(cash_rows)} rows")
        print(f"      alerts.csv   : {len(alert_rows)} rows\n")

    # Validate row-level data before opening the target graph.
    checked_accounts = import_accounts(None, acc_rows, dry_run=True)
    checked_transactions = import_transactions(None, tx_rows, dry_run=True)
    checked_cash = import_cash_transactions(None, cash_rows, dry_run=True)
    checked_alerts = import_alerts(None, alert_rows, dry_run=True)
    checked_stats = [
        checked_accounts,
        checked_transactions,
        checked_cash,
        checked_alerts,
    ]
    validation_errors = file_errors + [
        error
        for stats in checked_stats
        for error in stats.errors
    ]

    if validation_errors:
        for error in validation_errors:
            print(f"  VALIDATION ERROR: {error}", file=sys.stderr)
        return ImportResult({
            "success": False,
            "dry_run": dry_run,
            "graph_name": GRAPH_NAME,
            "validation_errors": validation_errors,
            "accounts": checked_accounts.summary(),
            "transactions": checked_transactions.summary(),
            "cash_transactions": checked_cash.summary(),
            "alerts": checked_alerts.summary(),
            "total_rejected": sum(stats.rejected for stats in checked_stats),
        })

    if dry_run:
        acc_stats = checked_accounts
        tx_stats = checked_transactions
        cash_stats = checked_cash
        alert_stats = checked_alerts
    else:
        graph = get_graph(DATASET_IBM_AMLSIM)

        # ---- 2. Import validated data in idempotent batches ----
        if verbose:
            print("[2/5] Importing accounts ...")
        acc_stats = import_accounts(graph, acc_rows, dry_run=False)
        if verbose:
            print(f"      read={acc_stats.read} created={acc_stats.created} "
                  f"updated={acc_stats.updated} rejected={acc_stats.rejected}")

        if verbose:
            print("[3/5] Importing account transactions ...")
        tx_stats = import_transactions(graph, tx_rows, dry_run=False)
        if verbose:
            print(f"      read={tx_stats.read} created={tx_stats.created} "
                  f"updated={tx_stats.updated} rejected={tx_stats.rejected}")

        if verbose:
            print("[4/5] Importing cash transactions ...")
        cash_stats = import_cash_transactions(graph, cash_rows, dry_run=False)
        if verbose:
            print(f"      read={cash_stats.read} created={cash_stats.created} "
                  f"updated={cash_stats.updated} rejected={cash_stats.rejected}")

        if verbose:
            print("[5/5] Importing alerts ...")
        alert_stats = import_alerts(graph, alert_rows, dry_run=False)
        if verbose:
            print(f"      read={alert_stats.read} created={alert_stats.created} "
                  f"updated={alert_stats.updated} rejected={alert_stats.rejected}")

    total_read = sum(
        stats.read for stats in (
            acc_stats, tx_stats, cash_stats, alert_stats
        )
    )
    total_created = sum(
        stats.created for stats in (
            acc_stats, tx_stats, cash_stats, alert_stats
        )
    )
    total_updated = sum(
        stats.updated for stats in (
            acc_stats, tx_stats, cash_stats, alert_stats
        )
    )
    total_rejected = sum(
        stats.rejected for stats in (
            acc_stats, tx_stats, cash_stats, alert_stats
        )
    )

    result = ImportResult({
        "success": total_rejected == 0,
        "dry_run": dry_run,
        "graph_name": GRAPH_NAME,
        "import_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_read": total_read,
        "total_created": total_created,
        "total_updated": total_updated,
        "total_rejected": total_rejected,
        "accounts_read": acc_stats.read,
        "accounts_created": acc_stats.created,
        "accounts_updated": acc_stats.updated,
        "tx_read": tx_stats.read,
        "tx_created": tx_stats.created,
        "tx_updated": tx_stats.updated,
        "cash_transactions_read": cash_stats.read,
        "cash_transactions_created": cash_stats.created,
        "cash_transactions_updated": cash_stats.updated,
        "transactions_total_read": tx_stats.read + cash_stats.read,
        "alerts_read": alert_stats.read,
        "alerts_created": alert_stats.created,
        "alerts_updated": alert_stats.updated,
        "accounts": acc_stats.summary(),
        "transactions": tx_stats.summary(),
        "cash_transactions": cash_stats.summary(),
        "alerts": alert_stats.summary(),
    })

    if verbose:
        print(f"\n{'='*60}")
        status = (
            "DRY RUN COMPLETE" if dry_run
            else "IMPORT COMPLETE" if result["success"]
            else "IMPORT COMPLETED WITH REJECTIONS"
        )
        print(status)
        print(f"  Total records read:    {total_read}")
        print(f"  Total created:         {total_created}")
        print(f"  Total updated:         {total_updated}")
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
