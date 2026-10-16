
from ring_detection import detect_connected_accounts
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("FraudTrace")


def investigate_question(account_id: str, question: str) -> dict:
    """
    Generate an evidence-based investigation response.
    Uses FalkorDB-backed evidence rather than inventing facts.
    """

    account_id = account_id.strip().upper()
    question = question.strip()

    if not account_id or not question:
        return {
            "account_id": account_id,
            "answer": "Please provide an account ID and a question.",
            "evidence": [],
        }

    try:
        # Retrieve actual account transaction evidence.
        transaction_query = """
            MATCH (a:Account {id: $account_id})
            OPTIONAL MATCH (a)-[:MADE]->(t:Transaction)
            OPTIONAL MATCH (t)-[:PAID_TO]->(m:Merchant)
            RETURN a.id AS account_id,
                   a.risk AS risk_label,
                   collect(DISTINCT {
                       transaction_id: t.id,
                       amount: t.amount,
                       status: t.status,
                       merchant_id: m.id
                   }) AS transactions
        """

        result = graph.query(
            transaction_query,
            params={"account_id": account_id},
        )

        if not result.result_set:
            return {
                "account_id": account_id,
                "answer": f"Account {account_id} was not found in the graph.",
                "evidence": [],
            }

        row = result.result_set[0]
        transactions = [
            item for item in (row[2] or [])
            if item and item.get("transaction_id") is not None
        ]

        # Retrieve connected-account signals from FalkorDB.
        network = detect_connected_accounts(account_id)

        if network is None:
            return {
                "account_id": account_id,
                "answer": f"Account {account_id} was not found.",
                "evidence": [],
            }

        evidence = []

        for item in network["related_accounts"]:
            evidence.append({
                "type": "connected_account",
                "account_id": item["account_id"],
                "signals": item["signals"],
                "shared_devices": item["shared_devices"],
                "shared_ips": item["shared_ips"],
                "common_merchants": item["common_merchants"],
                "review_priority": item["review_priority"],
            })

        for transaction in transactions:
            evidence.append({
                "type": "transaction",
                **transaction,
            })

        # Produce a transparent answer from retrieved evidence.
        related_count = network["related_account_count"]
        flagged_count = sum(
            1 for transaction in transactions
            if transaction.get("status") == "flagged"
        )

        answer = (
            f"Investigation of {account_id}: "
            f"{related_count} connected account(s) were found, "
            f"along with {flagged_count} flagged transaction(s) "
            f"in this synthetic dataset. "
        )

        if related_count:
            answer += (
                "Review the shared devices, IP addresses, and merchants "
                "in the evidence list to understand the connections."
            )
        else:
            answer += "No related accounts were found by the current checks."

        answer += (
            " These are investigation leads, not proof of fraud."
        )

        return {
            "account_id": account_id,
            "question": question,
            "answer": answer,
            "evidence": evidence,
            "warning": (
                "This initial assistant uses graph evidence and deterministic "
                "reasoning. It does not yet use a language model."
            ),
        }

    except Exception as exc:
        return {
            "account_id": account_id,
            "answer": "The investigation could not be completed.",
            "error": str(exc),
            "evidence": [],
        }
