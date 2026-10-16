
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("FraudTrace")


def detect_connected_accounts(account_id: str):
    # Confirm the account exists.
    account_result = graph.query(
        """
        MATCH (a:Account {id: $account_id})
        RETURN a.id, a.risk
        """,
        params={"account_id": account_id},
    )

    if not account_result.result_set:
        return None

    _, risk_label = account_result.result_set[0]

    # Find actual shared entities for each account pair.
    query = """
    MATCH (a:Account {id: $account_id})
    MATCH (b:Account)
    WHERE a.id <> b.id

    OPTIONAL MATCH
        (a)-[:USES_DEVICE]->(d:Device)<-[:USES_DEVICE]-(b)

    WITH a, b, collect(DISTINCT d.id) AS devices

    OPTIONAL MATCH
        (a)-[:CONNECTS_FROM]->(ip:IPAddress)
        <-[:CONNECTS_FROM]-(b)

    WITH a, b, devices, collect(DISTINCT ip.id) AS ips

    OPTIONAL MATCH
        (a)-[:MADE]->(:Transaction)-[:PAID_TO]->(m:Merchant)
        <-[:PAID_TO]-(:Transaction)<-[:MADE]-(b)

    WITH a, b, devices, ips,
         collect(DISTINCT m.id) AS merchants

    WHERE size(devices) > 0
       OR size(ips) > 0
       OR size(merchants) > 0

    RETURN b.id AS related_account,
           devices,
           ips,
           merchants
    ORDER BY related_account
    """

    result = graph.query(query, params={"account_id": account_id})

    related_accounts = []

    for row in result.result_set:
        related_id, devices, ips, merchants = row

        devices = [x for x in (devices or []) if x is not None]
        ips = [x for x in (ips or []) if x is not None]
        merchants = [x for x in (merchants or []) if x is not None]

        signals = []
        evidence = []

        if devices:
            signals.append("shared_device")
            evidence.extend(
                f"Both accounts use device {device}"
                for device in devices
            )

        if ips:
            signals.append("shared_ip")
            evidence.extend(
                f"Both accounts connect from IP {ip}"
                for ip in ips
            )

        if merchants:
            signals.append("shared_merchant")
            evidence.extend(
                f"Both accounts transacted with merchant {merchant}"
                for merchant in merchants
            )

        signal_count = len(signals)

        related_accounts.append({
            "account_id": related_id,
            "signals": signals,
            "signal_count": signal_count,
            "shared_devices": devices,
            "shared_ips": ips,
            "common_merchants": merchants,
            "evidence": evidence,
            "review_priority": (
                "HIGH" if signal_count >= 3
                else "MEDIUM" if signal_count == 2
                else "REVIEW"
            ),
        })

    return {
        "account_id": account_id,
        "risk_label": risk_label,
        "related_account_count": len(related_accounts),
        "related_accounts": related_accounts,
        "warning": (
            "Review priority is a transparent heuristic based on distinct "
            "relationship types, not a calibrated fraud probability. "
            "Shared entities can have legitimate explanations."
        ),
    }


if __name__ == "__main__":
    account_id = input("Enter account ID (example ACC002): ").strip()

    try:
        report = detect_connected_accounts(account_id)

        if report is None:
            print(f"Account {account_id} was not found.")
        else:
            print("\n=== FraudTrace AI: Pair-Specific Evidence ===")
            print(f"Account: {report['account_id']}")
            print(f"Risk label: {report['risk_label']}")
            print(f"Related accounts: {report['related_account_count']}")

            for item in report["related_accounts"]:
                print(f"\nAccount: {item['account_id']}")
                print(f"Review priority: {item['review_priority']}")
                print(f"Signals: {', '.join(item['signals'])}")

                for evidence in item["evidence"]:
                    print(f"  - {evidence}")

            print(f"\nCaution: {report['warning']}")

    except Exception as exc:
        print(f"Graph query failed: {exc}")
        raise
