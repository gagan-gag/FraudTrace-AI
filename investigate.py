
from falkordb import FalkorDB


def main():
    db = FalkorDB(host="localhost", port=6379)
    graph = db.select_graph("FraudTrace")

    query = """
        MATCH
            (a:Account)-[:USES_DEVICE]->(d:Device)
            <-[:USES_DEVICE]-(b:Account)
            -[:CONNECTS_FROM]->(ip:IPAddress)
            <-[:CONNECTS_FROM]-(c:Account)
        WHERE a.id <> b.id
          AND b.id <> c.id
          AND a.id <> c.id
        RETURN DISTINCT a.id, d.id, b.id, ip.id, c.id
        ORDER BY a.id, c.id
    """

    result = graph.query(query)

    print("\n=== FraudTrace AI: Connected Account Investigation ===\n")

    if not result.result_set:
        print("No connected-account patterns found.")
        return

    for row in result.result_set:
        account_a, device, account_b, ip, account_c = row

        print(f"Starting account: {account_a}")
        print(f"  -> shares device {device} with {account_b}")
        print(f"  -> {account_b} shares IP {ip} with {account_c}")
        print("\nFinding: A multi-hop connection exists.")
        print("This is an investigation lead, not proof of fraud.")
        print("-" * 45)


if __name__ == "__main__":
    main()
