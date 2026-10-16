
from falkordb import FalkorDB


def main():
    db = FalkorDB(host="localhost", port=6379)
    graph = db.select_graph("FraudTrace")

    # Reset only this project's synthetic graph.
    graph.query("MATCH (n) DETACH DELETE n")

    # Create accounts, devices, IP addresses, merchants and transactions.
    graph.query("""
        CREATE
            (a1:Account {id: 'ACC001', risk: 'high'}),
            (a2:Account {id: 'ACC002', risk: 'medium'}),
            (a3:Account {id: 'ACC003', risk: 'high'}),
            (a4:Account {id: 'ACC004', risk: 'low'}),
            (a5:Account {id: 'ACC005', risk: 'medium'}),
            (a6:Account {id: 'ACC006', risk: 'low'}),

            (d1:Device {id: 'DEV001'}),
            (d2:Device {id: 'DEV002'}),
            (d3:Device {id: 'DEV003'}),

            (ip1:IPAddress {id: 'IP001'}),
            (ip2:IPAddress {id: 'IP002'}),
            (ip3:IPAddress {id: 'IP003'}),

            (m1:Merchant {id: 'MER001'}),
            (m2:Merchant {id: 'MER002'}),
            (m3:Merchant {id: 'MER003'}),

            (t1:Transaction {
                id: 'TXN001', amount: 9500, status: 'flagged'
            }),
            (t2:Transaction {
                id: 'TXN002', amount: 8700, status: 'flagged'
            }),
            (t3:Transaction {
                id: 'TXN003', amount: 1200, status: 'normal'
            }),
            (t4:Transaction {
                id: 'TXN004', amount: 7600, status: 'flagged'
            }),
            (t5:Transaction {
                id: 'TXN005', amount: 400, status: 'normal'
            }),

            (a1)-[:USES_DEVICE]->(d1),
            (a2)-[:USES_DEVICE]->(d1),
            (a2)-[:USES_DEVICE]->(d2),
            (a3)-[:USES_DEVICE]->(d2),
            (a4)-[:USES_DEVICE]->(d3),
            (a5)-[:USES_DEVICE]->(d3),
            (a6)-[:USES_DEVICE]->(d2),

            (a1)-[:CONNECTS_FROM]->(ip1),
            (a2)-[:CONNECTS_FROM]->(ip1),
            (a2)-[:CONNECTS_FROM]->(ip2),
            (a3)-[:CONNECTS_FROM]->(ip2),
            (a4)-[:CONNECTS_FROM]->(ip3),
            (a5)-[:CONNECTS_FROM]->(ip3),
            (a6)-[:CONNECTS_FROM]->(ip2),

            (a1)-[:MADE]->(t1),
            (a2)-[:MADE]->(t2),
            (a3)-[:MADE]->(t3),
            (a4)-[:MADE]->(t4),
            (a5)-[:MADE]->(t5),

            (t1)-[:PAID_TO]->(m1),
            (t2)-[:PAID_TO]->(m1),
            (t3)-[:PAID_TO]->(m2),
            (t4)-[:PAID_TO]->(m3),
            (t5)-[:PAID_TO]->(m3)
    """)

    # Count each entity type.
    result = graph.query("""
        MATCH (n)
        RETURN labels(n)[0] AS entity_type, count(n) AS total
        ORDER BY entity_type
    """)

    print("\n=== FraudTrace Synthetic Network ===")
    for row in result.result_set:
        print(f"{row[0]}: {row[1]}")

    # Discover account pairs connected by shared devices.
    result = graph.query("""
        MATCH
            (a:Account)-[:USES_DEVICE]->(d:Device)
            <-[:USES_DEVICE]-(b:Account)
        WHERE a.id < b.id
        RETURN a.id, b.id, d.id
        ORDER BY a.id, b.id
    """)

    print("\n=== Shared-device connections ===")
    for row in result.result_set:
        print(f"{row[0]} <-> {row[1]} via {row[2]}")

    print("\nSynthetic graph created successfully.")


if __name__ == "__main__":
    main()
