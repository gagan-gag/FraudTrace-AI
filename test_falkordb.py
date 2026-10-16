
from falkordb import FalkorDB

def main():
    db = FalkorDB(host="localhost", port=6379)
    graph = db.select_graph("FraudTraceTest")

    graph.query("""
        CREATE (:Account {id: 'ACC001', risk: 'high'})
              -[:USES_DEVICE]->
              (:Device {id: 'DEV001'})
    """)

    result = graph.query("""
        MATCH (a:Account)-[:USES_DEVICE]->(d:Device)
        RETURN a.id AS account, a.risk AS risk, d.id AS device
    """)

    for row in result.result_set:
        print(f"Account: {row[0]} | Risk: {row[1]} | Device: {row[2]}")

    print("SUCCESS: Python connected to FalkorDB and queried the graph.")

if __name__ == "__main__":
    main()
