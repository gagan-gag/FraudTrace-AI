from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("FraudTrace")

for title, query in [
    ("NODE LABELS", "CALL db.labels()"),
    ("RELATIONSHIP TYPES", "CALL db.relationshipTypes()"),
]:
    print(f"\n=== {title} ===")
    result = graph.query(query)
    for row in result.result_set:
        print(row)
