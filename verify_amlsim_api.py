
import requests

def test_endpoints():
    print("--- 1. GET /datasets ---")
    r = requests.get("http://127.0.0.1:8010/datasets")
    print("Status:", r.status_code)
    data = r.json()
    print("Datasets:", [d["dataset_id"] for d in data.get("datasets", [])])

    print("\n--- 2. GET /dataset-stats/ibm_amlsim ---")
    r = requests.get("http://127.0.0.1:8010/dataset-stats/ibm_amlsim")
    print("Status:", r.status_code)
    print("Total nodes:", r.json().get("total_nodes"))

    print("\n--- 3. GET /graph/AML_ACC_25?hops=2&dataset=ibm_amlsim ---")
    r = requests.get("http://127.0.0.1:8010/graph/AML_ACC_25?hops=2&dataset=ibm_amlsim")
    print("Status:", r.status_code)
    g = r.json()
    print(f"AML_ACC_25 graph nodes: {len(g.get('nodes', []))}, edges: {len(g.get('edges', []))}")

    print("\n--- 4. GET /investigate/AML_ACC_25?dataset=ibm_amlsim ---")
    r = requests.get("http://127.0.0.1:8010/investigate/AML_ACC_25?dataset=ibm_amlsim")
    print("Status:", r.status_code)
    inv = r.json()
    print(f"Related accounts: {len(inv.get('related_accounts', []))}, risk: {inv.get('risk_label')}")

    print("\n--- 5. GET /clusters?dataset=ibm_amlsim ---")
    r = requests.get("http://127.0.0.1:8010/clusters?dataset=ibm_amlsim")
    print("Status:", r.status_code)
    cl = r.json()
    print(f"Clusters count: {cl.get('cluster_count')}")

    print("\n--- 6. POST /ask (AMLSim) ---")
    r = requests.post("http://127.0.0.1:8010/ask", json={
        "account_id": "AML_ACC_25",
        "question": "Why is this account suspicious?",
        "session_id": "verify-amlsim",
        "dataset_id": "ibm_amlsim",
    })
    print("Status:", r.status_code)
    ask_res = r.json()
    print("Method:", ask_res.get("answer_method"))
    print("Evidence items:", len(ask_res.get("evidence", [])))
    print("Answer length:", len(ask_res.get("answer", "")))

if __name__ == "__main__":
    test_endpoints()
