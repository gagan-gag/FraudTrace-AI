
from falkordb import FalkorDB
from dataset_registry import get_graph, validate_dataset_id, get_dataset_metadata

def detect_connected_accounts(account_id: str, dataset_id: str = "demo_synthetic"):
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

    if dataset_id == "demo_synthetic":
        # Confirm the account exists.
        account_result = target_graph.query(
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

        result = target_graph.query(query, params={"account_id": account_id})

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

    elif dataset_id == "ibm_amlsim":
        account_result = target_graph.query(
            """
            MATCH (a:AMLAccount {id: $account_id})
            RETURN a.id, a.is_fraud, a.suspicious
            """,
            params={"account_id": account_id},
        )

        if not account_result.result_set:
            return None

        row = account_result.result_set[0]
        is_fraud = bool(row[1])
        suspicious = bool(row[2])
        risk_label = (
            "HIGH (isFraud=True)" if is_fraud
            else "MEDIUM (suspicious=True)" if suspicious
            else "LOW"
        )

        query = """
        MATCH (a:AMLAccount {id: $account_id})
        MATCH (b:AMLAccount)
        WHERE a.id <> b.id

        OPTIONAL MATCH (a)-[:AML_SENT]->(tx_out:AMLTransaction)-[:AML_RECEIVED]->(b)
        WITH a, b, collect(DISTINCT tx_out.id) AS sent_txns

        OPTIONAL MATCH (b)-[:AML_SENT]->(tx_in:AMLTransaction)-[:AML_RECEIVED]->(a)
        WITH a, b, sent_txns, collect(DISTINCT tx_in.id) AS recv_txns

        OPTIONAL MATCH (a)-[:HAS_ALERT]->(al:AMLAlert)<-[:HAS_ALERT]-(b)
        WITH a, b, sent_txns, recv_txns, collect(DISTINCT al.id) AS alerts

        WHERE size(sent_txns) > 0 OR size(recv_txns) > 0 OR size(alerts) > 0

        RETURN b.id AS related_account,
               sent_txns,
               recv_txns,
               alerts,
               b.is_fraud AS b_fraud,
               b.suspicious AS b_suspicious
        ORDER BY related_account
        """
        result = target_graph.query(query, params={"account_id": account_id})

        related_accounts = []
        for r_row in result.result_set:
            related_id, sent_txns, recv_txns, alerts, b_fraud, b_suspicious = r_row
            sent_txns = [x for x in (sent_txns or []) if x is not None]
            recv_txns = [x for x in (recv_txns or []) if x is not None]
            alerts = [x for x in (alerts or []) if x is not None]

            signals = []
            evidence = []

            if sent_txns:
                signals.append("sent_transactions")
                evidence.append(f"Account {account_id} sent {len(sent_txns)} transaction(s) to {related_id}")
            if recv_txns:
                signals.append("received_transactions")
                evidence.append(f"Account {account_id} received {len(recv_txns)} transaction(s) from {related_id}")
            if alerts:
                signals.append("shared_aml_alert")
                evidence.append(f"Both accounts are linked in AML alert(s): {', '.join(alerts)}")
            if b_fraud:
                signals.append("counterparty_is_fraud")
                evidence.append(f"Counterparty account {related_id} is flagged as fraudulent in AMLSim")

            signal_count = len(signals)
            review_priority = (
                "HIGH" if (b_fraud or alerts or signal_count >= 3)
                else "MEDIUM" if signal_count >= 1
                else "REVIEW"
            )

            related_accounts.append({
                "account_id": related_id,
                "signals": signals,
                "signal_count": signal_count,
                "shared_devices": [],
                "shared_ips": [],
                "common_merchants": [],
                "sent_transactions": sent_txns,
                "received_transactions": recv_txns,
                "shared_alerts": alerts,
                "counterparty_is_fraud": bool(b_fraud),
                "evidence": evidence,
                "review_priority": review_priority,
            })

        return {
            "account_id": account_id,
            "risk_label": risk_label,
            "related_account_count": len(related_accounts),
            "related_accounts": related_accounts,
            "warning": (
                "IBM AMLSim transaction simulation data. Device/IP and "
                "merchant relationships are not present in this schema. "
                "Signals reflect transaction counterparties and shared alerts."
            ),
        }

    return None


def find_graph_paths(
    source_id: str,
    target_id: str,
    max_hops: int = 4,
    dataset_id: str = "demo_synthetic",
) -> dict:
    """
    Find real multi-hop paths between two entities in FalkorDB.
    Returns ordered steps, relationship types, and supporting evidence.
    """
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

    source_id = str(source_id or "").strip().upper()
    target_id = str(target_id or "").strip().upper()

    if not source_id or not target_id:
        return {
            "source_id": source_id,
            "target_id": target_id,
            "paths": [],
            "path_count": 0,
            "message": "Both source and target IDs are required.",
        }

    if source_id == target_id:
        return {
            "source_id": source_id,
            "target_id": target_id,
            "paths": [],
            "path_count": 0,
            "message": "Source and target entities are identical.",
        }

    hops = max(1, min(int(max_hops), 6))

    query = """
    MATCH (s {id: $source_id}), (t {id: $target_id})
    WHERE NOT 'InvestigationMemory' IN labels(s)
      AND NOT 'InvestigationMemory' IN labels(t)
    MATCH path = (s)-[*1..6]-(t)
    WHERE length(path) <= $hops
      AND all(n IN nodes(path) WHERE NOT 'InvestigationMemory' IN labels(n))
    RETURN [n IN nodes(path) | {id: n.id, label: labels(n)[0], properties: properties(n)}] AS path_nodes,
           [r IN relationships(path) | {source: startNode(r).id, target: endNode(r).id, type: type(r)}] AS path_edges,
           length(path) AS hops
    ORDER BY hops ASC
    LIMIT 10
    """

    try:
        result = target_graph.query(
            query,
            params={
                "source_id": source_id,
                "target_id": target_id,
                "hops": hops,
            },
        )

        discovered = []
        for row in result.result_set:
            raw_nodes, raw_edges, hop_count = row
            steps = [n.get("id") for n in raw_nodes if isinstance(n, dict)]
            step_labels = [n.get("label", "Unknown") for n in raw_nodes if isinstance(n, dict)]
            relationships = [r.get("type", "CONNECTED") for r in raw_edges if isinstance(r, dict)]

            evidence_items = []
            for i in range(len(steps) - 1):
                s1, s2 = steps[i], steps[i + 1]
                rel = relationships[i] if i < len(relationships) else "CONNECTED"
                evidence_items.append(f"{s1} -[:{rel}]-> {s2}")

            discovered.append({
                "source": source_id,
                "target": target_id,
                "hops": hop_count,
                "steps": steps,
                "step_labels": step_labels,
                "nodes": raw_nodes,
                "relationships": relationships,
                "evidence": evidence_items,
                "summary": " → ".join(steps),
            })

        return {
            "source_id": source_id,
            "target_id": target_id,
            "max_hops": hops,
            "path_count": len(discovered),
            "paths": discovered,
            "message": (
                f"Discovered {len(discovered)} path(s) within {hops} hop(s)."
                if discovered
                else f"No graph connection found between {source_id} and {target_id} within {hops} hop(s)."
            ),
        }
    except Exception as exc:
        raise RuntimeError(f"Graph path query failed: {exc}") from exc


def detect_suspicious_clusters(dataset_id: str = "demo_synthetic") -> list[dict]:
    """
    Discover connected account clusters/rings connected by shared resources or transaction flows.
    Ranks clusters by explainable heuristics without fabricating fraud probabilities.
    """
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

    import networkx as nx

    if dataset_id == "demo_synthetic":
        query = """
        MATCH (a:Account)-[:USES_DEVICE]->(d:Device)<-[:USES_DEVICE]-(b:Account)
        WHERE a.id < b.id
        RETURN a.id AS acc_a, b.id AS acc_b, 'shared_device' AS kind, d.id AS item
        UNION
        MATCH (a:Account)-[:CONNECTS_FROM]->(ip:IPAddress)<-[:CONNECTS_FROM]-(b:Account)
        WHERE a.id < b.id
        RETURN a.id AS acc_a, b.id AS acc_b, 'shared_ip' AS kind, ip.id AS item
        UNION
        MATCH (a:Account)-[:MADE]->(:Transaction)-[:PAID_TO]->(m:Merchant)<-[:PAID_TO]-(:Transaction)<-[:MADE]-(b:Account)
        WHERE a.id < b.id
        RETURN a.id AS acc_a, b.id AS acc_b, 'shared_merchant' AS kind, m.id AS item
        """

        try:
            result = target_graph.query(query)
        except Exception as exc:
            raise RuntimeError(
                f"Unable to query synthetic graph clusters: {exc}"
            ) from exc

        g = nx.Graph()
        link_details = {}

        for row in result.result_set:
            acc_a, acc_b, kind, item = row
            g.add_edge(acc_a, acc_b)
            pair_key = tuple(sorted([acc_a, acc_b]))
            if pair_key not in link_details:
                link_details[pair_key] = {"devices": set(), "ips": set(), "merchants": set()}
            if kind == "shared_device":
                link_details[pair_key]["devices"].add(item)
            elif kind == "shared_ip":
                link_details[pair_key]["ips"].add(item)
            elif kind == "shared_merchant":
                link_details[pair_key]["merchants"].add(item)

        components = list(nx.connected_components(g))
        clusters = []

        for idx, comp in enumerate(components, start=1):
            accounts = sorted(list(comp))
            shared_devices = set()
            shared_ips = set()
            common_merchants = set()

            for a in accounts:
                for b in accounts:
                    if a < b:
                        p = tuple(sorted([a, b]))
                        if p in link_details:
                            shared_devices.update(link_details[p]["devices"])
                            shared_ips.update(link_details[p]["ips"])
                            common_merchants.update(link_details[p]["merchants"])

            # Fetch flagged transactions for accounts in cluster
            flagged_txns = []
            try:
                tx_res = target_graph.query(
                    """
                    MATCH (a:Account)-[:MADE]->(t:Transaction)
                    WHERE a.id IN $accounts AND t.status = 'flagged'
                    RETURN a.id, t.id, t.amount
                    """,
                    params={"accounts": accounts},
                )
                for trow in tx_res.result_set:
                    flagged_txns.append({
                        "account_id": trow[0],
                        "transaction_id": trow[1],
                        "amount": trow[2],
                    })
            except Exception as exc:
                raise RuntimeError(
                    f"Unable to query flagged synthetic transactions: {exc}"
                ) from exc

            heuristic_score = (
                len(accounts) * 15
                + len(shared_devices) * 20
                + len(shared_ips) * 15
                + len(common_merchants) * 10
                + len(flagged_txns) * 15
            )
            heuristic_priority = (
                "HIGH" if heuristic_score >= 60
                else "MEDIUM" if heuristic_score >= 35
                else "REVIEW"
            )

            clusters.append({
                "cluster_id": f"CLUSTER-{idx:02d}",
                "accounts": accounts,
                "account_count": len(accounts),
                "shared_devices": sorted(list(shared_devices)),
                "shared_ips": sorted(list(shared_ips)),
                "common_merchants": sorted(list(common_merchants)),
                "flagged_transactions": flagged_txns,
                "flagged_count": len(flagged_txns),
                "heuristic_priority": heuristic_priority,
                "heuristic_score": min(heuristic_score, 100),
                "explanation": (
                    f"Cluster of {len(accounts)} accounts sharing "
                    f"{len(shared_devices)} device(s), {len(shared_ips)} IP(s), "
                    f"and {len(common_merchants)} merchant(s) with {len(flagged_txns)} flagged transaction(s)."
                ),
            })

        clusters.sort(key=lambda c: (c["heuristic_score"], c["account_count"]), reverse=True)
        return clusters

    elif dataset_id == "ibm_amlsim":
        query = """
        MATCH (a:AMLAccount)-[:AML_SENT]->(t:AMLTransaction)-[:AML_RECEIVED]->(b:AMLAccount)
        WHERE a.id < b.id
        RETURN a.id AS acc_a, b.id AS acc_b, 'transaction_flow' AS kind, t.id AS item
        UNION
        MATCH (a:AMLAccount)-[:HAS_ALERT]->(al:AMLAlert)<-[:HAS_ALERT]-(b:AMLAccount)
        WHERE a.id < b.id
        RETURN a.id AS acc_a, b.id AS acc_b, 'shared_alert' AS kind, al.id AS item
        """
        try:
            result = target_graph.query(query)
        except Exception as exc:
            raise RuntimeError(
                f"Unable to query AMLSim graph clusters: {exc}"
            ) from exc

        g = nx.Graph()
        link_details = {}

        for row in result.result_set:
            acc_a, acc_b, kind, item = row
            g.add_edge(acc_a, acc_b)
            pair_key = tuple(sorted([acc_a, acc_b]))
            if pair_key not in link_details:
                link_details[pair_key] = {"transactions": set(), "alerts": set()}
            if kind == "transaction_flow":
                link_details[pair_key]["transactions"].add(item)
            elif kind == "shared_alert":
                link_details[pair_key]["alerts"].add(item)

        components = list(nx.connected_components(g))
        clusters = []

        for idx, comp in enumerate(components, start=1):
            accounts = sorted(list(comp))
            cluster_txns = set()
            cluster_alerts = set()

            for a in accounts:
                for b in accounts:
                    if a < b:
                        p = tuple(sorted([a, b]))
                        if p in link_details:
                            cluster_txns.update(link_details[p]["transactions"])
                            cluster_alerts.update(link_details[p]["alerts"])

            fraud_accounts = []
            try:
                f_res = target_graph.query(
                    """
                    MATCH (a:AMLAccount)
                    WHERE a.id IN $accounts AND (a.is_fraud = true OR a.suspicious = true)
                    RETURN a.id, a.is_fraud, a.suspicious
                    """,
                    params={"accounts": accounts},
                )
                for frow in f_res.result_set:
                    fraud_accounts.append({
                        "account_id": frow[0],
                        "is_fraud": bool(frow[1]),
                        "suspicious": bool(frow[2]),
                    })
            except Exception as exc:
                raise RuntimeError(
                    f"Unable to query flagged AMLSim accounts: {exc}"
                ) from exc

            heuristic_score = (
                len(accounts) * 10
                + len(cluster_txns) * 10
                + len(cluster_alerts) * 25
                + len(fraud_accounts) * 30
            )
            heuristic_priority = (
                "HIGH" if (fraud_accounts or cluster_alerts or heuristic_score >= 60)
                else "MEDIUM" if heuristic_score >= 30
                else "REVIEW"
            )

            clusters.append({
                "cluster_id": f"AML-CLUSTER-{idx:02d}",
                "accounts": accounts,
                "account_count": len(accounts),
                "shared_devices": [],
                "shared_ips": [],
                "common_merchants": [],
                "transactions": sorted(list(cluster_txns)),
                "alerts": sorted(list(cluster_alerts)),
                "flagged_accounts": fraud_accounts,
                "flagged_count": len(fraud_accounts),
                "flagged_transactions": [{"transaction_id": t} for t in sorted(list(cluster_txns))],
                "heuristic_priority": heuristic_priority,
                "heuristic_score": min(heuristic_score, 100),
                "explanation": (
                    f"AML transaction network of {len(accounts)} accounts with "
                    f"{len(cluster_txns)} transaction link(s), {len(cluster_alerts)} shared alert(s), "
                    f"and {len(fraud_accounts)} flagged fraudulent/suspicious account(s)."
                ),
            })

        clusters.sort(key=lambda c: (c["heuristic_score"], c["account_count"]), reverse=True)
        return clusters

    return []


def search_graph_entities(query_text: str, limit: int = 15, dataset_id: str = "demo_synthetic") -> list[dict]:
    """Search graph nodes by ID substring safely using Cypher parameterization."""
    dataset_id = validate_dataset_id(dataset_id)
    target_graph = get_graph(dataset_id)

    cleaned = str(query_text or "").strip()
    if not cleaned:
        return []

    query = """
    MATCH (n)
    WHERE toUpper(n.id) CONTAINS toUpper($search_term)
      AND NOT 'InvestigationMemory' IN labels(n)
    RETURN n.id AS id, labels(n)[0] AS type, properties(n) AS properties
    LIMIT $limit
    """
    try:
        res = target_graph.query(query, params={"search_term": cleaned, "limit": max(1, min(limit, 50))})
        entities = []
        for row in res.result_set:
            entities.append({
                "id": row[0],
                "type": row[1] if row[1] else "Entity",
                "properties": row[2] if isinstance(row[2], dict) else {},
            })
        return entities
    except Exception as exc:
        raise RuntimeError(f"Unable to search graph entities: {exc}") from exc


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
