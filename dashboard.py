import requests
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import networkx as nx
import tempfile
import uuid
from pathlib import Path

from ring_detection import detect_connected_accounts
from export_case_report import build_report, get_json, post_json


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8010"

st.set_page_config(
    page_title="FraudTrace AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# API HELPERS
# ============================================================

def api_get(path):
    response = requests.get(
        f"{API_URL}{path}",
        timeout=20,
    )
    response.raise_for_status()
    return response.json()


def create_case_report_pdf(account_id, hops=3):
    """Fetch current API evidence and return a generated case-report PDF."""
    with requests.Session() as session:
        health = get_json(session, API_URL, "/health")
        if not isinstance(health, dict):
            raise ValueError(
                "The API health endpoint returned an invalid response."
            )

        investigation = get_json(
            session, API_URL, f"/investigate/{account_id}"
        )
        account_evidence = get_json(
            session, API_URL, f"/account-evidence/{account_id}"
        )
        graph_data = get_json(
            session, API_URL, f"/graph/{account_id}?hops={hops}"
        )
        assistant = post_json(
            session,
            API_URL,
            "/ask",
            {
                "account_id": account_id,
                "question": "Why is this account suspicious?",
            },
        )

    if not graph_data.get("nodes"):
        raise ValueError(
            f"No graph nodes were returned for {account_id}. "
            "Check that the account exists and the graph is seeded."
        )

    with tempfile.TemporaryDirectory(
        prefix="fraudtrace_report_"
    ) as temp_dir:
        output_path = Path(temp_dir) / f"{account_id}_case_report.pdf"

        build_report(
            output_path=output_path,
            account_id=account_id,
            investigation=investigation,
            account_evidence=account_evidence,
            graph_data=graph_data,
            assistant=assistant,
            hops=hops,
        )

        return output_path.read_bytes()


def render_evidence_items(evidence_items):
    """Display connected-account and transaction evidence."""
    if not evidence_items:
        st.info("No supporting evidence was returned.")
        return

    for item in evidence_items:
        if item.get("type") == "connected_account":
            account = item.get("account_id", "Unknown")
            priority = item.get("review_priority", "REVIEW")

            with st.expander(
                f"{account} — {priority} review priority"
            ):
                st.write(
                    "**Relationship signals:**",
                    ", ".join(item.get("signals") or []) or "None",
                )
                st.write(
                    "**Shared devices:**",
                    ", ".join(item.get("shared_devices") or []) or "None",
                )
                st.write(
                    "**Shared IP addresses:**",
                    ", ".join(item.get("shared_ips") or []) or "None",
                )
                st.write(
                    "**Common merchants:**",
                    ", ".join(item.get("common_merchants") or []) or "None",
                )
                st.caption(
                    "Review priority is a heuristic, not a calibrated "
                    "fraud probability."
                )

        elif item.get("type") == "transaction":
            transaction_id = item.get("transaction_id", "Unknown")

            with st.expander(f"Transaction {transaction_id}"):
                amount = item.get("amount")

                if isinstance(amount, (int, float)):
                    st.write(f"**Amount:** {amount:,.2f}")
                else:
                    st.write(
                        "**Amount:**",
                        amount if amount is not None else "Unavailable",
                    )

                st.write("**Status:**", item.get("status", "Unknown"))
                st.write(
                    "**Merchant:**",
                    item.get("merchant_id", "Unknown"),
                )


# ============================================================
# MULTI-HOP PATH VISUALIZATION
# ============================================================

def render_path_graph(steps):
    """Display one investigation path returned by the API."""
    if not steps:
        st.info("No path is available to visualize.")
        return

    figure = go.Figure()

    x_positions = list(range(len(steps)))
    y_positions = [0] * len(steps)

    for index in range(len(steps) - 1):
        figure.add_trace(
            go.Scatter(
                x=[x_positions[index], x_positions[index + 1]],
                y=[0, 0],
                mode="lines",
                line=dict(color="#94a3b8", width=2),
                hoverinfo="skip",
                showlegend=False,
            )
        )

    node_colors = []

    for node in steps:
        if node.startswith("ACC"):
            node_colors.append("#ef4444")
        elif node.startswith("DEV"):
            node_colors.append("#8b5cf6")
        elif node.startswith("IP"):
            node_colors.append("#06b6d4")
        elif node.startswith("MER"):
            node_colors.append("#f59e0b")
        elif node.startswith("TXN"):
            node_colors.append("#10b981")
        else:
            node_colors.append("#64748b")

    figure.add_trace(
        go.Scatter(
            x=x_positions,
            y=y_positions,
            mode="markers+text",
            text=steps,
            textposition="bottom center",
            marker=dict(size=24, color=node_colors),
            hovertemplate="%{text}<extra></extra>",
            showlegend=False,
        )
    )

    figure.update_layout(
        height=260,
        margin=dict(l=30, r=30, t=20, b=60),
        xaxis=dict(
            visible=False,
            range=[-0.5, len(steps) - 0.5],
        ),
        yaxis=dict(visible=False, range=[-0.8, 0.8]),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(figure, use_container_width=True)


# ============================================================
# MULTI-HOP FALKORDB GRAPH
# ============================================================

def render_stored_graph(account_id, hops=2):
    """
    Display actual nodes and stored relationships returned by
    GET /graph/{account_id}?hops=N.
    """
    try:
        graph_data = api_get(
            f"/graph/{account_id}?hops={hops}"
        )
    except requests.HTTPError as exc:
        st.error(
            f"Graph request failed: {exc.response.status_code} "
            f"- {exc.response.text}"
        )
        return
    except requests.RequestException:
        st.error(
            "Could not retrieve graph data. Check that FastAPI and "
            "FalkorDB are running."
        )
        return

    nodes = graph_data.get("nodes") or []
    edges = graph_data.get("edges") or []

    if not nodes:
        st.info("No graph nodes were returned.")
        return

    graph = nx.Graph()

    for node in nodes:
        node_id = node.get("id")

        if not node_id:
            continue

        graph.add_node(
            node_id,
            node_type=node.get("label", "Unknown"),
            properties=node.get("properties") or {},
        )

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")

        if source in graph and target in graph:
            graph.add_edge(
                source,
                target,
                relationship=edge.get("relationship", "CONNECTED"),
            )

    if graph.number_of_nodes() == 0:
        st.info("No valid graph nodes were returned.")
        return

    # Layered layout
    positions = {}

    row_y = {
        "Account": 6,
        "Device": 3,
        "IPAddress": 0,
        "Transaction": -3,
        "Merchant": -6,
    }

    for node_type, y in row_y.items():
        selected = sorted(
            node
            for node, attrs in graph.nodes(data=True)
            if attrs["node_type"] == node_type
        )

        if not selected:
            continue

        spacing = 4.5
        start_x = -(len(selected) - 1) * spacing / 2

        for index, node in enumerate(selected):
            positions[node] = (
                start_x + index * spacing,
                y,
            )

    unknown_nodes = [
        node
        for node in graph.nodes
        if node not in positions
    ]

    for index, node in enumerate(unknown_nodes):
        positions[node] = (index * 4.5, -9)

    colors = {
        "Account": "#ef4444",
        "Device": "#8b5cf6",
        "IPAddress": "#06b6d4",
        "Merchant": "#f59e0b",
        "Transaction": "#10b981",
        "Unknown": "#64748b",
    }

    figure = go.Figure()

    # Draw stored relationships
    for source, target, attrs in graph.edges(data=True):
        x0, y0 = positions[source]
        x1, y1 = positions[target]

        relationship = attrs.get("relationship", "CONNECTED")

        figure.add_trace(
            go.Scatter(
                x=[x0, x1],
                y=[y0, y1],
                mode="lines",
                line=dict(color="#94a3b8", width=1.5),
                hovertemplate=(
                    f"<b>{source} → {target}</b><br>"
                    f"Relationship: {relationship}"
                    "<extra></extra>"
                ),
                showlegend=False,
            )
        )

    # Draw nodes
    for node_type, color in colors.items():
        selected = [
            node
            for node, attrs in graph.nodes(data=True)
            if attrs["node_type"] == node_type
        ]

        if not selected:
            continue

        hover_details = []

        for node in selected:
            properties = graph.nodes[node].get("properties") or {}

            details = [
                f"ID: {node}",
                f"Type: {node_type}",
            ]

            for key in ("risk", "amount", "status"):
                if key in properties:
                    details.append(
                        f"{key.title()}: {properties[key]}"
                    )

            hover_details.append("<br>".join(details))

        figure.add_trace(
            go.Scatter(
                x=[positions[node][0] for node in selected],
                y=[positions[node][1] for node in selected],
                mode="markers+text",
                text=selected,
                textposition="middle right",
                textfont=dict(size=11),
                marker=dict(
                    size=[
                        32 if node == account_id else 24
                        for node in selected
                    ],
                    color=color,
                    line=dict(color="white", width=1.5),
                ),
                name=node_type,
                customdata=hover_details,
                hovertemplate="%{customdata}<extra></extra>",
            )
        )

    max_x = max(
        (abs(x) for x, _ in positions.values()),
        default=4,
    )
    x_bound = max(10, max_x + 5)

    figure.update_layout(
        title=f"FalkorDB Network — {account_id} ({hops} hop(s))",
        height=700,
        margin=dict(l=40, r=120, t=70, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            visible=False,
            range=[-x_bound, x_bound],
        ),
        yaxis=dict(
            visible=False,
            range=[-8, 8],
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="left",
            x=0,
        ),
        hovermode="closest",
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
        config={
            "displayModeBar": True,
            "scrollZoom": True,
        },
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Hop depth", graph_data.get("hops", hops))
    col2.metric("Nodes", graph_data.get("node_count", len(nodes)))
    col3.metric("Relationships", graph_data.get("edge_count", len(edges)))

    st.caption(
        "Source: FalkorDB stored relationships. The graph displays "
        "the subgraph returned for the selected hop depth. Shared "
        "entities and flagged transactions are investigation leads, "
        "not proof of fraud."
    )

    with st.expander("Inspect graph nodes"):
        node_rows = [
            {
                "ID": node.get("id"),
                "Type": node.get("label"),
                "Properties": str(node.get("properties") or {}),
            }
            for node in nodes
        ]

        st.dataframe(
            pd.DataFrame(node_rows),
            use_container_width=True,
            hide_index=True,
        )

    with st.expander("Inspect stored relationships"):
        if edges:
            st.dataframe(
                pd.DataFrame(edges),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No stored relationships were returned.")


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    st.title("🛡️ FraudTrace AI")
    st.caption("Graph-powered fraud investigation")

    st.divider()
    st.subheader("Investigation")

    account_id = st.text_input(
        "Account ID",
        value="ACC001",
        key="main_account_id",
        placeholder="Example: ACC002",
    ).strip().upper()

    investigate_clicked = st.button(
        "Investigate account",
        type="primary",
        use_container_width=True,
    )

    st.divider()
    st.caption("Backend: FastAPI · Port 8010")
    st.caption("Graph database: FalkorDB")
    st.caption("Synthetic demonstration data")


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ FraudTrace AI")
st.caption("GRAPH-POWERED FRAUD INVESTIGATION · FALKORDB")

st.info(
    "Investigate connected accounts, devices, IP addresses, merchants, "
    "and transactions. Connections and transaction flags are clues, "
    "not proof of fraud."
)


# ============================================================
# SESSION STATE
# ============================================================

if "investigation_data" not in st.session_state:
    st.session_state.investigation_data = None

if "transaction_data" not in st.session_state:
    st.session_state.transaction_data = None

if "investigation_account" not in st.session_state:
    st.session_state.investigation_account = None

if "case_report_pdf" not in st.session_state:
    st.session_state.case_report_pdf = None

if "case_report_account" not in st.session_state:
    st.session_state.case_report_account = None

if "case_report_hops" not in st.session_state:
    st.session_state.case_report_hops = None


# ============================================================
# RUN INVESTIGATION
# ============================================================

if investigate_clicked:
    if not account_id:
        st.warning("Enter an account ID first.")
    else:
        try:
            with st.spinner("Querying FalkorDB..."):
                investigation = api_get(
                    f"/investigate/{account_id}"
                )
                transactions = api_get(
                    f"/account-evidence/{account_id}"
                )

            st.session_state.investigation_data = investigation
            st.session_state.transaction_data = transactions
            st.session_state.investigation_account = account_id

        except requests.HTTPError as exc:
            st.session_state.investigation_data = None
            st.session_state.transaction_data = None
            st.error(
                f"Investigation request failed: {exc.response.text}"
            )

        except requests.RequestException:
            st.error(
                "Cannot connect to FastAPI. "
                "Start the backend on port 8010."
            )


# ============================================================
# INVESTIGATION REPORT
# ============================================================

data = st.session_state.investigation_data
transaction_data = st.session_state.transaction_data

if data:
    report_account = data["account_id"]

    st.header(f"Investigation Report: {report_account}")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Account", report_account)
    col2.metric("Risk label", data.get("risk_label") or "Unknown")
    col3.metric(
        "Direct connections",
        len(data.get("related_accounts") or []),
    )
    col4.metric(
        "Multi-hop paths",
        data.get("multi_hop_path_count", 0),
    )

    st.divider()

    # Connected accounts
    st.subheader("Connected Accounts")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Accounts returned by the investigation**")

        connected = data.get("related_accounts") or []

        if connected:
            for item in connected:
                st.write(f"• {item}")
        else:
            st.write("No directly connected accounts found.")

    with col2:
        st.markdown("**Shared devices**")

        devices = data.get("shared_devices") or []

        if devices:
            for device in devices:
                st.write(f"• {device}")
        else:
            st.write("No shared devices found.")

    # Multi-hop paths
    st.subheader("Multi-hop Network Investigation")

    paths = data.get("multi_hop_paths") or []

    if paths:
        path_labels = [
            (
                f"{path.get('start_account')} → "
                f"{path.get('connected_account')} "
                f"(via {path.get('intermediary_account')})"
            )
            for path in paths
        ]

        selected_index = st.selectbox(
            "Select a discovered path",
            options=list(range(len(paths))),
            format_func=lambda index: path_labels[index],
        )

        selected_path = paths[selected_index]

        st.markdown("**Evidence path**")
        st.code(" → ".join(selected_path.get("steps") or []))

        render_path_graph(selected_path.get("steps") or [])

        st.markdown("**Evidence discovered**")

        for evidence_item in selected_path.get("evidence") or []:
            st.write(f"• {evidence_item}")
    else:
        st.info("No multi-hop paths were found for this account.")

    st.divider()

    # Transaction evidence
    st.subheader("Transaction Evidence")

    if transaction_data:
        col1, col2, col3 = st.columns(3)

        total = transaction_data.get("transaction_count", 0)
        flagged = transaction_data.get("flagged_transaction_count", 0)

        col1.metric("Transactions", total)
        col2.metric("Flagged transactions", flagged)
        col3.metric("Other transactions", max(0, total - flagged))

        transaction_rows = transaction_data.get("transactions") or []

        if transaction_rows:
            st.dataframe(
                pd.DataFrame(transaction_rows),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No transaction records were found.")

        st.caption(
            "Transaction flags in this synthetic dataset are "
            "investigation clues, not proof of fraud."
        )

    st.divider()

    # Interactive multi-hop graph
    st.subheader("Interactive FalkorDB Graph")

    graph_hops = st.select_slider(
        "Graph exploration depth",
        options=[1, 2, 3],
        value=2,
        key="graph_hops",
        help=(
            "One hop shows direct neighbors. Greater depths include "
            "additional connected entities."
        ),
    )

    render_stored_graph(report_account, hops=graph_hops)

    st.divider()

    # Connected-account risk signals
    st.subheader("Connected Account Risk Signals")

    try:
        with st.spinner("Analyzing connected-account signals..."):
            network_data = detect_connected_accounts(report_account)

        if network_data is None:
            st.info("Account not found in the graph.")
        else:
            related = network_data.get("related_accounts") or []

            if related:
                summary_rows = [
                    {
                        "Related account": item["account_id"],
                        "Review priority": item["review_priority"],
                        "Signal count": item["signal_count"],
                        "Shared devices": ", ".join(
                            item.get("shared_devices") or []
                        ) or "—",
                        "Shared IPs": ", ".join(
                            item.get("shared_ips") or []
                        ) or "—",
                        "Common merchants": ", ".join(
                            item.get("common_merchants") or []
                        ) or "—",
                    }
                    for item in related
                ]

                st.dataframe(
                    pd.DataFrame(summary_rows),
                    use_container_width=True,
                    hide_index=True,
                )

                st.markdown("**Inspect evidence by account**")

                for item in related:
                    with st.expander(
                        f"{item['account_id']} — "
                        f"{item['review_priority']} review priority"
                    ):
                        st.write(
                            "**Signals:**",
                            ", ".join(item.get("signals") or []) or "None",
                        )

                        for entry in item.get("evidence") or []:
                            st.write(f"• {entry}")

                st.caption(network_data.get("warning", ""))
            else:
                st.info("No related accounts matched the current checks.")

    except Exception as exc:
        st.warning(
            "Connected-account risk signals could not be loaded. "
            "Check that FalkorDB is running."
        )
        st.caption(str(exc))

    st.divider()


    # ============================================================
    # INVESTIGATION FINDING — EVIDENCE-BACKED SUMMARY
    # ============================================================

    st.divider()
    st.subheader("Investigation Finding")

    finding_text = data.get("finding") or "No finding available."

    warning_text = (
        data.get("warning")
        or (
            "Connections are investigation leads, not proof of fraud. "
            "Shared devices and IP addresses can have legitimate explanations."
        )
    )

    # Reuse the connected-account analysis already performed above.
    network_data_for_finding = (
        network_data if "network_data" in locals() and network_data else {}
    )

    related_accounts_for_finding = (
        network_data_for_finding.get("related_accounts") or []
    )

    # Index actual evidence by account ID.
    related_by_id = {
        str(item["account_id"]): item
        for item in related_accounts_for_finding
        if item.get("account_id")
    }

    investigation_related_ids = [
        str(item)
        for item in (data.get("related_accounts") or [])
        if item
    ]

    network_related_ids = [
        str(item["account_id"])
        for item in related_accounts_for_finding
        if item.get("account_id")
    ]

    related_ids = list(
        dict.fromkeys(
            investigation_related_ids + network_related_ids
        )
    )

    # Derive priority only from values returned by the analysis.
    priority_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    known_priorities = [
        str(item.get("review_priority", "")).strip().upper()
        for item in related_accounts_for_finding
        if str(item.get("review_priority", "")).strip().upper()
        in priority_rank
    ]

    highest_priority = (
        max(known_priorities, key=lambda priority: priority_rank[priority])
        if known_priorities
        else None
    )

    # Finding and priority header.
    finding_col, priority_col = st.columns([3, 1])

    with finding_col:
        st.markdown(f"**{finding_text}**")

    with priority_col:
        if highest_priority == "HIGH":
            st.error("HIGH review priority")
        elif highest_priority == "MEDIUM":
            st.warning("MEDIUM review priority")
        elif highest_priority == "LOW":
            st.success("LOW review priority")
        else:
            st.caption("Priority unavailable")

    # Summary metrics.
    transaction_records = (
        (transaction_data or {}).get("transactions") or []
    )

    flagged_count = (
        (transaction_data or {}).get("flagged_transaction_count")
    )

    metric_col1, metric_col2, metric_col3 = st.columns(3)

    metric_col1.metric(
        "Related accounts",
        len(related_ids),
    )

    metric_col2.metric(
        "Shared devices",
        len(data.get("shared_devices") or []),
    )

    metric_col3.metric(
        "Flagged transactions",
        (
            flagged_count
            if flagged_count is not None
            else "Unavailable"
        ),
    )

    # Account-by-account supporting evidence.
    st.markdown("#### Connected-account evidence")

    if related_ids:
        for related_id in related_ids:
            evidence_item = related_by_id.get(related_id, {})

            priority_text = evidence_item.get(
                "review_priority",
                "Priority unavailable",
            )

            with st.expander(
                f"{related_id} — {priority_text}",
                expanded=False,
            ):
                signals = evidence_item.get("signals") or []
                shared_devices = evidence_item.get("shared_devices") or []
                shared_ips = evidence_item.get("shared_ips") or []
                common_merchants = (
                    evidence_item.get("common_merchants") or []
                )

                evidence_col1, evidence_col2 = st.columns(2)

                with evidence_col1:
                    st.markdown("**Relationship signals**")

                    if signals:
                        for signal in signals:
                            st.write(f"- {signal}")
                    else:
                        st.write("No detailed signals returned.")

                    st.markdown("**Shared devices**")

                    if shared_devices:
                        for device in shared_devices:
                            st.write(f"- {device}")
                    else:
                        st.write("None returned for this account.")

                with evidence_col2:
                    st.markdown("**Shared IP addresses**")

                    if shared_ips:
                        for ip_address in shared_ips:
                            st.write(f"- {ip_address}")
                    else:
                        st.write("None returned for this account.")

                    st.markdown("**Common merchants**")

                    if common_merchants:
                        for merchant in common_merchants:
                            st.write(f"- {merchant}")
                    else:
                        st.write("None returned for this account.")

                additional_evidence = evidence_item.get("evidence") or []

                if additional_evidence:
                    st.markdown("**Additional evidence**")

                    for entry in additional_evidence:
                        st.write(f"- {entry}")

    else:
        st.info(
            "No related accounts were returned by the available checks."
        )

    # Transaction details from the account-evidence API response.
    st.markdown("#### Transaction evidence")

    if transaction_records:
        expected_columns = [
            "transaction_id",
            "amount",
            "status",
            "merchant_id",
        ]

        display_columns = [
            column
            for column in expected_columns
            if any(column in record for record in transaction_records)
        ]

        if display_columns:
            st.dataframe(
                pd.DataFrame(transaction_records)[display_columns],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "Transaction records were returned, but their fields "
                "do not match the expected display columns."
            )
    else:
        st.info("No transaction records are available for this account.")

    # Explicit caution and interpretation limits.
    st.warning(warning_text)

    st.caption(
        "Review priority is a heuristic, not a calibrated fraud probability. "
        "Verify each signal against the underlying graph and transaction data."
    )


    # Exportable case report
    st.divider()
    st.subheader("Export Investigation Case Report")
    st.write(
        "Generate a PDF containing the current account investigation, "
        "transaction evidence, graph nodes and relationships, and assistant "
        "findings."
    )
    st.caption(
        "The report is generated from current API responses. Shared entities "
        "and flagged transactions are investigation signals, not proof of fraud."
    )

    export_hops = st.select_slider(
        "PDF graph depth",
        options=[1, 2, 3],
        value=3,
        key="case_report_hops_selector",
        help="Choose how many relationship hops to include in the exported PDF.",
    )

    generate_report_clicked = st.button(
        "Generate PDF case report",
        type="primary",
        key="generate_case_report_button",
    )

    if generate_report_clicked:
        try:
            with st.spinner("Collecting evidence and generating PDF..."):
                pdf_bytes = create_case_report_pdf(
                    report_account,
                    hops=export_hops,
                )

            st.session_state.case_report_pdf = pdf_bytes
            st.session_state.case_report_account = report_account
            st.session_state.case_report_hops = export_hops
            st.success("Case report generated successfully.")

        except requests.RequestException as exc:
            st.session_state.case_report_pdf = None
            st.session_state.case_report_account = None
            st.error(
                "Could not retrieve report evidence from the API. "
                "Check that FastAPI and FalkorDB are running."
            )
            st.caption(str(exc))

        except Exception as exc:
            st.session_state.case_report_pdf = None
            st.session_state.case_report_account = None
            st.error("The PDF report could not be generated.")
            st.caption(str(exc))

    if (
        st.session_state.case_report_pdf
        and st.session_state.case_report_account == report_account
        and st.session_state.case_report_hops == export_hops
    ):
        st.download_button(
            label="Download PDF case report",
            data=st.session_state.case_report_pdf,
            file_name=f"{report_account}_case_report.pdf",
            mime="application/pdf",
            use_container_width=True,
            key="download_case_report_button",
        )

else:
    st.subheader("Start an investigation")
    st.write(
        "Enter an account ID in the sidebar and select "
        "**Investigate account** to retrieve graph evidence."
    )

    st.markdown("**Synthetic demonstration path**")
    st.code("ACC001 → DEV001 → ACC002 → IP002 → ACC003")


# ============================================================
# AI INVESTIGATION ASSISTANT — MULTI-TURN OPEN-ENDED CHAT
# ============================================================

st.divider()
st.header("AI Investigation Assistant")
st.caption(
    "Ask follow-up questions in natural language. The assistant retrieves "
    "current FalkorDB evidence for each question and keeps a conversation "
    "history for this browser session."
)

if "assistant_chat_session_id" not in st.session_state:
    st.session_state.assistant_chat_session_id = uuid.uuid4().hex[:16]

if "assistant_messages" not in st.session_state:
    st.session_state.assistant_messages = []

with st.container(border=True):
    default_assistant_account = (
        st.session_state.investigation_account or "ACC002"
    )

    assistant_account = st.text_input(
        "Account context",
        value=default_assistant_account,
        key="assistant_account_id",
        help=(
            "The account anchors the graph investigation. You can ask about "
            "other accounts and the wider graph in your question."
        ),
    ).strip().upper()

    st.caption(
        f"Conversation session: `{st.session_state.assistant_chat_session_id}`"
    )

    if st.session_state.assistant_messages:
        if st.button(
            "Clear visible conversation",
            key="clear_assistant_conversation",
        ):
            st.session_state.assistant_messages = []
            st.session_state.assistant_chat_session_id = uuid.uuid4().hex[:16]
            st.rerun()

    for message in st.session_state.assistant_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

            if message["role"] == "assistant":
                evidence_items = message.get("evidence") or []

                if evidence_items:
                    with st.expander("Supporting graph evidence"):
                        render_evidence_items(evidence_items)

                if message.get("warning"):
                    st.caption(message["warning"])

    with st.form("assistant_chat_form", clear_on_submit=True):
        assistant_question = st.text_area(
            "Ask a question",
            placeholder=(
                "Examples:\n"
                "• Which accounts share devices or IP addresses?\n"
                "• What is the total value of flagged transactions?\n"
                "• Compare ACC002 and ACC003.\n"
                "• Explain the previous finding in simpler terms.\n"
                "• What evidence is missing to assess this case?"
            ),
            height=110,
            max_chars=2000,
            key="assistant_question_input",
        )

        ask_button = st.form_submit_button(
            "Send question",
            type="primary",
            use_container_width=True,
        )

    if ask_button:
        if not assistant_account:
            st.warning("Enter an account ID to anchor the investigation.")
        elif not assistant_question.strip():
            st.warning("Enter a question first.")
        else:
            question_text = assistant_question.strip()

            st.session_state.assistant_messages.append({
                "role": "user",
                "content": question_text,
            })

            try:
                with st.spinner(
                    "Retrieving graph evidence and preparing an answer..."
                ):
                    response = requests.post(
                        f"{API_URL}/ask",
                        json={
                            "account_id": assistant_account,
                            "question": question_text,
                            "session_id": (
                                st.session_state.assistant_chat_session_id
                            ),
                        },
                        timeout=75,
                    )

                if response.ok:
                    assistant_data = response.json()

                    answer_text = assistant_data.get(
                        "answer",
                        "The assistant returned no answer.",
                    )

                    st.session_state.assistant_messages.append({
                        "role": "assistant",
                        "content": answer_text,
                        "evidence": assistant_data.get("evidence") or [],
                        "warning": assistant_data.get("warning", ""),
                        "answer_method": assistant_data.get("answer_method"),
                    })

                else:
                    try:
                        detail = response.json().get(
                            "detail",
                            "The investigation request failed.",
                        )
                    except (ValueError, AttributeError):
                        detail = "The investigation request failed."

                    st.session_state.assistant_messages.append({
                        "role": "assistant",
                        "content": f"**Request failed:** {detail}",
                        "evidence": [],
                    })

            except requests.RequestException as exc:
                st.session_state.assistant_messages.append({
                    "role": "assistant",
                    "content": (
                        "Could not connect to FastAPI. Make sure the backend "
                        "is running on port 8010. "
                        f"Details: `{type(exc).__name__}`"
                    ),
                    "evidence": [],
                })

            st.rerun()


# ============================================================
# CASE HISTORY — SEARCHABLE INVESTIGATION MEMORY
# ============================================================

st.divider()
st.header("Case History")
st.caption(
    "Search and review previous investigations stored in FalkorDB. "
    "Historical records are unverified observations; verify them against current graph evidence."
)

if "case_history_data" not in st.session_state:
    st.session_state.case_history_data = None

if "case_history_account" not in st.session_state:
    st.session_state.case_history_account = None

if "case_history_error" not in st.session_state:
    st.session_state.case_history_error = None

history_default_account = (
    st.session_state.investigation_account or "ACC002"
)

with st.container(border=True):
    history_col1, history_col2 = st.columns([2, 1])

    with history_col1:
        history_account = st.text_input(
            "Account ID for history",
            value=history_default_account,
            key="case_history_account_input",
            placeholder="Example: ACC002",
        ).strip().upper()

    with history_col2:
        history_limit = st.selectbox(
            "Maximum records to retrieve",
            options=[1, 5, 10, 20, 50],
            index=4,
            key="case_history_limit",
            help="The API supports up to 50 records per request.",
        )

    history_session = st.text_input(
        "Session filter (optional)",
        value="",
        key="case_history_session_filter",
        placeholder="Blank includes all sessions",
        help="Leave blank to include every session for this account.",
    ).strip()

    load_history_clicked = st.button(
        "Load case history",
        type="primary",
        key="load_case_history_button",
        use_container_width=True,
    )

    if load_history_clicked:
        if not history_account:
            st.session_state.case_history_data = None
            st.session_state.case_history_account = None
            st.session_state.case_history_error = "Enter an account ID."
        else:
            try:
                params = {"limit": history_limit}

                if history_session:
                    params["session_id"] = history_session

                with st.spinner("Loading persistent case history..."):
                    history_response = requests.get(
                        f"{API_URL}/case-history/{history_account}",
                        params=params,
                        timeout=20,
                    )
                    history_response.raise_for_status()
                    history_payload = history_response.json()

                if not isinstance(history_payload, dict):
                    raise ValueError(
                        "The case-history API returned an invalid response."
                    )

                returned_memories = history_payload.get("memories", [])

                if not isinstance(returned_memories, list):
                    raise ValueError(
                        "The case-history API returned an invalid memories list."
                    )

                st.session_state.case_history_data = history_payload
                st.session_state.case_history_account = history_account
                st.session_state.case_history_error = None

            except requests.HTTPError as exc:
                try:
                    detail = exc.response.json().get("detail", str(exc))
                except (ValueError, AttributeError):
                    detail = str(exc)

                st.session_state.case_history_data = None
                st.session_state.case_history_account = None
                st.session_state.case_history_error = (
                    f"Could not load history: {detail}"
                )

            except requests.RequestException:
                st.session_state.case_history_data = None
                st.session_state.case_history_account = None
                st.session_state.case_history_error = (
                    "Could not connect to FastAPI. Check that the backend "
                    "and FalkorDB are running."
                )

            except (TypeError, ValueError) as exc:
                st.session_state.case_history_data = None
                st.session_state.case_history_account = None
                st.session_state.case_history_error = str(exc)

if st.session_state.case_history_error:
    st.error(st.session_state.case_history_error)

history_data = st.session_state.case_history_data

if history_data is not None and st.session_state.case_history_account:
    loaded_account = st.session_state.case_history_account
    memories = history_data.get("memories") or []

    st.subheader(f"Investigation history · {loaded_account}")

    summary_col1, summary_col2, summary_col3 = st.columns(3)

    summary_col1.metric("Records returned", len(memories))
    summary_col2.metric(
        "API memory count",
        history_data.get("memory_count", len(memories)),
    )
    summary_col3.metric("Records available in this view", len(memories))

    if history_data.get("warning"):
        st.warning(history_data["warning"])

    if memories:
        # Search and filters operate only on the retrieved records.
        # They never delete or modify stored FalkorDB memories.
        search_col, intent_col, verification_col = st.columns([2, 1, 1])

        with search_col:
            history_search = st.text_input(
                "Search investigations",
                value="",
                key="case_history_search",
                placeholder="Search question, answer, account, evidence...",
            ).strip().casefold()

        available_intents = sorted({
            str(item.get("intent") or "general_investigation")
            for item in memories
        })

        intent_options = ["All intents"] + available_intents

        with intent_col:
            selected_intent = st.selectbox(
                "Intent",
                options=intent_options,
                key="case_history_intent_filter",
            )

        available_verification = sorted({
            str(item.get("verification_status") or "unverified")
            for item in memories
        })

        verification_options = ["All statuses"] + available_verification

        with verification_col:
            selected_verification = st.selectbox(
                "Verification",
                options=verification_options,
                key="case_history_verification_filter",
            )

        filtered_memories = []

        for memory in memories:
            intent = str(
                memory.get("intent") or "general_investigation"
            )
            verification = str(
                memory.get("verification_status") or "unverified"
            )

            if (
                selected_intent != "All intents"
                and intent != selected_intent
            ):
                continue

            if (
                selected_verification != "All statuses"
                and verification != selected_verification
            ):
                continue

            searchable_parts = [
                memory.get("question", ""),
                memory.get("answer", ""),
                memory.get("account_id", ""),
                memory.get("session_id", ""),
                intent,
                verification,
                memory.get("memory_id", ""),
                str(memory.get("evidence") or []),
            ]

            searchable_text = " ".join(
                str(part)
                for part in searchable_parts
                if part is not None
            ).casefold()

            if history_search and history_search not in searchable_text:
                continue

            filtered_memories.append(memory)

        st.caption(
            f"Showing {len(filtered_memories)} of {len(memories)} retrieved "
            "records. Filters affect this view only; stored history is unchanged."
        )

        if not filtered_memories:
            st.info(
                "No records match the current search and filters. "
                "Clear the search or select broader filters to see more records."
            )
        else:
            history_rows = [
                {
                    "Created at (UTC)": item.get(
                        "created_at", "Unknown"
                    ),
                    "Question": item.get(
                        "question"
                    ) or "Untitled investigation",
                    "Intent": item.get(
                        "intent", "general_investigation"
                    ),
                    "Session": item.get("session_id", "default"),
                    "Verification": item.get(
                        "verification_status", "unverified"
                    ),
                }
                for item in filtered_memories
            ]

            with st.expander(
                "Compact overview table",
                expanded=False,
            ):
                st.dataframe(
                    pd.DataFrame(history_rows),
                    use_container_width=True,
                    hide_index=True,
                )

            st.markdown("#### Investigation records")

            for index, memory in enumerate(
                filtered_memories,
                start=1,
            ):
                question = str(
                    memory.get("question") or "Untitled investigation"
                )
                timestamp = str(
                    memory.get("created_at") or "Unknown timestamp"
                )
                intent = str(
                    memory.get("intent") or "general_investigation"
                )
                verification = str(
                    memory.get("verification_status") or "unverified"
                )
                session_id = str(
                    memory.get("session_id") or "default"
                )
                evidence = memory.get("evidence") or []
                answer = memory.get("answer") or "No answer was stored."

                with st.expander(
                    f"{index}. {question} · {timestamp} · {verification}",
                    expanded=(len(filtered_memories) == 1),
                ):
                    badge_col1, badge_col2, badge_col3 = st.columns(3)

                    badge_col1.markdown(
                        f"**Intent**\n\n`{intent}`"
                    )
                    badge_col2.markdown(
                        f"**Session**\n\n`{session_id}`"
                    )
                    badge_col3.markdown(
                        f"**Verification**\n\n`{verification}`"
                    )

                    st.markdown("**Investigation summary**")
                    st.write(answer)

                    st.markdown("**Stored evidence**")

                    if not evidence:
                        st.info(
                            "No evidence items were stored with this record."
                        )
                    else:
                        evidence_summary_rows = []

                        for evidence_item in evidence:
                            evidence_type = evidence_item.get(
                                "type", "other"
                            )

                            if evidence_type == "connected_account":
                                evidence_summary_rows.append({
                                    "Type": "Connected account",
                                    "Entity": evidence_item.get(
                                        "account_id", "Unknown"
                                    ),
                                    "Signals": ", ".join(
                                        evidence_item.get("signals") or []
                                    ) or "None",
                                    "Review priority": evidence_item.get(
                                        "review_priority", "Unknown"
                                    ),
                                    "Details": (
                                        "Devices: "
                                        + (
                                            ", ".join(
                                                evidence_item.get(
                                                    "shared_devices"
                                                ) or []
                                            ) or "None"
                                        )
                                        + " | IPs: "
                                        + (
                                            ", ".join(
                                                evidence_item.get(
                                                    "shared_ips"
                                                ) or []
                                            ) or "None"
                                        )
                                        + " | Merchants: "
                                        + (
                                            ", ".join(
                                                evidence_item.get(
                                                    "common_merchants"
                                                ) or []
                                            ) or "None"
                                        )
                                    ),
                                })

                            elif evidence_type == "transaction":
                                amount = evidence_item.get("amount")

                                if isinstance(amount, (int, float)):
                                    amount_text = f"{amount:,.2f}"
                                else:
                                    amount_text = (
                                        str(amount)
                                        if amount is not None
                                        else "Unavailable"
                                    )

                                evidence_summary_rows.append({
                                    "Type": "Transaction",
                                    "Entity": evidence_item.get(
                                        "transaction_id", "Unknown"
                                    ),
                                    "Signals": evidence_item.get(
                                        "status", "Unknown"
                                    ),
                                    "Review priority": "—",
                                    "Details": (
                                        f"Amount: {amount_text} | Merchant: "
                                        f"{evidence_item.get('merchant_id', 'Unknown')}"
                                    ),
                                })

                            else:
                                evidence_summary_rows.append({
                                    "Type": str(evidence_type),
                                    "Entity": str(
                                        evidence_item.get(
                                            "account_id",
                                            evidence_item.get(
                                                "transaction_id",
                                                "Evidence item",
                                            ),
                                        )
                                    ),
                                    "Signals": str(
                                        evidence_item.get("signals") or "—"
                                    ),
                                    "Review priority": "—",
                                    "Details": str(evidence_item),
                                })

                        st.dataframe(
                            pd.DataFrame(evidence_summary_rows),
                            use_container_width=True,
                            hide_index=True,
                        )

                        with st.expander(
                            "View complete raw evidence",
                            expanded=False,
                        ):
                            for evidence_index, evidence_item in enumerate(
                                evidence,
                                start=1,
                            ):
                                st.markdown(
                                    f"**Evidence item {evidence_index}**"
                                )
                                st.json(evidence_item)

                    st.caption(
                        f"Memory ID: {memory.get('memory_id', 'Unknown')}"
                    )
                    st.caption(
                        "Historical observations may be stale. Re-run the "
                        "investigation to verify them against the current graph. "
                        "Shared entities are not proof of fraud."
                    )

    else:
        st.info(
            "No saved investigation memories were found for this account "
            "and session filter. A single record will also be displayed when available."
        )

    st.caption(
        "Source: FalkorDB persistent investigation history. "
        "History is read-only from this panel; repeated investigations remain "
        "separate records."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "FraudTrace AI · FalkorDB graph investigation · "
    "Synthetic demonstration data · Shared entities are not proof of fraud."
)