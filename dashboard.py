
import requests
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import networkx as nx
import tempfile
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
            session,
            API_URL,
            f"/investigate/{account_id}",
        )

        account_evidence = get_json(
            session,
            API_URL,
            f"/account-evidence/{account_id}",
        )

        graph_data = get_json(
            session,
            API_URL,
            f"/graph/{account_id}?hops={hops}",
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

    # Build the PDF in a temporary directory, then return its bytes.
    # The temporary directory is automatically cleaned up afterward.
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


# ============================================================
# EVIDENCE DISPLAY
# ============================================================

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

                st.write(
                    "**Status:**",
                    item.get("status", "Unknown"),
                )

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

    # Draw connections between consecutive path nodes.
    for index in range(len(steps) - 1):
        figure.add_trace(
            go.Scatter(
                x=[
                    x_positions[index],
                    x_positions[index + 1],
                ],
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
            marker=dict(
                size=24,
                color=node_colors,
            ),
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
        yaxis=dict(
            visible=False,
            range=[-0.8, 0.8],
        ),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(
        figure,
        use_container_width=True,
    )


# ============================================================
# MULTI-HOP FALKORDB GRAPH
# ============================================================

def render_stored_graph(account_id, hops=2):
    """
    Display the actual nodes and stored relationships returned by
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

    # --------------------------------------------------------
    # LAYERED LAYOUT
    # --------------------------------------------------------

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

    # Position unexpected labels rather than omitting their nodes.
    unknown_nodes = [
        node
        for node in graph.nodes
        if node not in positions
    ]

    for index, node in enumerate(unknown_nodes):
        positions[node] = (index * 4.5, -9)

    # --------------------------------------------------------
    # NODE COLORS
    # --------------------------------------------------------

    colors = {
        "Account": "#ef4444",
        "Device": "#8b5cf6",
        "IPAddress": "#06b6d4",
        "Merchant": "#f59e0b",
        "Transaction": "#10b981",
        "Unknown": "#64748b",
    }

    figure = go.Figure()

    # --------------------------------------------------------
    # DRAW ACTUAL STORED RELATIONSHIPS
    # --------------------------------------------------------

    for source, target, attrs in graph.edges(data=True):
        x0, y0 = positions[source]
        x1, y1 = positions[target]

        relationship = attrs.get(
            "relationship",
            "CONNECTED",
        )

        figure.add_trace(
            go.Scatter(
                x=[x0, x1],
                y=[y0, y1],
                mode="lines",
                line=dict(
                    color="#94a3b8",
                    width=1.5,
                ),
                hovertemplate=(
                    f"<b>{source} → {target}</b><br>"
                    f"Relationship: {relationship}"
                    "<extra></extra>"
                ),
                showlegend=False,
            )
        )

    # --------------------------------------------------------
    # DRAW NODES
    # --------------------------------------------------------

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
            properties = (
                graph.nodes[node].get("properties") or {}
            )

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
                x=[
                    positions[node][0]
                    for node in selected
                ],
                y=[
                    positions[node][1]
                    for node in selected
                ],
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
                    line=dict(
                        color="white",
                        width=1.5,
                    ),
                ),
                name=node_type,
                customdata=hover_details,
                hovertemplate="%{customdata}<extra></extra>",
            )
        )

    max_x = max(
        (
            abs(x)
            for x, _ in positions.values()
        ),
        default=4,
    )

    x_bound = max(10, max_x + 5)

    figure.update_layout(
        title=(
            f"FalkorDB Network — {account_id} "
            f"({hops} hop(s))"
        ),
        height=700,
        margin=dict(
            l=40,
            r=120,
            t=70,
            b=40,
        ),
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

    # --------------------------------------------------------
    # GRAPH METRICS
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Hop depth",
        graph_data.get("hops", hops),
    )

    col2.metric(
        "Nodes",
        graph_data.get("node_count", len(nodes)),
    )

    col3.metric(
        "Relationships",
        graph_data.get("edge_count", len(edges)),
    )

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
                "Properties": str(
                    node.get("properties") or {}
                ),
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
            st.info(
                "No stored relationships were returned."
            )


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
st.caption(
    "GRAPH-POWERED FRAUD INVESTIGATION · FALKORDB"
)

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

            # Invalidate an old report after investigating a new account.
            st.session_state.case_report_pdf = None
            st.session_state.case_report_account = None
            st.session_state.case_report_hops = None

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

    st.header(
        f"Investigation Report: {report_account}"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Account",
        report_account,
    )

    col2.metric(
        "Risk label",
        data.get("risk_label") or "Unknown",
    )

    col3.metric(
        "Direct connections",
        len(data.get("related_accounts") or []),
    )

    col4.metric(
        "Multi-hop paths",
        data.get("multi_hop_path_count", 0),
    )

    st.divider()

    # --------------------------------------------------------
    # CONNECTED ACCOUNTS
    # --------------------------------------------------------

    st.subheader("Connected Accounts")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            "**Accounts returned by the investigation**"
        )

        connected = data.get("related_accounts") or []

        if connected:
            for item in connected:
                st.write(f"• {item}")
        else:
            st.write(
                "No directly connected accounts found."
            )

    with col2:
        st.markdown("**Shared devices**")

        devices = data.get("shared_devices") or []

        if devices:
            for device in devices:
                st.write(f"• {device}")
        else:
            st.write("No shared devices found.")

    # --------------------------------------------------------
    # MULTI-HOP PATHS
    # --------------------------------------------------------

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

        st.code(
            " → ".join(selected_path.get("steps") or [])
        )

        render_path_graph(
            selected_path.get("steps") or []
        )

        st.markdown("**Evidence discovered**")

        for evidence in selected_path.get("evidence") or []:
            st.write(f"• {evidence}")

    else:
        st.info(
            "No multi-hop paths were found for this account."
        )

    st.divider()

    # --------------------------------------------------------
    # TRANSACTION EVIDENCE
    # --------------------------------------------------------

    st.subheader("Transaction Evidence")

    if transaction_data:
        col1, col2, col3 = st.columns(3)

        total = transaction_data.get(
            "transaction_count",
            0,
        )

        flagged = transaction_data.get(
            "flagged_transaction_count",
            0,
        )

        col1.metric(
            "Transactions",
            total,
        )

        col2.metric(
            "Flagged transactions",
            flagged,
        )

        col3.metric(
            "Other transactions",
            max(0, total - flagged),
        )

        transaction_rows = (
            transaction_data.get("transactions") or []
        )

        if transaction_rows:
            st.dataframe(
                pd.DataFrame(transaction_rows),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info(
                "No transaction records were found."
            )

        st.caption(
            "Transaction flags in this synthetic dataset are "
            "investigation clues, not proof of fraud."
        )

    st.divider()

    # --------------------------------------------------------
    # INTERACTIVE MULTI-HOP GRAPH
    # --------------------------------------------------------

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

    render_stored_graph(
        report_account,
        hops=graph_hops,
    )

    st.divider()

    # --------------------------------------------------------
    # CONNECTED-ACCOUNT RISK SIGNALS
    # --------------------------------------------------------

    st.subheader("Connected Account Risk Signals")

    try:
        with st.spinner(
            "Analyzing connected-account signals..."
        ):
            network_data = detect_connected_accounts(
                report_account
            )

        if network_data is None:
            st.info(
                "Account not found in the graph."
            )
        else:
            related = network_data.get(
                "related_accounts"
            ) or []

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

                st.markdown(
                    "**Inspect evidence by account**"
                )

                for item in related:
                    with st.expander(
                        f"{item['account_id']} — "
                        f"{item['review_priority']} review priority"
                    ):
                        st.write(
                            "**Signals:**",
                            ", ".join(
                                item.get("signals") or []
                            ) or "None",
                        )

                        for entry in item.get("evidence") or []:
                            st.write(f"• {entry}")

                st.caption(
                    network_data.get("warning", "")
                )

            else:
                st.info(
                    "No related accounts matched the current checks."
                )

    except Exception as exc:
        st.warning(
            "Connected-account risk signals could not be loaded. "
            "Check that FalkorDB is running."
        )

        st.caption(str(exc))

    st.divider()

    # --------------------------------------------------------
    # INVESTIGATION FINDING
    # --------------------------------------------------------

    st.subheader("Investigation Finding")

    st.write(
        data.get(
            "finding",
            "No finding available.",
        )
    )

    st.warning(
        data.get("warning", "")
    )

    # --------------------------------------------------------
    # EXPORTABLE CASE REPORT
    # --------------------------------------------------------

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
        help=(
            "Choose how many relationship hops to include "
            "in the exported PDF."
        ),
    )

    generate_report_clicked = st.button(
        "Generate PDF case report",
        type="primary",
        key="generate_case_report_button",
    )

    if generate_report_clicked:
        try:
            with st.spinner(
                "Collecting evidence and generating PDF..."
            ):
                pdf_bytes = create_case_report_pdf(
                    report_account,
                    hops=export_hops,
                )

            st.session_state.case_report_pdf = pdf_bytes
            st.session_state.case_report_account = report_account
            st.session_state.case_report_hops = export_hops

            st.success(
                "Case report generated successfully."
            )

        except requests.RequestException as exc:
            st.session_state.case_report_pdf = None
            st.session_state.case_report_account = None
            st.session_state.case_report_hops = None

            st.error(
                "Could not retrieve report evidence from the API. "
                "Check that FastAPI and FalkorDB are running."
            )

            st.caption(str(exc))

        except Exception as exc:
            st.session_state.case_report_pdf = None
            st.session_state.case_report_account = None
            st.session_state.case_report_hops = None

            st.error(
                "The PDF report could not be generated."
            )

            st.caption(str(exc))

    # Only show a download button for the selected account and depth.
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

    st.code(
        "ACC001 → DEV001 → ACC002 → IP002 → ACC003"
    )


# ============================================================
# AI INVESTIGATION ASSISTANT
# ============================================================

st.divider()

st.header("AI Investigation Assistant")

st.caption(
    "Ask questions about connected accounts and transaction evidence. "
    "Answers are based on evidence retrieved by the current assistant."
)

with st.container(border=True):
    default_assistant_account = (
        st.session_state.investigation_account or "ACC002"
    )

    assistant_account = st.text_input(
        "Account to investigate",
        value=default_assistant_account,
        key="assistant_account_id",
    )

    assistant_question = st.text_area(
        "Your question",
        value="Why is this account suspicious?",
        placeholder=(
            "Example: Which accounts share devices with this account?"
        ),
        key="assistant_question",
    )

    ask_button = st.button(
        "Investigate with AI Assistant",
        type="primary",
        key="ask_investigation_button",
    )

    if ask_button:
        if (
            not assistant_account.strip()
            or not assistant_question.strip()
        ):
            st.warning(
                "Enter an account ID and a question."
            )

        else:
            try:
                with st.spinner(
                    "Retrieving graph evidence..."
                ):
                    response = requests.post(
                        f"{API_URL}/ask",
                        json={
                            "account_id": assistant_account.strip().upper(),
                            "question": assistant_question.strip(),
                        },
                        timeout=30,
                    )

                if response.ok:
                    assistant_data = response.json()

                    st.subheader("Investigation Answer")

                    st.write(
                        assistant_data.get(
                            "answer",
                            "No answer returned.",
                        )
                    )

                    st.subheader("Supporting Evidence")

                    render_evidence_items(
                        assistant_data.get("evidence") or []
                    )

                    if assistant_data.get("warning"):
                        st.info(
                            assistant_data["warning"]
                        )

                else:
                    try:
                        detail = response.json().get(
                            "detail",
                            "The investigation request failed.",
                        )
                    except ValueError:
                        detail = (
                            "The investigation request failed."
                        )

                    st.error(
                        f"Investigation failed: {detail}"
                    )

            except requests.RequestException:
                st.error(
                    "Could not connect to FastAPI. "
                    "Make sure the backend is running on port 8010."
                )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "FraudTrace AI · FalkorDB graph investigation · "
    "Synthetic demonstration data · Shared entities are not proof of fraud."
)
