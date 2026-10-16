"""
FraudTrace AI — Graph-Powered Fraud Investigation Dashboard
WeMakeDevs x FalkorDB Graph Hacks (Track 01 & Track 02)

Features:
- Light-mode professional fraud-investigation workbench
- Genuine interactive 3D Molecular Network graph visualization (Plotly 3D)
- Multi-layout support (3D Molecular, 2D Force-Directed, 3D Spherical Orbit)
- Real FalkorDB multi-hop traversal, path finder, and suspicious cluster detection
- Evidence linkage between graph nodes, transaction records, and AI findings
- Case memory search and inspection across sessions
- One-click PDF case report generation and export
"""

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import json
import math
import tempfile
import uuid
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

from export_case_report import build_report, get_json, post_json

# ============================================================
# CONFIGURATION & THEME
# ============================================================


import os

API_URL = os.getenv(
    "API_BASE_URL",
    "http://127.0.0.1:8010",
).rstrip("/")


st.set_page_config(
    page_title="FraudTrace AI — Graph-Powered Fraud Investigation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Light-Mode Design System CSS
LIGHT_THEME_CSS = """
<style>
/* Base Styles */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #0F172A;
}

/* Background */
.stApp {
    background-color: #F8FAFC;
}

/* Top App Header Banner */
.fraud-navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    background: #FFFFFF;
    border-bottom: 1px solid #E2E8F0;
    margin-bottom: 16px;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
}

.fraud-brand {
    display: flex;
    align-items: center;
    gap: 12px;
}

.fraud-logo-icon {
    font-size: 26px;
    background: #EFF6FF;
    padding: 8px;
    border-radius: 10px;
    border: 1px solid #DBEAFE;
}

.fraud-brand-title {
    font-size: 20px;
    font-weight: 700;
    color: #0F172A;
    margin: 0;
    line-height: 1.2;
}

.fraud-brand-sub {
    font-size: 11px;
    font-weight: 500;
    color: #64748B;
    letter-spacing: 0.5px;
    margin: 0;
}

/* Metric Pills */
.metric-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 12px;
}

.metric-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid transparent;
}

.pill-neutral { background: #F1F5F9; color: #334155; border-color: #E2E8F0; }
.pill-accounts { background: #EFF6FF; color: #1D4ED8; border-color: #BFDBFE; }
.pill-txns { background: #FFF7ED; color: #C2410C; border-color: #FED7AA; }
.pill-devices { background: #FAF5FF; color: #6D28D9; border-color: #E9D5FF; }
.pill-merchants { background: #FFF1F2; color: #BE123C; border-color: #FECDD3; }
.pill-ips { background: #F0FDF4; color: #15803D; border-color: #BBF7D0; }

/* Status Badges */
.badge-flagged {
    background: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FECACA;
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.badge-completed {
    background: #DCFCE7;
    color: #15803D;
    border: 1px solid #BBF7D0;
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    display: inline-block;
}

.badge-high-risk {
    background: #FEE2E2;
    color: #B91C1C;
    border: 1px solid #FCA5A5;
    padding: 4px 10px;
    border-radius: 14px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
}

.badge-medium-risk {
    background: #FEF3C7;
    color: #B45309;
    border: 1px solid #FDE68A;
    padding: 4px 10px;
    border-radius: 14px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
}

.badge-low-risk {
    background: #DCFCE7;
    color: #15803D;
    border: 1px solid #86EFAC;
    padding: 4px 10px;
    border-radius: 14px;
    font-size: 11px;
    font-weight: 700;
    display: inline-block;
}

/* Card Containers */
.fraud-card {
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
    margin-bottom: 14px;
}

.fraud-card-title {
    font-size: 15px;
    font-weight: 700;
    color: #0F172A;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* Entity list item */
.entity-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    margin-bottom: 6px;
}

.entity-row:hover {
    background: #EFF6FF;
    border-color: #BFDBFE;
}

/* Disclaimer Banner */
.disclaimer-box {
    background: #EFF6FF;
    border: 1px solid #BFDBFE;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 12px;
    color: #1E40AF;
    margin-top: 10px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #FFFFFF !important;
    border-right: 1px solid #E2E8F0;
}
</style>
"""

st.markdown(LIGHT_THEME_CSS, unsafe_allow_html=True)


# ============================================================
# API HELPERS
# ============================================================

def _api_request(
    method: str,
    path: str,
    params: dict | None = None,
    payload: dict | None = None,
) -> dict:
    """Request a JSON object from the API and report actionable errors."""
    url = f"{API_URL}{path}"
    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=payload,
            timeout=60 if method == "POST" else 20,
        )
    except requests.Timeout as exc:
        raise RuntimeError(
            f"The FraudTrace API request to {path} timed out. "
            "Check the backend and try again."
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Could not reach the FraudTrace API at {API_URL}: {exc}"
        ) from exc

    response.encoding = "utf-8"
    try:
        result = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"The FraudTrace API returned invalid JSON "
            f"(HTTP {response.status_code}) for {path}."
        ) from exc

    if not response.ok:
        detail = result.get("detail", result) if isinstance(result, dict) else result
        raise RuntimeError(
            f"FraudTrace API {path} returned HTTP {response.status_code}: "
            f"{detail}"
        )
    if not isinstance(result, dict):
        raise RuntimeError(
            f"The FraudTrace API returned {type(result).__name__}, "
            f"not a JSON object, for {path}."
        )
    return result


def api_get(path: str, params: dict | None = None) -> dict:
    return _api_request("GET", path, params=params)


def api_post(path: str, payload: dict) -> dict:
    return _api_request("POST", path, payload=payload)


def create_case_report_pdf(account_id: str, hops: int = 3, dataset_id: str = "demo_synthetic") -> bytes:
    """Fetch current API evidence and return a generated case-report PDF."""
    with requests.Session() as session:
        health = get_json(session, API_URL, "/health")
        if not isinstance(health, dict):
            raise ValueError("The API health endpoint returned an invalid response.")

        investigation = get_json(session, API_URL, f"/investigate/{account_id}?dataset={dataset_id}")
        account_evidence = get_json(session, API_URL, f"/account-evidence/{account_id}?dataset={dataset_id}")
        graph_data = get_json(session, API_URL, f"/graph/{account_id}?hops={hops}&dataset={dataset_id}")
        assistant = post_json(
            session,
            API_URL,
            "/ask",
            {
                "account_id": account_id,
                "question": "Why is this account suspicious?",
                "dataset_id": dataset_id,
            },
        )

    if not graph_data.get("nodes"):
        raise ValueError(
            f"No graph nodes were returned for {account_id}. "
            f"Check that the account exists in dataset '{dataset_id}'."
        )

    with tempfile.TemporaryDirectory(prefix="fraudtrace_report_") as temp_dir:
        output_path = Path(temp_dir) / f"{account_id}_case_report.pdf"
        build_report(
            output_path=output_path,
            account_id=account_id,
            investigation=investigation,
            account_evidence=account_evidence,
            graph_data=graph_data,
            assistant=assistant,
            hops=hops,
            dataset_id=dataset_id,
        )
        return output_path.read_bytes()


# ============================================================
# 3D MOLECULAR NETWORK & 2D GRAPH VISUALIZATION
# ============================================================

# Visual token color palette matching light-mode design system
NODE_COLORS = {
    "Account": "#2563EB",        # Sapphire Blue
    "AMLAccount": "#2563EB",     # Sapphire Blue
    "Transaction": "#F97316",    # Bright Orange
    "AMLTransaction": "#F97316", # Bright Orange
    "AMLAlert": "#DC2626",       # Crimson Red
    "AMLBranch": "#64748B",       # Slate
    "Device": "#8B5CF6",         # Amethyst Purple
    "IPAddress": "#10B981",      # Emerald Green
    "Merchant": "#F43F5E",       # Coral Rose
    "Unknown": "#64748B",        # Slate Gray
}

EDGE_COLORS = {
    "MADE": "#F97316",           # Orange
    "PAID_TO": "#EF4444",        # Coral Red
    "USES_DEVICE": "#8B5CF6",    # Violet
    "CONNECTS_FROM": "#10B981",  # Green
    "AML_SENT": "#2563EB",       # Blue
    "AML_RECEIVED": "#10B981",   # Green
    "AML_AT_BRANCH": "#64748B",  # Slate
    "HAS_ALERT": "#DC2626",      # Red
    "CONNECTED": "#94A3B8",      # Gray
}


def build_filtered_subgraph(
    nodes: list[dict],
    edges: list[dict],
    target_id: str,
    filters: dict[str, bool],
) -> tuple[nx.Graph, dict]:
    """Build a NetworkX graph respecting node-type filter toggles."""
    g = nx.Graph()
    node_attr = {}

    type_to_filter = {
        "Transaction": "show_txns",
        "AMLTransaction": "show_txns",
        "Device": "show_devices",
        "IPAddress": "show_ips",
        "Merchant": "show_merchants",
    }

    # Add allowed nodes
    for n in nodes:
        nid = n.get("id")
        if not nid:
            continue
        label = n.get("label", "Unknown")

        # The target root account is always preserved
        if nid != target_id:
            filter_key = type_to_filter.get(label)
            if filter_key and not filters.get(filter_key, True):
                continue

        g.add_node(nid, label=label, properties=n.get("properties") or {})
        node_attr[nid] = {"label": label, "properties": n.get("properties") or {}}

    # Add edges where both endpoints are in graph
    for e in edges:
        s = e.get("source")
        t = e.get("target")
        rel = e.get("relationship", "CONNECTED")
        if s in g and t in g:
            g.add_edge(s, t, relationship=rel)

    return g, node_attr


def render_3d_molecular_graph(
    g: nx.Graph,
    node_attr: dict,
    target_id: str,
    selected_id: str | None = None,
    layout_mode: str = "3D Molecular Network",
) -> go.Figure:
    """
    Renders an interactive 3D molecular network graph using Plotly 3D.
    Nodes are spherical 'atoms' and edges are chemical 'bonds' with relationship colors.
    """
    if g.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(
            text="No nodes visible under current filter settings.",
            showarrow=False,
            font=dict(size=14, color="#64748B"),
        )
        fig.update_layout(height=520, plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF")
        return fig

    # Compute 3D coordinates based on layout
    if layout_mode == "3D Spherical Orbit":
        # Concentric spherical shells: root at (0,0,0), 1-hop, 2-hop...
        pos = {}
        lengths = nx.single_source_shortest_path_length(g, target_id) if target_id in g else {}
        by_depth = {}
        for n in g.nodes():
            d = lengths.get(n, 1)
            by_depth.setdefault(d, []).append(n)

        pos[target_id] = (0.0, 0.0, 0.0)
        for depth, nlist in by_depth.items():
            if depth == 0:
                continue
            r = depth * 2.2
            count = len(nlist)
            for i, node in enumerate(nlist):
                phi = math.acos(1 - 2 * (i + 0.5) / count)
                theta = math.pi * (1 + 5**0.5) * (i + 0.5)
                x = r * math.sin(phi) * math.cos(theta)
                y = r * math.sin(phi) * math.sin(theta)
                z = r * math.cos(phi)
                pos[node] = (x, y, z)
    else:
        # 3D Spring force layout for natural molecular dynamics
        pos = nx.spring_layout(g, dim=3, seed=42, k=0.85, iterations=60)
        if target_id in pos:
            # Shift centroid so target is centered
            tx, ty, tz = pos[target_id]
            for n in pos:
                pos[n] = (pos[n][0] - tx, pos[n][1] - ty, pos[n][2] - tz)

    fig = go.Figure()

    # Draw 3D Bonds (Edges) grouped by relationship type for distinct colors
    edges_by_rel = {}
    for u, v, data in g.edges(data=True):
        rel = data.get("relationship", "CONNECTED")
        edges_by_rel.setdefault(rel, []).append((u, v))

    for rel, edge_list in edges_by_rel.items():
        edge_x, edge_y, edge_z = [], [], []
        mid_x, mid_y, mid_z, mid_text = [], [], [], []
        color = EDGE_COLORS.get(rel, "#94A3B8")

        for u, v in edge_list:
            x0, y0, z0 = pos[u]
            x1, y1, z1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_z.extend([z0, z1, None])

            # Midpoint marker for relationship hover
            mid_x.append((x0 + x1) / 2)
            mid_y.append((y0 + y1) / 2)
            mid_z.append((z0 + z1) / 2)
            mid_text.append(f"<b>{u}</b> -[:{rel}]-> <b>{v}</b>")

        # 3D Bond Line
        fig.add_trace(
            go.Scatter3d(
                x=edge_x,
                y=edge_y,
                z=edge_z,
                mode="lines",
                line=dict(color=color, width=4.5),
                hoverinfo="none",
                name=rel,
                showlegend=True,
            )
        )

        # 3D Midpoint Hover
        fig.add_trace(
            go.Scatter3d(
                x=mid_x,
                y=mid_y,
                z=mid_z,
                mode="markers",
                marker=dict(size=3, color=color, opacity=0.01),
                hoverinfo="text",
                hovertext=mid_text,
                showlegend=False,
            )
        )

    # Draw 3D Atoms (Nodes) grouped by node type
    types_in_graph = sorted(list({node_attr[n]["label"] for n in g.nodes()}))

    for ntype in types_in_graph:
        node_subset = [n for n in g.nodes() if node_attr[n]["label"] == ntype]
        xs = [pos[n][0] for n in node_subset]
        ys = [pos[n][1] for n in node_subset]
        zs = [pos[n][2] for n in node_subset]

        color = NODE_COLORS.get(ntype, "#64748B")
        sizes = []
        hover_texts = []
        labels = []

        for n in node_subset:
            props = node_attr[n]["properties"]
            risk = props.get("risk", "unknown")
            amt = props.get("amount")
            status = props.get("status")

            # Determine Atom size
            if n == target_id:
                size = 32
            elif n == selected_id:
                size = 28
            elif ntype == "Account":
                size = 22
            elif ntype in ("Merchant", "Device"):
                size = 20
            else:
                size = 17
            sizes.append(size)

            labels.append(n)

            # Rich hover tooltip
            tip_lines = [
                f"<b>{n}</b> ({ntype})",
                f"Connected degree: {g.degree(n)}",
            ]
            if risk != "unknown":
                tip_lines.append(f"Risk: {str(risk).upper()}")
            if amt is not None:
                tip_lines.append(f"Amount: ₹{amt:,.2f}" if isinstance(amt, (int, float)) else f"Amount: {amt}")
            if status:
                tip_lines.append(f"Status: {status}")
            hover_texts.append("<br>".join(tip_lines))

        # Node Atom Trace
        fig.add_trace(
            go.Scatter3d(
                x=xs,
                y=ys,
                z=zs,
                mode="markers+text",
                text=labels,
                textposition="top center",
                textfont=dict(size=10, color="#0F172A", family="Inter"),
                hovertext=hover_texts,
                hoverinfo="text",
                marker=dict(
                    size=sizes,
                    color=color,
                    opacity=0.95,
                    line=dict(
                        color="#FFFFFF" if ntype != "Account" else "#FBBF24",
                        width=2,
                    ),
                ),
                name=ntype,
                showlegend=True,
            )
        )

    # If an entity is selected, add a special 3D halo pulse ring
    if selected_id and selected_id in pos:
        sx, sy, sz = pos[selected_id]
        fig.add_trace(
            go.Scatter3d(
                x=[sx],
                y=[sy],
                z=[sz],
                mode="markers",
                marker=dict(
                    size=38,
                    color="rgba(37, 99, 235, 0.25)",
                    line=dict(color="#2563EB", width=3),
                ),
                hoverinfo="none",
                name="Selected Node",
                showlegend=False,
            )
        )

    # 3D Camera and clean white canvas layout
    fig.update_layout(
        height=580,
        margin=dict(l=0, r=0, t=10, b=10),
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="#FFFFFF",
        legend=dict(
            orientation="h",
            yanchor="top",
            y=-0.02,
            xanchor="center",
            x=0.5,
            font=dict(size=11, family="Inter", color="#334155"),
        ),
        scene=dict(
            xaxis=dict(visible=False, showbackground=False),
            yaxis=dict(visible=False, showbackground=False),
            zaxis=dict(visible=False, showbackground=False),
            bgcolor="#FFFFFF",
            camera=dict(
                eye=dict(x=1.35, y=1.35, z=0.9),
                center=dict(x=0, y=0, z=0),
            ),
        ),
    )
    return fig


def render_2d_force_graph(
    g: nx.Graph,
    node_attr: dict,
    target_id: str,
    selected_id: str | None = None,
) -> go.Figure:
    """Renders a clean 2D force-directed graph matching the reference UI."""
    if g.number_of_nodes() == 0:
        fig = go.Figure()
        fig.update_layout(height=520, plot_bgcolor="#FFFFFF", paper_bgcolor="#FFFFFF")
        return fig

    pos = nx.spring_layout(g, seed=42, k=0.7, iterations=50)

    fig = go.Figure()

    # Edges
    for u, v, data in g.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        rel = data.get("relationship", "CONNECTED")
        color = EDGE_COLORS.get(rel, "#94A3B8")

        fig.add_trace(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode="lines",
                line=dict(color=color, width=2.5),
                hoverinfo="none",
                showlegend=False,
            )
        )

    # Nodes by type
    types = sorted(list({node_attr[n]["label"] for n in g.nodes()}))
    for ntype in types:
        subset = [n for n in g.nodes() if node_attr[n]["label"] == ntype]
        xs = [pos[n][0] for n in subset]
        ys = [pos[n][1] for n in subset]
        color = NODE_COLORS.get(ntype, "#64748B")

        sizes = [34 if n == target_id else 26 if n == selected_id else 22 for n in subset]
        hover_texts = [f"<b>{n}</b> ({ntype})<br>Degree: {g.degree(n)}" for n in subset]

        fig.add_trace(
            go.Scatter(
                x=xs,
                y=ys,
                mode="markers+text",
                text=subset,
                textposition="bottom center",
                textfont=dict(size=11, color="#0F172A", family="Inter"),
                hovertext=hover_texts,
                hoverinfo="text",
                marker=dict(
                    size=sizes,
                    color=color,
                    line=dict(color="#FFFFFF", width=2),
                ),
                name=ntype,
            )
        )

    fig.update_layout(
        height=580,
        margin=dict(l=20, r=20, t=20, b=20),
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="#FFFFFF",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        legend=dict(orientation="h", yanchor="bottom", y=-0.08, xanchor="center", x=0.5),
    )
    return fig


# ============================================================
# EVIDENCE ITEM RENDERER (shared by AI Assistant views)
# ============================================================

def render_evidence_items(evidence_items):
    """Display connected-account and transaction evidence from /ask response."""
    if not evidence_items:
        st.info("No supporting evidence was returned.")
        return

    for item in evidence_items:
        if item.get("type") == "connected_account":
            account = item.get("account_id", "Unknown")
            priority = item.get("review_priority", "REVIEW")
            ref = item.get("evidence_ref", "")
            with st.expander(f"{'👤'} {account} — {priority} priority  {ref}"):
                st.write("**Relationship signals:**", ", ".join(item.get("signals") or []) or "None")
                st.write("**Shared devices:**", ", ".join(item.get("shared_devices") or []) or "None")
                st.write("**Shared IPs:**", ", ".join(item.get("shared_ips") or []) or "None")
                st.write("**Common merchants:**", ", ".join(item.get("common_merchants") or []) or "None")
                if st.button(f"Focus {account} on graph", key=f"focus_ev_{account}_{ref}"):
                    st.session_state.selected_entity_id = account
                    st.session_state.current_account = account
                    st.rerun()

        elif item.get("type") == "transaction":
            txn_id = item.get("transaction_id", "Unknown")
            ref = item.get("evidence_ref", "")
            with st.expander(f"{'💳'} Transaction {txn_id}  {ref}"):
                amount = item.get("amount")
                if isinstance(amount, (int, float)):
                    st.write(f"**Amount:** {amount:,.2f}")
                else:
                    st.write("**Amount:**", amount if amount is not None else "Unavailable")
                st.write("**Status:**", item.get("status", "Unknown"))
                st.write("**Merchant:**", item.get("merchant_id", "Unknown"))

        else:
            ref = item.get("evidence_ref", "")
            label = item.get("type", "evidence")
            with st.expander(f"{label}  {ref}"):
                st.json(item)


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if "dataset_id" not in st.session_state:
    st.session_state.dataset_id = "demo_synthetic"

if "current_account" not in st.session_state:
    st.session_state.current_account = "ACC002"

if "graph_depth" not in st.session_state:
    st.session_state.graph_depth = 2

if "selected_entity_id" not in st.session_state:
    st.session_state.selected_entity_id = "ACC002"

if "investigation_cache" not in st.session_state:
    st.session_state.investigation_cache = {}

if "global_search_result" not in st.session_state:
    st.session_state.global_search_result = None

if "case_report_pdf" not in st.session_state:
    st.session_state.case_report_pdf = None

if "assistant_messages" not in st.session_state:
    st.session_state.assistant_messages = []

if "assistant_chat_session_id" not in st.session_state:
    st.session_state.assistant_chat_session_id = uuid.uuid4().hex[:16]

if "assistant_quick_result" not in st.session_state:
    st.session_state.assistant_quick_result = None


# ============================================================
# TOP NAVIGATION BAR & BRAND
# ============================================================

nav_col1, nav_col2, nav_col3 = st.columns([3, 4, 3])

with nav_col1:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:12px; padding:6px 0;">
            <div style="font-size:28px; background:#EFF6FF; border:1px solid #BFDBFE; border-radius:12px; padding:6px 10px;">🛡️</div>
            <div>
                <div style="font-size:20px; font-weight:800; color:#0F172A; line-height:1.2;">FraudTrace AI</div>
                <div style="font-size:11px; font-weight:600; color:#64748B; letter-spacing:0.4px;">GRAPH-POWERED FRAUD INVESTIGATION</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with nav_col2:
    selected_view = st.radio(
        "Navigation",
        options=["Investigation", "AI Assistant", "Graph Explorer", "Case Memory", "Reports"],
        horizontal=True,
        label_visibility="collapsed",
    )

with nav_col3:
    search_query = st.text_input(
        "Search entities",
        placeholder="Search accounts, transactions, alerts, devices...",
        label_visibility="collapsed",
        key="nav_search_input",
    )

    if search_query.strip():
        try:
            search_response = api_get(
                "/search",
                params={
                    "q": search_query.strip(),
                    "dataset": st.session_state.dataset_id,
                },
            )

            found_entities = (
                search_response.get("results", [])
                if isinstance(search_response, dict)
                else search_response
            )

            if found_entities:
                with st.expander(
                    f"Search Results ({len(found_entities)})",
                    expanded=True,
                ):
                    for item in found_entities:
                        e_id = item.get("id", "Unknown")
                        e_type = item.get("type", "Unknown")

                        if st.button(
                            f"{e_id} ({e_type})",
                            key=f"search_btn_{e_id}",
                        ):
                            if e_type in ("Account", "AMLAccount"):
                                st.session_state.current_account = e_id

                            st.session_state.selected_entity_id = e_id
                            st.rerun()
            else:
                st.caption(
                    f"No matching entities in dataset "
                    f"'{st.session_state.dataset_id}'."
                )

        except Exception as exc:
            st.error(f"Entity search failed: {exc}")

st.markdown(
    "<hr style='margin:4px 0 16px 0; border:none; "
    "border-bottom:1px solid #E2E8F0;'>",
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR — DATASET SWITCHER & INVESTIGATION CONTROLS
# ============================================================

with st.sidebar:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
            <span style="font-size:18px;">🗂️</span>
            <span style="font-size:15px; font-weight:700; color:#0F172A;">Dataset Selection</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dataset_map = {
        "FraudTrace AI Demo (Synthetic)": "demo_synthetic",
        "IBM AMLSim (Transaction Network)": "ibm_amlsim",
    }
    cur_idx = 0 if st.session_state.dataset_id == "demo_synthetic" else 1

    selected_ds_name = st.radio(
        "Dataset",
        options=list(dataset_map.keys()),
        index=cur_idx,
        label_visibility="collapsed",
        key="sidebar_dataset_selector",
    )
    chosen_ds_id = dataset_map[selected_ds_name]

    if chosen_ds_id != st.session_state.dataset_id:
        st.session_state.dataset_id = chosen_ds_id
        if chosen_ds_id == "ibm_amlsim":
            st.session_state.current_account = "AML_ACC_25"
            st.session_state.selected_entity_id = "AML_ACC_25"
            st.session_state["sidebar_account_select"] = "AML_ACC_25"
            st.session_state["sidebar_acc_input"] = "AML_ACC_25"
        else:
            st.session_state.current_account = "ACC002"
            st.session_state.selected_entity_id = "ACC002"
            st.session_state["sidebar_account_select"] = "ACC002"
            st.session_state["sidebar_acc_input"] = "ACC002"
        st.session_state.case_report_pdf = None
        st.session_state.assistant_messages = []
        st.rerun()

    # Safeguard against mismatched account ID in session state across datasets
    if st.session_state.dataset_id == "ibm_amlsim" and not st.session_state.current_account.startswith("AML_"):
        st.session_state.current_account = "AML_ACC_25"
        st.session_state.selected_entity_id = "AML_ACC_25"
        st.session_state["sidebar_account_select"] = "AML_ACC_25"
        st.session_state["sidebar_acc_input"] = "AML_ACC_25"
        st.session_state.case_report_pdf = None
        st.session_state.assistant_messages = []
        st.rerun()
    elif st.session_state.dataset_id == "demo_synthetic" and st.session_state.current_account.startswith("AML_"):
        st.session_state.current_account = "ACC002"
        st.session_state.selected_entity_id = "ACC002"
        st.session_state["sidebar_account_select"] = "ACC002"
        st.session_state["sidebar_acc_input"] = "ACC002"
        st.session_state.case_report_pdf = None
        st.session_state.assistant_messages = []
        st.rerun()

    if st.session_state.dataset_id == "ibm_amlsim":
        st.markdown(
            """
            <div style="background:#EFF6FF; border:1px solid #BFDBFE; border-radius:8px; padding:8px 10px; font-size:11px; color:#1E40AF; margin-bottom:12px;">
                <b>IBM AMLSim Graph</b><br>
                • 30 Accounts · 133 Transactions (45 transfers, 88 cash) · 2 Alerts<br>
                • Synthetic activity generated using IBM AMLSim<br>
                • <i>Note: Device and IP entities not present in this schema.</i>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="background:#F0FDF4; border:1px solid #BBF7D0; border-radius:8px; padding:8px 10px; font-size:11px; color:#166534; margin-bottom:12px;">
                <b>FraudTrace AI Synthetic Demo</b><br>
                • 6 Accounts · 3 Devices · 3 IPs · 3 Merchants<br>
                • Full multi-entity device/IP graph
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='margin:10px 0 14px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)

    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
            <span style="font-size:18px;">🔍</span>
            <span style="font-size:15px; font-weight:700; color:#0F172A;">Investigation Target</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dataset_prefix = (
        "AML_ACC_" if st.session_state.dataset_id == "ibm_amlsim" else "ACC"
    )
    try:
        account_response = api_get(
            "/search",
            params={
                "q": dataset_prefix,
                "limit": 50,
                "dataset": st.session_state.dataset_id,
            },
        )
        account_ids = sorted({
            item["id"]
            for item in account_response.get("results", [])
            if item.get("type") in ("Account", "AMLAccount")
            and item.get("id")
        })
    except RuntimeError as exc:
        account_ids = []
        st.warning(f"Account selector could not load accounts: {exc}")

    if account_ids:
        selected_account = st.session_state.get("sidebar_account_select")
        if selected_account not in account_ids:
            selected_account = (
                st.session_state.current_account
                if st.session_state.current_account in account_ids
                else account_ids[0]
            )
            st.session_state["sidebar_account_select"] = selected_account
        account_input = st.selectbox(
            "Account ID",
            options=account_ids,
            key="sidebar_account_select",
        )
    else:
        st.info(
            f"No accounts are currently available in "
            f"'{st.session_state.dataset_id}'."
        )
        account_input = st.text_input(
            "Account ID",
            value=st.session_state.current_account,
            placeholder="Example: ACC002 or AML_ACC_25",
            key="sidebar_acc_input",
        )

    account_input = account_input.strip().upper()

    col_depth_label, col_depth_sel = st.columns([1, 2])
    with col_depth_label:
        st.markdown("<div style='font-size:13px; font-weight:600; padding-top:6px;'>Graph Depth</div>", unsafe_allow_html=True)
    with col_depth_sel:
        depth_option = st.selectbox(
            "Graph Depth",
            options=[1, 2, 3],
            index=st.session_state.graph_depth - 1,
            label_visibility="collapsed",
        )
        st.session_state.graph_depth = depth_option

    st.markdown("<div style='margin-top:10px; font-size:13px; font-weight:600;'>Entity Filters</div>", unsafe_allow_html=True)
    show_txns = st.checkbox("Show Transactions", value=True)
    show_devices = st.checkbox("Show Devices", value=True, disabled=(st.session_state.dataset_id == "ibm_amlsim"))
    show_ips = st.checkbox("Show IP Addresses", value=True, disabled=(st.session_state.dataset_id == "ibm_amlsim"))
    show_merchants = st.checkbox("Show Merchants", value=True, disabled=(st.session_state.dataset_id == "ibm_amlsim"))

    filter_settings = {
        "show_txns": show_txns,
        "show_devices": show_devices,
        "show_ips": show_ips,
        "show_merchants": show_merchants,
    }

    if st.button("Explore Graph", type="primary", use_container_width=True):
        if account_input:
            st.session_state.current_account = account_input
            st.session_state.selected_entity_id = account_input
            st.session_state.case_report_pdf = None
            st.rerun()
    elif account_input and account_input != st.session_state.current_account:
        st.session_state.current_account = account_input
        st.session_state.selected_entity_id = account_input
        st.session_state.case_report_pdf = None
        st.rerun()

    st.markdown("<hr style='margin:16px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)

    # Dynamic Node Types Legend
    st.markdown("<div style='font-size:13px; font-weight:700; margin-bottom:8px;'>Node Types</div>", unsafe_allow_html=True)
    if st.session_state.dataset_id == "ibm_amlsim":
        st.markdown(
            """
            <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:50%; background:#2563EB; display:inline-block;"></span>
                    <span><b>AMLAccount</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; transform:rotate(45deg); background:#F97316; display:inline-block;"></span>
                    <span><b>AMLTransaction</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:3px; background:#DC2626; display:inline-block;"></span>
                    <span><b>AMLAlert</b> (esc. case)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:3px; background:#64748B; display:inline-block;"></span>
                    <span><b>AMLBranch</b> (cash location)</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:50%; background:#2563EB; display:inline-block;"></span>
                    <span><b>Account</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; transform:rotate(45deg); background:#F97316; display:inline-block;"></span>
                    <span><b>Transaction</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:3px; background:#8B5CF6; display:inline-block;"></span>
                    <span><b>Device</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:2px; background:#10B981; display:inline-block;"></span>
                    <span><b>IP Address</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="width:12px; height:12px; border-radius:50%; background:#F43F5E; display:inline-block;"></span>
                    <span><b>Merchant</b></span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='margin:16px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)

    # Dynamic Relationship Types Legend
    st.markdown("<div style='font-size:13px; font-weight:700; margin-bottom:8px;'>Relationship Types</div>", unsafe_allow_html=True)
    if st.session_state.dataset_id == "ibm_amlsim":
        st.markdown(
            """
            <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#2563EB; font-weight:700;">➔</span>
                    <span><b>AML_SENT</b> (sender)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#10B981; font-weight:700;">➔</span>
                    <span><b>AML_RECEIVED</b> (receiver)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#64748B; font-weight:700;">➔</span>
                    <span><b>AML_AT_BRANCH</b> (cash transaction)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#DC2626; font-weight:700;">➔</span>
                    <span><b>HAS_ALERT</b> (AML alert)</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="font-size:12px; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#F97316; font-weight:700;">➔</span>
                    <span><b>MADE</b> (transaction)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#EF4444; font-weight:700;">➔</span>
                    <span><b>PAID_TO</b> (merchant)</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#8B5CF6; font-weight:700;">➔</span>
                    <span><b>USES_DEVICE</b></span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="color:#10B981; font-weight:700;">➔</span>
                    <span><b>CONNECTS_FROM</b> (IP)</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='margin:16px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)
    active_graph = "ibm_amlsim" if st.session_state.dataset_id == "ibm_amlsim" else "FraudTrace"
    st.caption(f"Backend: FastAPI · Port 8010\nDatabase: FalkorDB Docker\nGraph: {active_graph}")


# ============================================================
# FETCH LIVE DATA FOR CURRENT ACCOUNT & DATASET
# ============================================================

current_acc = st.session_state.current_account
depth = st.session_state.graph_depth
current_ds = st.session_state.dataset_id

try:
    graph_data = api_get(f"/graph/{current_acc}", params={"hops": depth, "dataset": current_ds})
except Exception as exc:
    graph_data = {"nodes": [], "edges": []}
    st.error(f"Could not load graph data: {exc}")

try:
    investigation_data = api_get(f"/investigate/{current_acc}", params={"dataset": current_ds})
except Exception as exc:
    investigation_data = {}
    st.warning(f"Could not load account investigation: {exc}")

try:
    transaction_data = api_get(f"/account-evidence/{current_acc}", params={"dataset": current_ds})
except Exception as exc:
    transaction_data = {}
    st.warning(f"Could not load transaction and alert evidence: {exc}")

network_data = {
    "related_accounts": investigation_data.get("details", [])
}


# ============================================================
# VIEW 1: INVESTIGATION WORKBENCH (PRIMARY)
# ============================================================

if selected_view == "Investigation":
    # 2-column layout: Center Graph (70%) and Right Inspector (30%)
    center_col, right_col = st.columns([7, 3])

    # --------------------------------------------------------
    # CENTER COLUMN: GRAPH WORKSPACE
    # --------------------------------------------------------
    with center_col:
        # Title and Controls Header
        header_l, header_r = st.columns([6, 4])
        with header_l:
            st.markdown(
                f"""
                <div style="font-size:18px; font-weight:700; color:#0F172A;">Fraud Network Graph</div>
                <div style="font-size:12px; color:#64748B;">Connected entities for <b>{current_acc}</b> (depth {depth})</div>
                """,
                unsafe_allow_html=True,
            )
        with header_r:
            layout_choice = st.selectbox(
                "Graph Layout",
                options=["3D Molecular Network", "2D Force Layout", "3D Spherical Orbit"],
                index=0,
                label_visibility="collapsed",
                key="graph_layout_selector",
            )

        # Metric Badges Row
        all_nodes = graph_data.get("nodes", [])
        all_edges = graph_data.get("edges", [])

        if current_ds == "ibm_amlsim":
            acc_count = sum(1 for n in all_nodes if n.get("label") in ("Account", "AMLAccount"))
            txn_count = sum(1 for n in all_nodes if n.get("label") in ("Transaction", "AMLTransaction"))
            alert_count = sum(1 for n in all_nodes if n.get("label") == "AMLAlert")
            branch_count = sum(1 for n in all_nodes if n.get("label") == "AMLBranch")

            st.markdown(
                f"""
                <div class="metric-pill-row">
                    <span class="metric-pill pill-neutral"><b>{len(all_nodes)}</b> Nodes</span>
                    <span class="metric-pill pill-neutral"><b>{len(all_edges)}</b> Relationships</span>
                    <span class="metric-pill pill-accounts"><b>{acc_count}</b> Accounts</span>
                    <span class="metric-pill pill-txns"><b>{txn_count}</b> Transactions</span>
                    <span class="metric-pill" style="background:#FEE2E2; color:#991B1B; border:1px solid #FECACA; padding:4px 10px; border-radius:12px; font-size:12px; font-weight:600;"><b>{alert_count}</b> Alerts</span>
                    <span class="metric-pill pill-neutral"><b>{branch_count}</b> Branches</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            acc_count = sum(1 for n in all_nodes if n.get("label") == "Account")
            txn_count = sum(1 for n in all_nodes if n.get("label") == "Transaction")
            dev_count = sum(1 for n in all_nodes if n.get("label") == "Device")
            mer_count = sum(1 for n in all_nodes if n.get("label") == "Merchant")
            ip_count = sum(1 for n in all_nodes if n.get("label") == "IPAddress")

            st.markdown(
                f"""
                <div class="metric-pill-row">
                    <span class="metric-pill pill-neutral"><b>{len(all_nodes)}</b> Nodes</span>
                    <span class="metric-pill pill-neutral"><b>{len(all_edges)}</b> Relationships</span>
                    <span class="metric-pill pill-accounts"><b>{acc_count}</b> Accounts</span>
                    <span class="metric-pill pill-txns"><b>{txn_count}</b> Transactions</span>
                    <span class="metric-pill pill-devices"><b>{dev_count}</b> Devices</span>
                    <span class="metric-pill pill-merchants"><b>{mer_count}</b> Merchants</span>
                    <span class="metric-pill pill-ips"><b>{ip_count}</b> IP Addresses</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Build filtered NetworkX graph
        g_sub, node_attrs = build_filtered_subgraph(
            all_nodes,
            all_edges,
            target_id=current_acc,
            filters=filter_settings,
        )

        # Node Focus Selector
        all_node_ids = sorted(list(g_sub.nodes()))
        selected_node = st.session_state.selected_entity_id
        if selected_node not in all_node_ids and current_acc in all_node_ids:
            selected_node = current_acc
        if not all_node_ids:
            st.info(
                "No graph nodes were returned. Confirm the account exists "
                "in the selected dataset and that the graph has been imported."
            )

        focus_col1, focus_col2 = st.columns([3, 1])
        with focus_col1:
            picked_node = st.selectbox(
                "Focus / Inspect Node",
                options=all_node_ids or ["No graph nodes available"],
                index=all_node_ids.index(selected_node) if selected_node in all_node_ids else 0,
                key="node_focus_picker",
                disabled=not all_node_ids,
                help="Select any node to inspect details and highlight in the 3D graph.",
            )
            if picked_node in all_node_ids and picked_node != st.session_state.selected_entity_id:
                st.session_state.selected_entity_id = picked_node

        # Render Main Graph
        with st.container(border=True):
            if layout_choice == "2D Force Layout":
                fig = render_2d_force_graph(g_sub, node_attrs, target_id=current_acc, selected_id=picked_node)
            else:
                fig = render_3d_molecular_graph(
                    g_sub,
                    node_attrs,
                    target_id=current_acc,
                    selected_id=picked_node,
                    layout_mode=layout_choice,
                )
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": True, "scrollZoom": True})

    # --------------------------------------------------------
    # RIGHT COLUMN: ENTITY INSPECTION PANEL
    # --------------------------------------------------------
    with right_col:
        inspected_id = st.session_state.selected_entity_id or current_acc
        inspected_attr = node_attrs.get(inspected_id, {})
        inspected_type = inspected_attr.get("label", "Account")
        inspected_props = inspected_attr.get("properties", {})

        # Card 1: Selected Entity
        with st.container(border=True):
            st.markdown(
                f"""
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="font-size:24px;">👤</span>
                        <span style="font-size:18px; font-weight:700; color:#0F172A;">{inspected_id}</span>
                    </div>
                    <span style="background:#EFF6FF; color:#1D4ED8; font-weight:600; font-size:11px; padding:3px 8px; border-radius:12px; border:1px solid #BFDBFE;">
                        {inspected_type}
                    </span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Details
            if inspected_type in ("Account", "AMLAccount"):
                default_risk = "HIGH" if inspected_props.get("is_fraud") else "MEDIUM" if inspected_props.get("suspicious") else investigation_data.get("risk_label", "UNKNOWN")
                risk = inspected_props.get("risk") or default_risk
                risk_upper = str(risk).upper()
                if "HIGH" in risk_upper:
                    risk_badge = '<span class="badge-high-risk">HIGH RISK</span>'
                    priority_text = '<span style="color:#B91C1C; font-weight:700;">HIGH</span>'
                elif "MEDIUM" in risk_upper:
                    risk_badge = '<span class="badge-medium-risk">MEDIUM RISK</span>'
                    priority_text = '<span style="color:#B45309; font-weight:700;">MEDIUM</span>'
                else:
                    risk_badge = '<span class="badge-low-risk">LOW RISK</span>'
                    priority_text = '<span style="color:#15803D; font-weight:700;">LOW</span>'

                total_tx = transaction_data.get("transaction_count", len(transaction_data.get("transactions", [])))
                flagged_tx = transaction_data.get("flagged_transaction_count", 0)
                conn_accs = len(investigation_data.get("related_accounts", []))

                st.markdown(
                    f"""
                    <table style="width:100%; font-size:12px; line-height:2.0;">
                        <tr><td style="color:#64748B;">Account ID</td><td style="font-weight:600; text-align:right;">{inspected_id}</td></tr>
                        <tr><td style="color:#64748B;">Risk Label</td><td style="text-align:right;">{risk_badge}</td></tr>
                        <tr><td style="color:#64748B;">Review Priority</td><td style="text-align:right;">{priority_text}</td></tr>
                        <tr><td style="color:#64748B;">Total Transactions</td><td style="font-weight:600; text-align:right;">{total_tx}</td></tr>
                        <tr><td style="color:#64748B;">Flagged Transactions</td><td style="font-weight:600; text-align:right; color:#B91C1C;">{flagged_tx}</td></tr>
                        <tr><td style="color:#64748B;">Connected Accounts</td><td style="font-weight:600; text-align:right;">{conn_accs}</td></tr>
                    </table>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(f"**Entity ID:** `{inspected_id}`")
                st.markdown(f"**Entity Type:** `{inspected_type}`")
                if inspected_props:
                    st.json(inspected_props)

        # Card 2: Connected Entities
        with st.container(border=True):
            st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>Connected Entities</div>", unsafe_allow_html=True)
            related_acc_list = network_data.get("related_accounts", [])

            if current_ds == "ibm_amlsim":
                ent_tabs = st.tabs(["Accounts", "Transactions", "Alerts"])

                with ent_tabs[0]:
                    if related_acc_list:
                        for item in related_acc_list:
                            acc_id = item["account_id"]
                            prio = item.get("review_priority", "REVIEW")
                            signals = len(item.get("signals", []))
                            p_badge = '<span class="badge-high-risk">High</span>' if prio == "HIGH" else '<span class="badge-medium-risk">Medium</span>' if prio == "MEDIUM" else '<span class="badge-low-risk">Low</span>'
                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <span style="font-weight:600; font-size:12px;">👤 {acc_id}</span>
                                    <div style="display:flex; align-items:center; gap:6px;">
                                        {p_badge}
                                        <span style="font-size:11px; color:#64748B;">{signals} signal(s)</span>
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No connected counterparties found.")

                with ent_tabs[1]:
                    tx_nodes = [n for n in all_nodes if n.get("label") in ("Transaction", "AMLTransaction")]
                    if tx_nodes:
                        for tx in tx_nodes:
                            tx_id = tx["id"]
                            amt = tx.get("properties", {}).get("amount", "")
                            amt_label = f" · ${amt}" if amt else ""
                            st.markdown(f"<div class='entity-row'><b>💳 {tx_id}</b> <span style='font-size:11px; color:#64748B;'>Transaction{amt_label}</span></div>", unsafe_allow_html=True)
                    else:
                        st.caption("No transaction nodes in graph.")

                with ent_tabs[2]:
                    alert_nodes = [n for n in all_nodes if n.get("label") == "AMLAlert" or "AMLAlert" in n.get("labels", [])]
                    if alert_nodes:
                        for al in alert_nodes:
                            al_id = al["id"]
                            pat = al.get("properties", {}).get("pattern", "Alert")
                            st.markdown(f"<div class='entity-row'><b>🚨 {al_id}</b> <span style='font-size:11px; color:#64748B;'>{pat}</span></div>", unsafe_allow_html=True)
                    else:
                        st.caption("No AML alerts in graph.")

            else:
                ent_tabs = st.tabs(["Accounts", "Devices", "IPs", "Merchants"])

                with ent_tabs[0]:
                    if related_acc_list:
                        for item in related_acc_list:
                            acc_id = item["account_id"]
                            prio = item.get("review_priority", "REVIEW")
                            signals = len(item.get("signals", []))
                            p_badge = '<span class="badge-high-risk">High</span>' if prio == "HIGH" else '<span class="badge-medium-risk">Medium</span>' if prio == "MEDIUM" else '<span class="badge-low-risk">Low</span>'
                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <span style="font-weight:600; font-size:12px;">👤 {acc_id}</span>
                                    <div style="display:flex; align-items:center; gap:6px;">
                                        {p_badge}
                                        <span style="font-size:11px; color:#64748B;">{signals} signal(s)</span>
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No connected accounts found.")

                with ent_tabs[1]:
                    shared_devs = investigation_data.get("shared_devices", [])
                    if shared_devs:
                        for dev in shared_devs:
                            st.markdown(f"<div class='entity-row'><b>💻 {dev}</b> <span style='font-size:11px; color:#64748B;'>Device</span></div>", unsafe_allow_html=True)
                    else:
                        st.caption("No devices linked.")

                with ent_tabs[2]:
                    ips = [n["id"] for n in all_nodes if n.get("label") == "IPAddress"]
                    if ips:
                        for ip in ips:
                            st.markdown(f"<div class='entity-row'><b>🌐 {ip}</b> <span style='font-size:11px; color:#64748B;'>IP Address</span></div>", unsafe_allow_html=True)
                    else:
                        st.caption("No IPs linked.")

                with ent_tabs[3]:
                    merchants = [n["id"] for n in all_nodes if n.get("label") == "Merchant"]
                    if merchants:
                        for m in merchants:
                            st.markdown(f"<div class='entity-row'><b>🏪 {m}</b> <span style='font-size:11px; color:#64748B;'>Merchant</span></div>", unsafe_allow_html=True)
                    else:
                        st.caption("No merchants linked.")

        # Card 3: Shared Resources (Adapts dynamically to dataset)
        with st.container(border=True):
            if current_ds == "ibm_amlsim":
                st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>Shared Resources & Transaction Flows</div>", unsafe_allow_html=True)
                res_tabs = st.tabs(["Connected Accounts", "Transaction Flows", "Alerts"])

                # Tab 1: Connected Accounts
                with res_tabs[0]:
                    if related_acc_list:
                        for item in related_acc_list:
                            acc_id = item["account_id"]
                            sent_cnt = len(item.get("sent_transactions", []))
                            recv_cnt = len(item.get("received_transactions", []))
                            shared_alerts = item.get("shared_alerts", [])
                            prio = item.get("review_priority", "REVIEW")
                            p_badge = '<span class="badge-high-risk">High</span>' if prio == "HIGH" else '<span class="badge-medium-risk">Medium</span>' if prio == "MEDIUM" else '<span class="badge-low-risk">Review</span>'

                            flow_parts = []
                            if sent_cnt > 0:
                                flow_parts.append(f"Sent {sent_cnt} txn")
                            if recv_cnt > 0:
                                flow_parts.append(f"Received {recv_cnt} txn")
                            if shared_alerts:
                                flow_parts.append(f"Alert: {', '.join(shared_alerts)}")
                            flow_desc = " · ".join(flow_parts) if flow_parts else "Transaction Counterparty"

                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div>
                                        <b>👤 {acc_id}</b><br>
                                        <span style="font-size:10px; color:#64748B;">{flow_desc}</span>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:6px;">
                                        {p_badge}
                                        <span class="metric-pill pill-accounts">Counterparty</span>
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No connected counterparties found for this account.")

                # Tab 2: Transaction Flows
                with res_tabs[1]:
                    txns = transaction_data.get("transactions", [])
                    if txns:
                        for t in txns[:25]:
                            t_id = t.get("transaction_id", "—")
                            amt = t.get("amount", 0.0)
                            direction = str(t.get("direction", "sent")).lower()
                            cparty = t.get("counterparty") or (
                                f"Branch {t.get('branch_id')}"
                                if t.get("branch_id") is not None
                                else "—"
                            )
                            status = str(t.get("status", "simulated")).lower()

                            arrow = (
                                "🏦 Cash at" if t.get("cash_transaction")
                                else "↗️ Sent to" if direction == "sent"
                                else "↙️ From"
                            )
                            amt_fmt = f"${amt:,.2f}" if isinstance(amt, (int, float)) else str(amt)
                            status_badge = '<span class="badge-high-risk">Flagged</span>' if status == "flagged" else '<span class="metric-pill pill-neutral">Simulated</span>'

                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div>
                                        <b>💳 {t_id}</b><br>
                                        <span style="font-size:10px; color:#64748B;">{arrow} <b>{cparty}</b> · {amt_fmt}</span>
                                    </div>
                                    {status_badge}
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        if len(txns) > 25:
                            st.caption(f"Showing 25 of {len(txns)} transactions.")
                    else:
                        st.caption("No transaction flows found for this account.")

                # Tab 3: Alerts
                with res_tabs[2]:
                    alert_nodes = [n for n in all_nodes if n.get("label") == "AMLAlert" or "AMLAlert" in n.get("labels", [])]
                    direct_alert_ids = set()
                    for e in all_edges:
                        if e.get("relationship") == "HAS_ALERT":
                            if e.get("source") == current_acc:
                                direct_alert_ids.add(e.get("target"))
                            elif e.get("target") == current_acc:
                                direct_alert_ids.add(e.get("source"))

                    if alert_nodes or direct_alert_ids:
                        seen_alerts = set()
                        for al in alert_nodes:
                            al_id = al["id"]
                            seen_alerts.add(al_id)
                            props = al.get("properties", {})
                            pat = props.get("pattern", "cycle")
                            date_str = props.get("event_date", "—")
                            is_direct = al_id in direct_alert_ids

                            badge = '<span class="badge-high-risk">Direct Alert</span>' if is_direct else '<span class="badge-medium-risk">Counterparty</span>'

                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div>
                                        <b>🚨 {al_id}</b><br>
                                        <span style="font-size:10px; color:#64748B;">Check: <b>{pat}</b> · Date: {date_str} · Escalated: {bool(props.get('escalated'))}</span>
                                    </div>
                                    {badge}
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            if props.get("alert_text"):
                                st.caption(props["alert_text"])
                        for al_id in direct_alert_ids:
                            if al_id not in seen_alerts:
                                st.markdown(
                                    f"""
                                    <div class="entity-row">
                                        <div>
                                            <b>🚨 {al_id}</b><br>
                                            <span style="font-size:10px; color:#64748B;">Direct AML Alert</span>
                                        </div>
                                        <span class="badge-high-risk">Direct Alert</span>
                                    </div>
                                    """,
                                    unsafe_allow_html=True,
                                )
                    else:
                        st.caption("No AML alerts linked to this account or immediate counterparties.")

            else:
                st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>Shared Resources</div>", unsafe_allow_html=True)
                res_tabs = st.tabs(["Devices", "IP Addresses", "Merchants"])

                with res_tabs[0]:
                    found_devs = []
                    for item in related_acc_list:
                        for d in item.get("shared_devices", []):
                            found_devs.append((d, item["account_id"]))
                    if found_devs:
                        for d, other_acc in found_devs:
                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div><b>💻 {d}</b><br><span style="font-size:10px; color:#64748B;">Shared with {other_acc}</span></div>
                                    <span class="metric-pill pill-devices">Linked</span>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No shared devices linked to this account.")

                with res_tabs[1]:
                    found_ips = []
                    for item in related_acc_list:
                        for ip in item.get("shared_ips", []):
                            found_ips.append((ip, item["account_id"]))
                    if found_ips:
                        for ip, other_acc in found_ips:
                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div><b>🌐 {ip}</b><br><span style="font-size:10px; color:#64748B;">Shared with {other_acc}</span></div>
                                    <span class="metric-pill pill-ips">Linked</span>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No shared IP addresses linked to this account.")

                with res_tabs[2]:
                    found_merchants = []
                    for item in related_acc_list:
                        for m in item.get("common_merchants", []):
                            found_merchants.append((m, item["account_id"]))
                    if found_merchants:
                        for m, other_acc in found_merchants:
                            st.markdown(
                                f"""
                                <div class="entity-row">
                                    <div><b>🏪 {m}</b><br><span style="font-size:10px; color:#64748B;">Common with {other_acc}</span></div>
                                    <span class="metric-pill pill-merchants">Linked</span>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.caption("No common merchants linked to this account.")

    # --------------------------------------------------------
    # BOTTOM INVESTIGATION WORKSPACE (3-COLUMN LAYOUT)
    # --------------------------------------------------------
    st.markdown("<hr style='margin:16px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)
    b_col1, b_col2, b_col3 = st.columns([1, 1, 1])

    # Bottom 1: Transaction History
    with b_col1:
        with st.container(border=True):
            txns = transaction_data.get("transactions", [])
            st.markdown(
                f"""
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <div style="font-size:14px; font-weight:700;">💳 Transaction History ({len(txns)})</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if txns:
                tx_display = []
                for t in txns:
                    amt = t.get("amount")
                    curr_symbol = "$" if current_ds == "ibm_amlsim" else "₹"
                    amt_str = f"{curr_symbol}{amt:,.2f}" if isinstance(amt, (int, float)) else str(amt or "—")
                    status_badge = '<span class="badge-flagged">Flagged</span>' if str(t.get("status", "")).lower() == "flagged" else '<span class="badge-completed">Completed</span>'
                    target_col = "Counterparty" if current_ds == "ibm_amlsim" else "Merchant"
                    target_val = (
                        t.get("counterparty")
                        or (
                            f"Branch {t.get('branch_id')}"
                            if t.get("branch_id") is not None
                            else t.get("merchant_id", "—")
                        )
                    )
                    tx_display.append({
                        "Transaction ID": t.get("transaction_id"),
                        "Amount": amt_str,
                        target_col: target_val,
                        "Status": t.get("status", "unknown").capitalize(),
                    })
                st.dataframe(pd.DataFrame(tx_display), use_container_width=True, hide_index=True)
            else:
                st.caption("No transaction records found.")

    # Bottom 2: Investigation Path Stepper
    with b_col2:
        with st.container(border=True):
            st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>🔗 Investigation Path</div>", unsafe_allow_html=True)
            path_tab1, path_tab2 = st.tabs(["Shortest Path", "Multi-hop Analysis"])

            paths = investigation_data.get("multi_hop_paths", [])

            with path_tab1:
                if paths:
                    p = paths[0]
                    steps = p.get("steps", [])
                    st.markdown(
                        f"""
                        <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:8px; padding:10px; margin-bottom:10px;">
                            <div style="font-weight:700; font-size:13px; color:#1E40AF; margin-bottom:6px;">
                                {p.get('start_account')} ➔ {p.get('connected_account')} ({len(steps)-1} hops)
                            </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    for i, step in enumerate(steps, start=1):
                        icon = "👤" if (step.startswith("ACC") or step.startswith("AML_ACC")) else "💻" if step.startswith("DEV") else "🌐" if step.startswith("IP") else "🏪" if step.startswith("MER") else "🚨" if step.startswith("AML_ALERT") else "💳"
                        st.markdown(f"**Step {i}:** {icon} `{step}`")
                    st.markdown("</div>", unsafe_allow_html=True)
                else:
                    # Direct connected account path
                    related = investigation_data.get("related_accounts", [])
                    if related:
                        st.markdown(f"**Direct Connection:** `{current_acc}` ➔ [Counterparties & Links] ➔ `{related[0]}`")
                    else:
                        st.caption("No multi-hop path found.")

            with path_tab2:
                if paths:
                    for idx, p in enumerate(paths, start=1):
                        with st.expander(f"Path {idx}: {p.get('start_account')} ➔ {p.get('connected_account')}"):
                            st.write(" → ".join(p.get("steps", [])))
                            for ev in p.get("evidence", []):
                                st.write(f"• {ev}")
                else:
                    st.caption("No multi-hop paths found.")

    # Bottom 3: AI Insights & Key Findings + Quick Ask
    with b_col3:
        with st.container(border=True):
            st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>✨ AI Insights</div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size:12px; font-weight:600; color:#B45309; margin-bottom:6px;'>Key Findings</div>", unsafe_allow_html=True)

            # Bulleted evidence findings
            findings_bullets = []
            rel_accs = investigation_data.get("related_accounts", [])
            shared_devs = investigation_data.get("shared_devices", [])
            flagged_cnt = transaction_data.get("flagged_transaction_count", 0)
            total_tx = transaction_data.get("transaction_count", 0)

            if current_ds == "ibm_amlsim":
                if rel_accs:
                    findings_bullets.append(f"{current_acc} is linked to {len(rel_accs)} counterparty account(s) via transaction network.")
                if flagged_cnt > 0:
                    findings_bullets.append(
                        f"{flagged_cnt} of {total_tx} associated transactions are "
                        "marked flagged by the AMLSim simulation."
                    )
                alerts = transaction_data.get("alerts", [])
                for alert in alerts:
                    findings_bullets.append(
                        f"Alert {alert.get('alert_id')} is linked to this account "
                        f"(check: {alert.get('check_name') or 'unknown'}; "
                        f"date: {alert.get('event_date') or 'unknown'})."
                    )
            else:
                if rel_accs:
                    findings_bullets.append(f"{current_acc} is connected to {len(rel_accs)} other account(s) via shared infrastructure.")
                if flagged_cnt > 0:
                    findings_bullets.append(
                        f"{flagged_cnt} of {total_tx} synthetic transactions "
                        "are flagged for review."
                    )
                if shared_devs:
                    findings_bullets.append(f"Shares device(s) {', '.join(shared_devs)} with neighboring accounts.")
            if not findings_bullets:
                findings_bullets.append(
                    "No connected-account, transaction-flag, or alert evidence "
                    "was returned for this account."
                )

            for b in findings_bullets:
                st.markdown(f"• <span style='font-size:12px;'>{b}</span>", unsafe_allow_html=True)

            st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size:12px; font-weight:600; color:#1D4ED8; margin-bottom:4px;'>Quick Ask</div>", unsafe_allow_html=True)

            quick_q = st.text_input(
                "Quick question",
                placeholder=f"Why is {current_acc} suspicious?",
                label_visibility="collapsed",
                key="quick_ask_input",
            )
            if st.button("Ask", key="quick_ask_btn", use_container_width=True):
                if quick_q.strip():
                    with st.spinner("Investigating..."):
                        try:
                            result = api_post("/ask", {
                                "account_id": current_acc,
                                "question": quick_q.strip(),
                                "session_id": st.session_state.assistant_chat_session_id,
                                "dataset_id": current_ds,
                            })
                            st.session_state.assistant_quick_result = result
                        except Exception as exc:
                            st.session_state.assistant_quick_result = {"answer": f"Request failed: {exc}", "evidence": []}

            if st.session_state.assistant_quick_result:
                qr = st.session_state.assistant_quick_result
                st.markdown(
                    f"<div style='background:#EFF6FF; border:1px solid #BFDBFE; border-radius:8px; padding:8px; font-size:12px; margin-top:6px;'>"
                    f"{qr.get('answer', '')[:400]}"
                    f"</div>",
                    unsafe_allow_html=True,
                )
                st.caption("Open AI Assistant tab for full investigation.")

            disclaimer_note = (
                "IBM AMLSim simulation data. Device and IP entities are not present in this schema."
                if current_ds == "ibm_amlsim"
                else "Synthetic data. Shared infrastructure is an investigative lead, not proof of fraud."
            )
            st.markdown(
                f"""
                <div class="disclaimer-box">
                    <span>ℹ️</span>
                    <span>{disclaimer_note}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ============================================================
# VIEW 2: AI INVESTIGATION ASSISTANT
# ============================================================

elif selected_view == "AI Assistant":
    st.markdown(
        "<div style='font-size:20px; font-weight:800; color:#0F172A; margin-bottom:4px;'>🤖 AI Investigation Assistant</div>"
        "<div style='font-size:13px; color:#64748B; margin-bottom:16px;'>Ask natural language questions. The assistant retrieves live FalkorDB evidence for every question and remembers this session.</div>",
        unsafe_allow_html=True,
    )

    ai_left, ai_right = st.columns([7, 3])

    with ai_left:
        # Account context and session bar
        ctx_col1, ctx_col2, ctx_col3 = st.columns([4, 4, 2])
        with ctx_col1:
            assistant_account = st.text_input(
                "Account context",
                value=st.session_state.current_account,
                key="assistant_account_id",
                help="The account that anchors graph evidence retrieval.",
            ).strip().upper()
        with ctx_col2:
            st.markdown(
                f"<div style='padding-top:28px; font-size:12px; color:#64748B;'>Session: <code>{st.session_state.assistant_chat_session_id[:12]}…</code></div>",
                unsafe_allow_html=True,
            )
        with ctx_col3:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            if st.button("Clear chat", key="clear_assistant_chat", use_container_width=True):
                st.session_state.assistant_messages = []
                st.session_state.assistant_chat_session_id = uuid.uuid4().hex[:16]
                st.session_state.assistant_quick_result = None
                st.rerun()

        # Suggested question chips
        st.markdown("<div style='font-size:12px; font-weight:600; color:#64748B; margin-bottom:6px;'>Suggested questions</div>", unsafe_allow_html=True)
        if current_ds == "ibm_amlsim":
            chip_questions = [
                f"Why is {assistant_account or current_acc} suspicious in AMLSim?",
                f"What transactions are linked to {assistant_account or current_acc}?",
                f"Are there any AML alerts for {assistant_account or current_acc}?",
                "What paths connect AML_ACC_24 and AML_ACC_25?",
                "Which accounts should be reviewed next, and why?",
                f"What is the total transfer volume for {assistant_account or current_acc}?",
            ]
        else:
            chip_questions = [
                f"Why is {assistant_account or current_acc} suspicious?",
                f"Which accounts share devices or IPs with {assistant_account or current_acc}?",
                f"Which transactions associated with {assistant_account or current_acc} are flagged?",
                f"Which merchants are connected to {assistant_account or current_acc}?",
                "What paths connect ACC001 and ACC002?",
                "Which accounts should be reviewed next, and why?",
            ]
        chip_cols = st.columns(3)
        for chip_i, chip_q in enumerate(chip_questions):
            with chip_cols[chip_i % 3]:
                if st.button(
                    chip_q[:55] + ("…" if len(chip_q) > 55 else ""),
                    key=f"chip_{chip_i}",
                    use_container_width=True,
                    help=chip_q,
                ):
                    st.session_state["_prefill_question"] = chip_q

        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)

        # Chat history display
        for msg in st.session_state.assistant_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

                if msg["role"] == "assistant":
                    # Metadata badges
                    badge_html = "<div style='display:flex; flex-wrap:wrap; gap:6px; margin:6px 0;'>"
                    for badge_key, badge_label, badge_color in [
                        ("intent", "Intent", "#1D4ED8"),
                        ("planning_method", "Planning", "#6D28D9"),
                        ("answer_method", "Answer Method", "#0F766E"),
                    ]:
                        val = msg.get(badge_key)
                        if val:
                            badge_html += (
                                f"<span style='background:#EFF6FF; color:{badge_color}; border:1px solid #BFDBFE; "
                                f"border-radius:12px; padding:2px 8px; font-size:11px; font-weight:600;'>"
                                f"{badge_label}: {val}</span>"
                            )
                    mem_status = "Saved" if msg.get("memory_saved") else "Not saved"
                    badge_html += (
                        f"<span style='background:#F0FDF4; color:#166534; border:1px solid #BBF7D0; "
                        f"border-radius:12px; padding:2px 8px; font-size:11px; font-weight:600;'>"
                        f"Memory: {mem_status}</span>"
                    )
                    badge_html += "</div>"
                    st.markdown(badge_html, unsafe_allow_html=True)

                    # Evidence expander
                    evidence_items = msg.get("evidence") or []
                    steps = msg.get("investigation_steps") or []
                    if evidence_items or steps:
                        with st.expander(f"Supporting Graph Evidence ({len(evidence_items)} items)"):
                            render_evidence_items(evidence_items)
                            if steps:
                                st.markdown("**Investigation Steps:**")
                                for s in steps:
                                    status_icon = "✅" if s.get("status") == "completed" else "⚠️"
                                    st.caption(f"{status_icon} `{s.get('step', '')}` — {s.get('status', '')}")

                    if msg.get("warning"):
                        st.caption(msg["warning"])

        # Chat input form
        with st.form("assistant_chat_form", clear_on_submit=True):
            prefill = st.session_state.pop("_prefill_question", "")
            assistant_question = st.text_area(
                "Ask a question",
                value=prefill,
                placeholder=(
                    "Examples:\n"
                    "• Which accounts share devices or IP addresses?\n"
                    "• What is the total value of flagged transactions?\n"
                    "• Compare ACC002 and ACC003.\n"
                    "• Explain the previous finding in simpler terms."
                ),
                height=100,
                max_chars=2000,
                key="assistant_question_input",
            )
            ask_button = st.form_submit_button(
                "🔍 Ask / Investigate",
                type="primary",
                use_container_width=True,
            )

        if ask_button:
            q_text = assistant_question.strip()
            if not q_text:
                st.warning("Enter a question before submitting.")
            elif not assistant_account:
                st.warning("Enter an account ID to anchor the investigation.")
            else:
                st.session_state.assistant_messages.append({"role": "user", "content": q_text})
                with st.spinner("Retrieving graph evidence from FalkorDB and preparing answer…"):
                    try:
                        data = api_post("/ask", {
                            "account_id": assistant_account,
                            "question": q_text,
                            "session_id": st.session_state.assistant_chat_session_id,
                            "dataset_id": current_ds,
                        })
                        st.session_state.assistant_messages.append({
                            "role": "assistant",
                            "content": data.get("answer", "The assistant returned no answer."),
                            "evidence": data.get("evidence") or [],
                            "investigation_steps": data.get("investigation_steps") or [],
                            "intent": data.get("intent"),
                            "planning_method": data.get("planning_method"),
                            "answer_method": data.get("answer_method"),
                            "memory_saved": data.get("memory_saved", False),
                            "warning": data.get("warning", ""),
                        })
                    except Exception as exc:
                        st.session_state.assistant_messages.append({
                            "role": "assistant",
                            "content": f"⚠️ Request failed: `{type(exc).__name__}` — {exc}",
                            "evidence": [],
                        })
                st.rerun()

    with ai_right:
        # Previous Memories Card
        with st.container(border=True):
            st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>📁 Case Memory</div>", unsafe_allow_html=True)
            st.caption(f"Session: `{st.session_state.assistant_chat_session_id[:12]}…`")
            st.markdown(f"**Account:** `{assistant_account or current_acc}`")
            st.markdown(f"**Messages this session:** {len(st.session_state.assistant_messages)}")

            if st.button("Load prior memories", key="load_memories_btn", use_container_width=True):
                try:
                    mem_data = api_get(f"/case-history/{assistant_account or current_acc}", params={"limit": 3, "dataset": current_ds})
                    mems = mem_data.get("memories", [])
                    if mems:
                        for m in mems:
                            st.markdown(
                                f"<div style='background:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; padding:8px; margin-bottom:6px; font-size:11px;'>"
                                f"<b>Q:</b> {m.get('question', '')[:80]}…<br>"
                                f"<b>A:</b> {m.get('answer', '')[:120]}…"
                                "</div>",
                                unsafe_allow_html=True,
                            )
                    else:
                        st.info("No prior memories found.")
                except Exception as exc:
                    st.error(f"Memory load failed: {exc}")

        # Evidence Summary Card
        with st.container(border=True):
            st.markdown("<div style='font-size:14px; font-weight:700; margin-bottom:8px;'>📊 Evidence Summary</div>", unsafe_allow_html=True)
            rel_count = investigation_data.get("related_account_count", len(investigation_data.get("related_accounts", [])))
            txn_count = transaction_data.get("transaction_count", 0)
            flagged_count = transaction_data.get("flagged_transaction_count", 0)
            risk = investigation_data.get("risk_label", "UNKNOWN")
            risk_color = "#B91C1C" if "HIGH" in str(risk).upper() else "#B45309" if "MEDIUM" in str(risk).upper() else "#15803D"
            st.markdown(
                f"""
                <table style='width:100%; font-size:12px; line-height:2.0;'>
                    <tr><td style='color:#64748B;'>Account</td><td style='font-weight:600; text-align:right;'>{assistant_account or current_acc}</td></tr>
                    <tr><td style='color:#64748B;'>Risk Label</td><td style='font-weight:700; text-align:right; color:{risk_color};'>{risk}</td></tr>
                    <tr><td style='color:#64748B;'>Connected Accounts</td><td style='font-weight:600; text-align:right;'>{rel_count}</td></tr>
                    <tr><td style='color:#64748B;'>Total Transactions</td><td style='font-weight:600; text-align:right;'>{txn_count}</td></tr>
                    <tr><td style='color:#64748B;'>Flagged Transactions</td><td style='font-weight:600; text-align:right; color:#B91C1C;'>{flagged_count}</td></tr>
                </table>
                """,
                unsafe_allow_html=True,
            )

        # Navigate to graph
        with st.container(border=True):
            st.markdown("<div style='font-size:13px; font-weight:700; margin-bottom:6px;'>🔗 Graph Navigation</div>", unsafe_allow_html=True)
            st.caption("Focus the graph on any entity from the investigation.")
            focus_id = st.text_input("Entity ID", value=assistant_account or current_acc, key="assistant_graph_focus")
            if st.button("Focus on Graph", key="assistant_focus_btn", use_container_width=True):
                if focus_id.strip():
                    focus_clean = focus_id.strip().upper()
                    st.session_state.selected_entity_id = focus_clean
                    if focus_clean.startswith("ACC"):
                        st.session_state.current_account = focus_clean
                    st.rerun()


# ============================================================
# VIEW 3: GRAPH EXPLORER (PATH FINDER & CLUSTERS)
# ============================================================

elif selected_view == "Graph Explorer":
    st.subheader("🌐 FalkorDB Graph Explorer & Path Finder")
    st.caption("Query real paths between any two entities and discover suspicious rings in FalkorDB.")

    exp_tabs = st.tabs(["Path Finder (Any 2 Entities)", "Suspicious Clusters & Rings", "Live Cypher Query Inspector"])

    # Path Finder Tab
    with exp_tabs[0]:
        col_s, col_t, col_h, col_btn = st.columns([3, 3, 2, 2])
        default_tgt = "AML_ACC_24" if current_ds == "ibm_amlsim" else "ACC001"
        with col_s:
            src_input = st.text_input("Source Entity ID", value=current_acc, key="pf_source").strip().upper()
        with col_t:
            tgt_input = st.text_input("Target Entity ID", value=default_tgt, key="pf_target").strip().upper()
        with col_h:
            hop_limit = st.slider("Max Search Hops", min_value=1, max_value=5, value=4, key="pf_hops")
        with col_btn:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            find_btn = st.button("Find Paths", type="primary", use_container_width=True)

        if find_btn:
            with st.spinner("Finding paths in FalkorDB..."):
                try:
                    path_res = api_get(
                        "/paths",
                        params={
                            "source": src_input,
                            "target": tgt_input,
                            "hops": hop_limit,
                            "dataset": current_ds,
                        },
                    )

                    paths_list = path_res.get("paths", [])
                    st.info(path_res.get("message", "Search completed."))

                    if paths_list:
                        selected_path_idx = st.selectbox(
                            "Select Path to Visualize",
                            options=range(len(paths_list)),
                            format_func=lambda i: (
                                f"Path {i + 1}: "
                                f"{paths_list[i].get('summary', 'Connected path')} "
                                f"({paths_list[i].get('hops', 0)} hops)"
                            ),
                        )

                        chosen_path = paths_list[selected_path_idx]
                        p_nodes = chosen_path.get("steps", [])
                        p_edges = chosen_path.get("relationships", [])

                        st.markdown(
                            f"**Path Steps ({chosen_path.get('hops', 0)} hops):**"
                        )

                        stepper_html = (
                            "<div style='display:flex; flex-wrap:wrap; "
                            "align-items:center; gap:8px; margin-bottom:12px;'>"
                        )

                        for i, step_id in enumerate(p_nodes):
                            step_id = str(step_id)

                            icon = (
                                "👤" if step_id.startswith(("ACC", "AML_ACC"))
                                else "💻" if step_id.startswith("DEV")
                                else "🌐" if step_id.startswith("IP")
                                else "🏪" if step_id.startswith("MER")
                                else "🏦" if step_id.startswith("AML_BRANCH")
                                else "🚨" if step_id.startswith("AML_ALERT")
                                else "💳"
                            )

                            stepper_html += (
                                "<div style='background:#EFF6FF; "
                                "border:1px solid #BFDBFE; border-radius:8px; "
                                "padding:6px 10px; font-size:12px; font-weight:700;'>"
                                f"{icon} {step_id}</div>"
                            )

                            if i < len(p_edges):
                                rel_name = p_edges[i]
                                stepper_html += (
                                    "<div style='color:#2563EB; font-weight:700; "
                                    "font-size:11px;'>"
                                    f"➔ [{rel_name}] ➔</div>"
                                )

                        stepper_html += "</div>"
                        st.markdown(stepper_html, unsafe_allow_html=True)

                        st.markdown("**Path Evidence References:**")

                        evidence = chosen_path.get("evidence", [])
                        if evidence:
                            for ev_line in evidence:
                                st.write(f"• {ev_line}")
                        else:
                            st.caption("No additional evidence references returned.")

                    else:
                        st.warning("No paths were found between these entities.")

                except Exception as exc:
                    st.error(f"Path search failed: {exc}")

    # Suspicious Clusters Tab
    with exp_tabs[1]:
        st.markdown("#### Connected Account Rings Discovered in FalkorDB")
        st.caption(
            "Clusters are grouped using the selected dataset's relationships "
            "and ranked with explainable heuristics, not fraud probabilities."
        )

        try:
            cluster_response = api_get(
                "/clusters",
                params={"dataset": current_ds},
            )
            clusters = cluster_response.get("clusters", [])
            if cluster_response.get("warning"):
                st.caption(cluster_response["warning"])
        except Exception as exc:
            clusters = []
            st.error(f"Cluster analysis failed: {exc}")
        if clusters:
            for c in clusters:
                prio = c["heuristic_priority"]
                badge = '<span class="badge-high-risk">HIGH PRIORITY</span>' if prio == "HIGH" else '<span class="badge-medium-risk">MEDIUM PRIORITY</span>' if prio == "MEDIUM" else '<span class="badge-low-risk">REVIEW</span>'

                with st.expander(f"{c['cluster_id']} — {c['account_count']} Accounts (Score: {c['heuristic_score']})", expanded=True):
                    st.markdown(f"**Priority:** {badge}", unsafe_allow_html=True)
                    st.markdown(f"**Explanation:** {c['explanation']}")

                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown("**Member Accounts:**")
                        for a in c["accounts"]:
                            st.write(f"• 👤 `{a}`")
                    with c2:
                        if current_ds == "ibm_amlsim":
                            st.markdown("**Transaction Links:**")
                            for t in c.get("transactions", []):
                                st.write(f"• 💳 Transaction: `{t}`")
                        else:
                            st.markdown("**Shared Infrastructure:**")
                            for d in c.get("shared_devices", []):
                                st.write(f"• 💻 Device: `{d}`")
                            for ip in c.get("shared_ips", []):
                                st.write(f"• 🌐 IP: `{ip}`")
                            for m in c.get("common_merchants", []):
                                st.write(f"• 🏪 Merchant: `{m}`")
                    with c3:
                        if current_ds == "ibm_amlsim":
                            st.markdown("**AML Alerts:**")
                            if c.get("alerts"):
                                for al in c["alerts"]:
                                    st.write(f"• 🚨 Alert: `{al}`")
                            else:
                                st.caption("No alerts in this cluster.")
                        else:
                            st.markdown("**Flagged Transactions:**")
                            if c.get("flagged_transactions"):
                                for ft in c["flagged_transactions"]:
                                    st.write(f"• 💳 `{ft['transaction_id']}` ({ft['account_id']}) — ₹{ft['amount']:,.2f}")
                            else:
                                st.caption("No flagged transactions.")
        else:
            st.info("No multi-account clusters found.")

    # Live Cypher Inspector
    with exp_tabs[2]:
        st.markdown("#### FalkorDB Cypher Query Inspector")
        st.caption("Verify the actual Cypher queries running against FalkorDB graph storage.")

        root_label = (
            "AMLAccount" if current_ds == "ibm_amlsim" else "Account"
        )
        if current_ds == "ibm_amlsim":
            relationship_query = """
MATCH (a:AMLAccount {id: $account_id})
OPTIONAL MATCH (a)-[:AML_SENT]->(tx:AMLTransaction)-[:AML_RECEIVED]->(b:AMLAccount)
RETURN b.id AS counterparty, collect(DISTINCT tx.id) AS transactions;

MATCH (a:AMLAccount {id: $account_id})-[:HAS_ALERT]->(al:AMLAlert)
RETURN al.id AS alert_id, al.check_name, al.event_date;
"""
        else:
            relationship_query = """
MATCH (a:Account {id: $account_id})
MATCH (b:Account) WHERE a.id <> b.id
OPTIONAL MATCH (a)-[:USES_DEVICE]->(d:Device)<-[:USES_DEVICE]-(b)
OPTIONAL MATCH (a)-[:CONNECTS_FROM]->(ip:IPAddress)<-[:CONNECTS_FROM]-(b)
OPTIONAL MATCH (a)-[:MADE]->(:Transaction)-[:PAID_TO]->(m:Merchant)<-[:PAID_TO]-(:Transaction)<-[:MADE]-(b)
RETURN b.id AS related_account, collect(DISTINCT d.id), collect(DISTINCT ip.id), collect(DISTINCT m.id);
"""
        st.code(
            f"""
// 1. Multi-hop Graph Traversal (Bounded)
MATCH (root:{root_label} {{id: $account_id}})
MATCH path = (root)-[*1..3]-(neighbor)
WHERE length(path) <= $hops
WITH collect(path) AS paths
UNWIND paths AS p
UNWIND nodes(p) AS n
WITH collect(DISTINCT n) AS graph_nodes, paths
UNWIND paths AS p
UNWIND relationships(p) AS r
RETURN graph_nodes, collect(DISTINCT r) AS graph_edges;

// 2. Dataset-specific account and alert/relationship evidence
{relationship_query}
""",
            language="cypher",
        )


# ============================================================
# VIEW 4: CASE MEMORY (TRACK 02 PERSISTENT HISTORY)
# ============================================================

elif selected_view == "Case Memory":
    st.subheader("📁 Persistent Case Memory (Track 02)")
    st.caption("Search and review previous investigations stored in FalkorDB. Survives process restarts.")

    mem_col1, mem_col2 = st.columns([3, 1])
    with mem_col1:
        mem_acc = st.text_input("Account ID for Memory", value=current_acc).strip().upper()
    with mem_col2:
        mem_limit = st.selectbox("Max Records", options=[5, 10, 20, 50], index=1)

    if st.button("Load Case History", type="primary"):
        st.session_state.load_mem_trigger = True

    try:
        mem_data = api_get(f"/case-history/{mem_acc}", params={"limit": mem_limit, "dataset": current_ds})
        memories = mem_data.get("memories", [])

        st.markdown(f"**Retrieved {len(memories)} investigation memories for {mem_acc}:**")

        if memories:
            for idx, m in enumerate(memories, start=1):
                status = m.get("verification_status", "unverified")
                created = m.get("created_at", "Unknown")
                q = m.get("question", "Untitled")
                ans = m.get("answer", "No answer stored.")

                with st.expander(f"{idx}. {q} · {created} [{status}]", expanded=(idx == 1)):
                    st.markdown(f"**Intent:** `{m.get('intent', 'general_investigation')}` | **Session:** `{m.get('session_id', 'default')}`")
                    st.markdown("**AI Investigation Summary:**")
                    st.write(ans)
                    if m.get("evidence"):
                        st.markdown("**Stored Graph Evidence:**")
                        st.json(m["evidence"])
        else:
            st.info("No prior investigation memories stored for this account.")
    except Exception as exc:
        st.error(f"Could not load case history: {exc}")


# ============================================================
# VIEW 5: REPORTS (PDF CASE REPORT GENERATION)
# ============================================================

elif selected_view == "Reports":
    st.subheader("📄 Export Investigation Case Report")
    st.caption("Generate a structured, court-ready PDF containing graph evidence, transaction tables, and AI findings.")

    rep_col1, rep_col2 = st.columns([3, 1])
    with rep_col1:
        rep_acc = st.text_input("Account ID for PDF Report", value=current_acc).strip().upper()
    with rep_col2:
        rep_hops = st.selectbox("Graph Depth in PDF", options=[1, 2, 3], index=2)

    if st.button("Generate PDF Case Report", type="primary"):
        with st.spinner("Generating ReportLab PDF with FalkorDB evidence..."):
            try:
                pdf_bytes = create_case_report_pdf(rep_acc, hops=rep_hops, dataset_id=current_ds)
                st.session_state.case_report_pdf = pdf_bytes
                st.success("Case report generated successfully!")
            except Exception as exc:
                st.error(f"Report generation failed: {exc}")

    if st.session_state.case_report_pdf:
        st.download_button(
            label="⬇️ Download PDF Case Report",
            data=st.session_state.case_report_pdf,
            file_name=f"{rep_acc}_case_report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("<hr style='margin:30px 0 10px 0; border:none; border-bottom:1px solid #E2E8F0;'>", unsafe_allow_html=True)
st.caption(
    "FraudTrace AI · WeMakeDevs × FalkorDB Graph Hacks (Track 01 & Track 02) · "
    "Synthetic demonstration data · Shared infrastructure is an investigative lead, not proof of fraud."
)