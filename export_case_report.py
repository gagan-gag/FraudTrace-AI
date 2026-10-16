
"""
FraudTrace AI — Investigation Case Report Exporter

Fetches evidence from the running FastAPI application and exports
a structured PDF report.

Run:
    python export_case_report.py --account ACC002

Optional:
    python export_case_report.py --account ACC002 --hops 3
    python export_case_report.py --account ACC002 --output reports/ACC002.pdf

The report uses synthetic project data and heuristic risk signals.
It does not establish that an account or person committed fraud.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

DEFAULT_API_URL = "http://127.0.0.1:8010"
REQUEST_TIMEOUT = 20

NAVY = colors.HexColor("#172554")
BLUE = colors.HexColor("#2563EB")
LIGHT_BLUE = colors.HexColor("#EFF6FF")
LIGHT_GREY = colors.HexColor("#F3F4F6")
DARK_GREY = colors.HexColor("#374151")
RED = colors.HexColor("#B91C1C")
AMBER = colors.HexColor("#92400E")
GREEN = colors.HexColor("#166534")


def get_json(
    session: requests.Session,
    base_url: str,
    path: str,
) -> dict[str, Any]:
    """Fetch one API endpoint and require a successful JSON response."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    response = session.get(url, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()

    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError(
            f"Expected a JSON object from {url}, "
            f"received {type(payload).__name__}."
        )

    return payload


def post_json(
    session: requests.Session,
    base_url: str,
    path: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Post JSON to an API endpoint and return its JSON object."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

    response = session.post(
        url,
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    result = response.json()

    if not isinstance(result, dict):
        raise ValueError(
            f"Expected a JSON object from {url}, "
            f"received {type(result).__name__}."
        )

    return result


def sanitize_unicode_for_pdf(text: str) -> str:
    """
    Normalize Unicode characters that standard Helvetica cannot render
    into clean, readable Latin-1 / ASCII equivalents to prevent black squares.
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""

    replacements = {
        "【": "[",
        "】": "]",
        "\u2011": "-",   # Non-breaking hyphen
        "\u2013": " - ", # En-dash
        "\u2014": " - ", # Em-dash
        "\u2018": "'",   # Left single quotation mark
        "\u2019": "'",   # Right single quotation mark
        "\u201c": '"',   # Left double quotation mark
        "\u201d": '"',   # Right double quotation mark
        "→": "->",       # Right arrow
        "➔": "->",       # Heavy right arrow
        "⟶": "->",       # Long right arrow
        "•": "*",        # Bullet symbol
        "●": "*",        # Black circle
        "₹": "INR ",     # Indian Rupee symbol
    }

    for k, v in replacements.items():
        text = text.replace(k, v)

    # Strip emojis or exotic non-Latin-1 symbols that trigger .notdef missing glyph boxes
    cleaned = []
    for ch in text:
        if ord(ch) < 256:
            cleaned.append(ch)
        else:
            cleaned.append(" ")
    return "".join(cleaned)


def format_inline_markdown(text: str) -> str:
    """Convert Markdown bold, italics, code, and sanitize Unicode for ReportLab Paragraphs."""
    text = sanitize_unicode_for_pdf(text)
    text = escape(text)

    # Convert bold: **bold** or __bold__ to <b>bold</b>
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__", r"<b>\1</b>", text)

    # Convert italic: *italic* or _italic_ to <i>italic</i>
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", text)

    # Convert inline code: `code` to <font name="Courier">code</font>
    text = re.sub(r"`(.+?)`", r'<font name="Courier">\1</font>', text)

    return text


def printable(value: Any, limit: int = 1800) -> str:
    """Convert arbitrary API values into readable report text."""
    if value is None:
        return "Not provided"

    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    else:
        text = str(value)

    if len(text) > limit:
        text = text[:limit] + "\n... [truncated]"

    return text


def safe_paragraph(value: Any, limit: int = 1800) -> str:
    """Escape and format API-supplied text before rendering it as a PDF paragraph."""
    raw = printable(value, limit)
    formatted = format_inline_markdown(raw)
    return formatted.replace("\n", "<br/>")


def first_value(
    data: dict[str, Any],
    keys: tuple[str, ...],
    default: Any = None,
) -> Any:
    """Return the first present, non-empty field from a dictionary."""
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return default


def make_styles():
    """Create consistent report typography."""
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=29,
            textColor=NAVY,
            alignment=TA_CENTER,
            spaceAfter=10,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CoverSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=15,
            textColor=DARK_GREY,
            alignment=TA_CENTER,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=13,
            spaceAfter=7,
            keepWithNext=True,
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=DARK_GREY,
            spaceAfter=5,
        )
    )

    styles.add(
        ParagraphStyle(
            name="TableCell",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=10,
            textColor=DARK_GREY,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="TableHeader",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=colors.white,
        )
    )

    styles.add(
        ParagraphStyle(
            name="Warning",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=AMBER,
            backColor=colors.HexColor("#FFFBEB"),
            borderColor=colors.HexColor("#FDE68A"),
            borderWidth=0.6,
            borderPadding=7,
            spaceBefore=5,
            spaceAfter=7,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallMuted",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#6B7280"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="SubHeading",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            textColor=NAVY,
            spaceBefore=6,
            spaceAfter=3,
            keepWithNext=True,
        )
    )

    styles.add(
        ParagraphStyle(
            name="NumberedItem",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=DARK_GREY,
            leftIndent=14,
            firstLineIndent=-10,
            spaceAfter=3,
        )
    )

    styles.add(
        ParagraphStyle(
            name="BulletItem",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=12,
            textColor=DARK_GREY,
            leftIndent=14,
            firstLineIndent=-8,
            spaceAfter=3,
        )
    )

    return styles


def add_markdown_flowables(story, markdown_text: str, styles):
    """
    Parse a Markdown string (headings, numbered steps, bullet points, bold sections)
    into cleanly styled ReportLab Flowable paragraphs without raw markdown markers.
    """
    if not markdown_text:
        return

    lines = str(markdown_text).splitlines()
    for line in lines:
        line_strip = line.strip()
        if not line_strip:
            continue

        # Markdown headings: ###, ##, #
        heading_match = re.match(r"^#{1,4}\s+(.+)$", line_strip)
        if heading_match:
            heading_content = format_inline_markdown(heading_match.group(1))
            story.append(Paragraph(heading_content, styles["SubHeading"]))
            continue

        # Numbered list: 1. ...
        numbered_match = re.match(r"^(\d+)\.\s+(.+)$", line_strip)
        if numbered_match:
            num = numbered_match.group(1)
            content = format_inline_markdown(numbered_match.group(2))
            story.append(Paragraph(f"<b>{num}.</b> {content}", styles["NumberedItem"]))
            continue

        # Bullet list: * ... or - ...
        bullet_match = re.match(r"^[\*\-]\s+(.+)$", line_strip)
        if bullet_match:
            content = format_inline_markdown(bullet_match.group(1))
            story.append(Paragraph(f"&bull;&nbsp; {content}", styles["BulletItem"]))
            continue

        # Standard paragraph with inline formatting
        formatted_line = format_inline_markdown(line_strip)
        story.append(Paragraph(formatted_line, styles["BodySmall"]))


def make_table(
    headers: list[str],
    rows: list[list[Any]],
    widths: list[float],
    styles,
):
    """Create a repeating-header PDF table with readable cell wrapping."""
    formatted = [
        [Paragraph(safe_paragraph(header), styles["TableHeader"])
         for header in headers]
    ]

    for row in rows:
        formatted.append(
            [
                Paragraph(safe_paragraph(value, limit=800), styles["TableCell"])
                for value in row
            ]
        )

    table = Table(
        formatted,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#D1D5DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    LIGHT_GREY,
                ]),
            ]
        )
    )

    return table


def add_dictionary_section(story, title, data, styles):
    """Display structured API output without assuming its exact schema."""
    story.append(Paragraph(title, styles["SectionHeading"]))

    if not isinstance(data, dict) or not data:
        story.append(
            Paragraph("No structured data was returned.", styles["BodySmall"])
        )
        return

    rows = [[key, printable(value, limit=900)] for key, value in data.items()]

    story.append(
        make_table(
            ["Field", "Value"],
            rows,
            [42 * mm, 126 * mm],
            styles,
        )
    )
    story.append(Spacer(1, 4 * mm))


def add_list_section(story, title, items, styles):
    """Display a list of evidence items in a readable table."""
    story.append(Paragraph(title, styles["SectionHeading"]))

    if not isinstance(items, list) or not items:
        story.append(
            Paragraph("No items were returned for this section.", styles["BodySmall"])
        )
        return

    if all(isinstance(item, dict) for item in items):
        keys = []
        for item in items:
            for key in item.keys():
                if key not in keys:
                    keys.append(key)

        # Limit very wide reports while retaining representative fields.
        keys = keys[:7]
        rows = [[printable(item.get(key)) for key in keys] for item in items]

        story.append(
            make_table(
                keys,
                rows,
                [168 * mm / max(len(keys), 1)] * len(keys),
                styles,
            )
        )
    else:
        for index, item in enumerate(items, start=1):
            story.append(
                Paragraph(
                    f"<b>{index}.</b> {safe_paragraph(item, limit=1200)}",
                    styles["BodySmall"],
                )
            )

    story.append(Spacer(1, 4 * mm))


def add_graph_section(story, graph_data, styles):
    """Summarize the graph response and list its nodes and relationships."""
    story.append(Paragraph("Graph Investigation", styles["SectionHeading"]))

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not isinstance(nodes, list):
        nodes = []
    if not isinstance(edges, list):
        edges = []

    story.append(
        Paragraph(
            f"Traversal depth: {graph_data.get('hops', 'as requested')} | "
            f"Returned nodes: {len(nodes)} | "
            f"Returned relationships: {len(edges)}",
            styles["BodySmall"],
        )
    )

    node_rows = []

    for node in nodes:
        if not isinstance(node, dict):
            continue

        node_rows.append(
            [
                node.get("id", "Unknown"),
                ", ".join(node.get("labels", []))
                if isinstance(node.get("labels"), list)
                else node.get("labels", ""),
                printable(node.get("properties", {}), limit=450),
            ]
        )

    story.append(Paragraph("Graph nodes", styles["Heading3"]))

    if node_rows:
        story.append(
            make_table(
                ["Node ID", "Labels", "Properties"],
                node_rows,
                [34 * mm, 36 * mm, 98 * mm],
                styles,
            )
        )
    else:
        story.append(
            Paragraph("No graph nodes were returned.", styles["BodySmall"])
        )

    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Graph relationships", styles["Heading3"]))

    edge_rows = []

    for edge in edges:
        if not isinstance(edge, dict):
            continue

        edge_rows.append(
            [
                edge.get("source", "Unknown"),
                edge.get("relationship", "Unknown"),
                edge.get("target", "Unknown"),
            ]
        )

    if edge_rows:
        story.append(
            make_table(
                ["Source", "Relationship", "Target"],
                edge_rows,
                [48 * mm, 58 * mm, 62 * mm],
                styles,
            )
        )
    else:
        story.append(
            Paragraph("No graph relationships were returned.", styles["BodySmall"])
        )

    story.append(Spacer(1, 4 * mm))


def draw_page(canvas, document):
    """Add page numbering and a discreet report footer."""
    canvas.saveState()

    page_width, _ = A4

    canvas.setStrokeColor(colors.HexColor("#D1D5DB"))
    canvas.setLineWidth(0.5)
    canvas.line(
        20 * mm,
        15 * mm,
        page_width - 20 * mm,
        15 * mm,
    )

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#6B7280"))
    canvas.drawString(
        20 * mm,
        10 * mm,
        "FraudTrace AI | Synthetic demonstration data",
    )
    canvas.drawRightString(
        page_width - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


def build_report(
    output_path: Path,
    account_id: str,
    investigation: dict[str, Any],
    account_evidence: dict[str, Any],
    graph_data: dict[str, Any],
    assistant: dict[str, Any],
    hops: int,
    dataset_id: str = "demo_synthetic",
    dataset_metadata: dict[str, Any] | None = None,
):
    """Build the complete PDF case report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = make_styles()
    story = []

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    dataset_name = (dataset_metadata or {}).get(
        "display_name",
        "FraudTrace AI Synthetic Demo" if dataset_id == "demo_synthetic" else "IBM AMLSim Sample Dataset",
    )

    story.append(Spacer(1, 12 * mm))
    story.append(Paragraph("FRAUDTRACE AI", styles["CoverTitle"]))
    story.append(
        Paragraph(
            "Account Investigation Case Report",
            styles["CoverSubtitle"],
        )
    )
    story.append(Spacer(1, 7 * mm))

    overview_rows = [
        ["Case account", account_id],
        ["Dataset", f"{dataset_name} ({dataset_id})"],
        ["Generated at", generated_at],
        ["Graph traversal depth", str(hops)],
        [
            "Investigation label",
            printable(
                first_value(
                    investigation,
                    ("risk_label", "risk_level", "label"),
                    "Not provided",
                )
            ),
        ],
        [
            "Transaction count",
            str(
                first_value(
                    account_evidence,
                    ("transaction_count",),
                    "Not provided",
                )
            ),
        ],
        [
            "Flagged transaction count",
            str(
                first_value(
                    account_evidence,
                    ("flagged_transaction_count",),
                    "Not provided",
                )
            ),
        ],
        [
            "Linked alert count",
            str(first_value(account_evidence, ("alert_count",), 0)),
        ],
        [
            "Graph nodes",
            str(len(graph_data.get("nodes", []))),
        ],
        [
            "Graph relationships",
            str(len(graph_data.get("edges", []))),
        ],
    ]

    story.append(
        make_table(
            ["Case field", "Value"],
            overview_rows,
            [55 * mm, 113 * mm],
            styles,
        )
    )

    story.append(Spacer(1, 5 * mm))

    disclaimer_text = (
        (dataset_metadata or {}).get("disclaimer")
        or (
            "IBM AMLSim transaction simulation data. Device/IP and merchant relationships are not present in this schema. "
            "A risk label or flagged transaction is a review signal, not a determination of criminal activity."
            if dataset_id == "ibm_amlsim"
            else (
                "This report summarizes the evidence returned by the FraudTrace AI demonstration system. "
                "A risk label or flagged transaction is a review signal, not a determination of criminal activity. "
                "Shared devices, IP addresses, or merchants can have legitimate explanations."
            )
        )
    )

    story.append(
        Paragraph(
            f"<b>Scope and limitation:</b> {disclaimer_text}",
            styles["Warning"],
        )
    )

    story.append(Paragraph("Investigation Finding", styles["SectionHeading"]))
    finding = first_value(
        investigation,
        ("finding", "summary", "conclusion"),
        "The API did not provide a separate investigation finding.",
    )
    story.append(
        Paragraph(safe_paragraph(finding, limit=3500), styles["BodySmall"])
    )

    warning = first_value(
        investigation,
        ("warning",),
        account_evidence.get("warning"),
    )
    if warning:
        story.append(
            Paragraph(
                f"<b>System warning:</b> {safe_paragraph(warning, limit=1500)}",
                styles["Warning"],
            )
        )

    related_accounts = first_value(
        investigation,
        ("related_accounts", "connected_accounts"),
        [],
    )
    add_list_section(
        story,
        "Related Accounts",
        related_accounts if isinstance(related_accounts, list) else [],
        styles,
    )

    shared_devices = first_value(
        investigation,
        ("shared_devices",),
        [],
    )
    add_list_section(
        story,
        "Shared Device Signals",
        shared_devices if isinstance(shared_devices, list) else [],
        styles,
    )

    multi_hop_paths = first_value(
        investigation,
        ("multi_hop_paths", "paths"),
        [],
    )
    add_list_section(
        story,
        "Multi-Hop Investigation Paths",
        multi_hop_paths if isinstance(multi_hop_paths, list) else [],
        styles,
    )

    transactions = first_value(
        account_evidence,
        ("transactions",),
        [],
    )
    add_list_section(
        story,
        "Transaction Evidence",
        transactions if isinstance(transactions, list) else [],
        styles,
    )

    alerts = first_value(account_evidence, ("alerts",), [])
    add_list_section(
        story,
        "Linked AML Alerts",
        alerts if isinstance(alerts, list) else [],
        styles,
    )

    add_graph_section(story, graph_data, styles)

    story.append(Paragraph("Investigation Assistant", styles["SectionHeading"]))
    question = assistant.get("question", "Why is this account suspicious?")
    answer = assistant.get("answer", "No assistant answer was returned.")

    story.append(
        Paragraph(
            f"<b>Question:</b> {safe_paragraph(question, limit=1200)}",
            styles["BodySmall"],
        )
    )
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("<b>Assistant Findings & Analysis:</b>", styles["SubHeading"]))
    add_markdown_flowables(story, answer, styles)
    story.append(Spacer(1, 3 * mm))

    assistant_evidence = assistant.get("evidence", [])
    if isinstance(assistant_evidence, list) and assistant_evidence:
        add_list_section(
            story,
            "Assistant Evidence",
            assistant_evidence,
            styles,
        )

    assistant_warning = assistant.get("warning")
    if assistant_warning:
        story.append(
            Paragraph(
                f"<b>Assistant limitation:</b> "
                f"{safe_paragraph(assistant_warning, limit=1500)}",
                styles["Warning"],
            )
        )

    story.append(Paragraph("Audit Notes", styles["SectionHeading"]))
    story.append(
        Paragraph(
            "This report was generated from the API responses available at "
            "the time of export. It is not a forensic certification or an "
            "automated determination of fraud. Analysts should verify "
            "source records, consider alternative explanations, and follow "
            "their organization's review and escalation procedures.",
            styles["BodySmall"],
        )
    )

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=21 * mm,
        title=f"FraudTrace AI Investigation — {account_id}",
        author="FraudTrace AI",
        subject="Account investigation and graph evidence",
    )

    doc.build(
        story,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Export a FraudTrace AI investigation to PDF."
    )
    parser.add_argument(
        "--account",
        default="ACC002",
        help="Account ID to investigate (default: ACC002)",
    )
    parser.add_argument(
        "--hops",
        type=int,
        choices=(1, 2, 3),
        default=3,
        help="Graph traversal depth: 1, 2, or 3 (default: 3)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output PDF path (default: reports/<ACCOUNT>_case_report.pdf)",
    )
    parser.add_argument(
        "--api",
        default=DEFAULT_API_URL,
        help=f"FastAPI base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--dataset",
        default="demo_synthetic",
        help="Dataset identifier: demo_synthetic or ibm_amlsim (default: demo_synthetic)",
    )

    args = parser.parse_args()
    account_id = args.account.strip().upper()
    dataset_id = args.dataset.strip()

    if not account_id:
        parser.error("--account cannot be empty")

    output_path = Path(
        args.output
        or f"reports/{account_id}_case_report.pdf"
    )

    print("=" * 60)
    print("FRAUDTRACE AI — CASE REPORT EXPORT")
    print("=" * 60)
    print(f"Account: {account_id}")
    print(f"Dataset: {dataset_id}")
    print(f"Graph depth: {args.hops}")
    print(f"API: {args.api}")
    print(f"Output: {output_path}")
    print()

    try:
        with requests.Session() as session:
            print("[1/5] Checking API health...")
            health = get_json(session, args.api, "/health")

            if str(health.get("status", "")).lower() not in (
                "ok",
                "healthy",
                "success",
            ):
                print(
                    "Warning: health endpoint returned an unexpected "
                    f"status: {health.get('status')}"
                )

            print("[2/5] Fetching investigation...")
            investigation = get_json(
                session,
                args.api,
                f"/investigate/{account_id}?dataset={dataset_id}",
            )

            print("[3/5] Fetching transaction evidence...")
            account_evidence = get_json(
                session,
                args.api,
                f"/account-evidence/{account_id}?dataset={dataset_id}",
            )

            print("[4/5] Fetching graph and assistant evidence...")
            graph_data = get_json(
                session,
                args.api,
                f"/graph/{account_id}?hops={args.hops}&dataset={dataset_id}",
            )

            assistant = post_json(
                session,
                args.api,
                "/ask",
                {
                    "account_id": account_id,
                    "question": "Why is this account suspicious?",
                    "dataset_id": dataset_id,
                },
            )

        if not graph_data.get("nodes"):
            raise ValueError(
                f"No graph nodes returned for {account_id}. "
                "Verify that the account exists and the graph is seeded."
            )

        print("[5/5] Building PDF...")
        build_report(
            output_path=output_path,
            account_id=account_id,
            investigation=investigation,
            account_evidence=account_evidence,
            graph_data=graph_data,
            assistant=assistant,
            hops=args.hops,
            dataset_id=dataset_id,
        )

        print()
        print("=" * 60)
        print("REPORT GENERATED SUCCESSFULLY")
        print("=" * 60)
        print(f"File: {output_path.resolve()}")
        print(f"Size: {output_path.stat().st_size:,} bytes")
        print("Open the PDF and verify the report before sharing it.")

    except requests.RequestException as exc:
        print(f"\nERROR: Could not retrieve data from the API.\n{exc}")
        print(
            "\nConfirm that FalkorDB and FastAPI are running, "
            "then retry."
        )
        sys.exit(1)

    except (ValueError, OSError, KeyError) as exc:
        print(f"\nERROR: Report generation failed.\n{exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
