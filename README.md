# FraudTrace AI
### Graph-Powered Fraud Investigation with FalkorDB

FraudTrace AI is a graph-powered investigation platform that helps analysts explore suspicious transaction activity, discover relationships between accounts, inspect shared infrastructure, and generate evidence-based case reports.

Instead of examining each transaction in isolation, FraudTrace AI uses **FalkorDB** to traverse relationships between accounts, devices, IP addresses, transactions, and merchants. Investigators can explore connected entities at different graph depths, inspect the evidence behind an investigation, and export a structured PDF report.

> **Important:** This project currently uses synthetic demonstration data. Its findings are investigative leads, not proof of fraud. The current investigation assistant uses deterministic reasoning and graph evidence; it does not use a large language model.

## Features

- **Graph-powered investigation:** Query connected entities and relationships using FalkorDB.
- **Multi-hop relationship exploration:** Expand investigations across graph depths 1, 2, and 3.
- **Connected-account signals:** Examine shared devices, IP addresses, and merchants.
- **Transaction evidence:** Inspect transaction amounts, merchant associations, and transaction status.
- **Interactive dashboard:** Explore investigations through a Streamlit interface.
- **Investigation assistant:** Receive deterministic, evidence-based investigation summaries.
- **PDF case reports:** Export findings, related accounts, transaction evidence, graph relationships, assistant evidence, and audit notes.
- **REST API:** Access investigation functionality through FastAPI endpoints.
- **Automated tests:** Validate API behavior, graph traversal, input validation, and PDF generation.

## Problem Statement

Fraud investigations can become difficult when relevant evidence is distributed across multiple accounts, transactions, devices, IP addresses, and merchants.

Traditional transaction-by-transaction review may fail to make these connections immediately visible.

FraudTrace AI models these entities as a graph, allowing investigators to follow relationships and identify patterns that deserve further review.

## Solution Architecture

The application uses the following architecture:

1. **Streamlit dashboard:** Provides the investigation interface, graph exploration controls, assistant interaction, and report export.
2. **FastAPI backend:** Exposes endpoints for account investigations, transaction evidence, graph traversal, and assistant responses.
3. **FalkorDB graph database:** Stores entities and relationships used for multi-hop investigation.
4. **Investigation logic:** Collects connected-account signals and constructs evidence-based findings.
5. **PDF report exporter:** Generates a case report from the available API responses.

### Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Graph database | FalkorDB |
| API framework | FastAPI |
| API validation | Pydantic |
| Dashboard | Streamlit |
| Graph visualization | Plotly and NetworkX |
| Data presentation | Pandas |
| PDF generation | ReportLab |
| API testing | Python `unittest` and smoke-test script |

## Graph Data Model

FraudTrace AI uses five principal node types.

| Node label | Purpose | Example |
|---|---|---|
| `Account` | Represents a customer account | `ACC002` |
| `Device` | Represents a device associated with an account | `DEV002` |
| `IPAddress` | Represents an IP address associated with an account | `IP002` |
| `Transaction` | Represents a transaction | `TXN002` |
| `Merchant` | Represents a merchant receiving a transaction | `MER001` |

### Relationships

| Relationship | Direction | Meaning |
|---|---|---|
| `USES_DEVICE` | Account → Device | An account is associated with a device |
| `CONNECTS_FROM` | Account → IPAddress | An account is associated with an IP address |
| `MADE` | Account → Transaction | An account made a transaction |
| `PAID_TO` | Transaction → Merchant | A transaction is associated with a merchant |

### Example Investigation

A graph investigation can reveal that multiple accounts share a device or IP address. Those relationships can be followed to inspect other connected accounts and their transaction activity.

For example, the synthetic `ACC002` case includes shared-device and shared-IP relationships involving `ACC003` and `ACC006`. The case also contains flagged transaction `TXN002`, with an amount of 8,700 in the dataset.

These facts demonstrate graph investigation functionality. They do not establish that the accounts are controlled by the same person or that a crime occurred.

## Example Cypher Queries

The following examples illustrate how the graph can support investigation.

### 1. Find accounts sharing a device

```cypher
MATCH (a:Account)-[:USES_DEVICE]->(d:Device)<-[:USES_DEVICE]-(other:Account)
WHERE a.id = $account_id
  AND other.id <> a.id
RETURN
    a.id AS investigated_account,
    d.id AS shared_device,
    other.id AS connected_account
```

### 2. Find accounts sharing an IP address

```cypher
MATCH (a:Account)-[:CONNECTS_FROM]->(ip:IPAddress)<-[:CONNECTS_FROM]-(other:Account)
WHERE a.id = $account_id
  AND other.id <> a.id
RETURN
    a.id AS investigated_account,
    ip.id AS shared_ip,
    other.id AS connected_account
```

### 3. Inspect an account's transactions and merchants

```cypher
MATCH (a:Account)-[:MADE]->(t:Transaction)-[:PAID_TO]->(m:Merchant)
WHERE a.id = $account_id
RETURN
    a.id AS account_id,
    t.id AS transaction_id,
    t.amount AS amount,
    t.status AS status,
    m.id AS merchant_id
```

### 4. Explore a bounded multi-hop graph

```cypher
MATCH (root:Account {id: $account_id})
MATCH path = (root)-[*1..3]-(neighbor)
WHERE length(path) <= $hops
RETURN path
```

The production API uses a bounded traversal and returns graph nodes and relationships in a structured response for the dashboard.

**Note:** The examples are intended to explain the graph model. The application may use more detailed queries for its actual endpoints.

## Project Structure

```text
FraudTrace AI/
├── app.py
├── dashboard.py
├── seed_graph.py
├── inspect_graph.py
├── investigate.py
├── ring_detection.py
├── ai_assistant.py
├── export_case_report.py
├── test_falkordb.py
├── smoke_test.py
├── test_case_report.py
├── reports/
│   └── ACC002_case_report.pdf
└── README.md
```

The `reports/` directory is generated output. Keep a sample PDF in the repository only if you intend to publish it as a synthetic demonstration artifact.

## Local Setup

### Prerequisites

- Python installed
- Docker Desktop installed and running
- Git installed
- A Windows PowerShell terminal

### 1. Clone the repository

After publishing the project to a Git repository, use your actual repository URL:

```powershell
git clone YOUR_PUBLIC_REPOSITORY_URL
cd "FraudTrace AI"
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

### 3. Install dependencies

Install the packages used by the application:

```powershell
python -m pip install fastapi uvicorn falkordb streamlit plotly requests pandas networkx reportlab
```

If the repository contains a maintained `requirements.txt`, prefer installing the pinned project dependencies with:

```powershell
python -m pip install -r requirements.txt
```

### 4. Start FalkorDB

If you do not already have a FalkorDB container, start one with:

```powershell
docker run -d --name falkordb -p 6379:6379 -p 3001:3000 falkordb/falkordb:latest
```

If the container already exists, start it instead:

```powershell
docker start falkordb
```

Verify the container:

```powershell
docker ps
```

The application expects FalkorDB at `localhost:6379`. The optional browser interface is exposed on host port `3001` by the command above.

### 5. Seed the demonstration graph

Run the graph seeding script:

```powershell
python seed_graph.py
```

Use the graph initialization script provided by the project if your setup requires an explicit reset or initialization step. Do not seed repeatedly unless you know whether the script clears existing data or creates duplicate records.

### 6. Start the FastAPI backend

Open a terminal in the project directory:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app:app --host 127.0.0.1 --port 8010
```

API documentation:

- API root: `http://127.0.0.1:8010/`
- Health check: `http://127.0.0.1:8010/health`
- Interactive API docs: `http://127.0.0.1:8010/docs`

### 7. Start the dashboard

Open another terminal:

```powershell
cd "D:\PROJECTS\FraudTrace AI"
.\.venv\Scripts\Activate.ps1
streamlit run dashboard.py
```

Open the local Streamlit URL printed in the terminal.

## API Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | API root |
| `GET /health` | Check API and database health |
| `GET /investigate/{account_id}` | Investigate connected-account signals |
| `GET /account-evidence/{account_id}` | Retrieve account transaction evidence |
| `GET /graph/{account_id}?hops=2` | Retrieve a bounded graph neighborhood |
| `POST /ask` | Request a deterministic investigation response |
| `GET /docs` | Explore API documentation |

Example graph request:

```text
GET /graph/ACC002?hops=3
```

Supported graph depths are 1 through 3.

Example assistant request:

```json
{
  "account_id": "ACC002",
  "question": "Why is this account suspicious?"
}
```

The API returns a structured response containing the question, answer, evidence, and applicable warning.

## Testing

Run the backend smoke tests:

```powershell
python smoke_test.py
```

Run the PDF report regression tests:

```powershell
python -m unittest test_case_report -v
```

The current development environment has passed:

- 28 API smoke checks
- 5 PDF exporter regression tests

These results validate the tested code paths in the development environment. They are not a benchmark of real-world fraud detection accuracy.

## AI and Decision Transparency

The current investigation assistant uses deterministic reasoning over graph evidence. It does not yet use a large language model.

The system surfaces connected-account signals, transaction status, graph relationships, and supporting evidence. Review priorities are heuristic signals rather than calibrated fraud probabilities.

The platform is intended to assist human investigation. It should not automatically accuse users, suspend accounts, or treat a shared device or IP address as conclusive evidence.

## Limitations and Responsible Use

- All current demonstration records are synthetic.
- A flagged transaction is a review signal, not proof of fraud.
- Legitimate users may share devices, networks, and merchants.
- Graph connections can identify leads but cannot independently establish intent or identity.
- No real-world precision, recall, false-positive rate, or financial-loss reduction claim is made by this demonstration.
- Production use would require representative data, privacy controls, access controls, auditability, evaluation on held-out data, and human review.

## Demo Walkthrough

A short demonstration can follow this sequence:

1. Open the Streamlit dashboard.
2. Investigate `ACC002`.
3. Review connected accounts and shared-device signals.
4. Expand graph traversal from depth 1 to depth 3.
5. Inspect transaction evidence.
6. Ask the investigation assistant why the account was flagged for review.
7. Generate and download the PDF case report.
8. Explain how FalkorDB represents and traverses connected entities.
9. Close by explaining the synthetic-data limitation and the role of human review.

## Hackathon Submission Checklist

- [ ] Publish the repository with public access.
- [ ] Confirm the README setup instructions work from a clean environment.
- [ ] Include a clear graph schema and representative Cypher queries.
- [ ] Confirm all required dependencies are documented.
- [ ] Run the smoke tests and PDF regression tests.
- [ ] Record a short demo showing the working application.
- [ ] Verify that the demo video and repository links are accessible.
- [ ] State the selected hackathon track accurately.
- [ ] Disclose AI-assisted development according to the event's rules.
- [ ] Remove credentials, tokens, private data, and local-only paths from published artifacts.
- [ ] Ensure all screenshots and example reports use synthetic data.

## Acknowledgements

Built for exploration of graph-powered investigation workflows using FalkorDB.

**FraudTrace AI — connect the evidence, investigate the pattern, and keep the decision human.**