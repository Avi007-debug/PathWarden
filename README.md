# PATHWARDEN

> **Trace the attack. Expose the path. Defend what matters.**

PathWarden is an evidence-driven cyberattack path reconstruction and threat investigation platform. It transforms large volumes of heterogeneous security logs into correlated incidents, ordered attack paths, explainable detections, evidence-backed reachability assessments, and auto-written executive incident briefings.

🌐 **Live Production Deployment**: [https://path-warden-delta.vercel.app](https://path-warden-delta.vercel.app/)

---

## 1. Functional Requirements & Bonus Matrix

| Requirement | Description | PathWarden Implementation |
|---|---|---|
| **FR-1** | **Bounded Memory Streaming** | Constant memory streaming chunker (DuckDB + PyArrow Parquet) handles 15 GB / 30 GB datasets under an 8.0 GB RAM lock. |
| **FR-2** | **Suspicious Event Detection** | Deterministic SQL rule predicates for credential access, privilege escalation, and lateral execution. |
| **FR-3** | **MITRE ATT&CK & Kill Chain Mapping** | Grounded technique identification (`T1566.001`, `T1003`, `T1021.002`) and kill-chain phase progression. |
| **FR-4** | **Incident Linking by Entity & Time** | Multi-attribute correlation over host, user identity, IP address, and causal window constraints. |
| **FR-5** | **Attack Path Timeline & Directed Graph** | Synchronized Cytoscape.js attack DAG and chronological timeline with side-by-side full window enlargement. |
| **FR-6** | **Reachability Assessment** | Strict separation of confirmed **Observed Access** (`OBSERVED_SESSION`) from **Potential Reachability** (`NETWORK_REACHABLE`, `PRIVILEGE_RELATIONSHIP`). |
| **FR-7** | **API & Operational Workspace** | Production FastAPI backend (`GET /incidents/{id}/path`) paired with Next.js Brutalist HUD console. |
| **[BONUS B-1]** | **Prioritized Incident Risk Scoring** | Multi-factor risk engine (0-100) combining severity, confidence, step count, tactic breadth, and objective achievement so highest-risk attacks sort on top. |
| **[BONUS B-2]** | **Auto-Written Incident Report in Plain English** | On-Device Tri-Agent Synthesis Engine & local GPU LLM integration (Ollama / Qwen 2.5 Coder 1.5B) producing executive summaries and actionable containment checklists. |
| **[BONUS B-3]** | **Raw Alerts Merged Accounting** | Exact telemetry accounting showing how many raw security alerts (e.g. 18 alerts) were clustered into attack steps (56%–86% noise reduction). |
| **[BONUS B-4]** | **Config-Driven Detection Rules** | Hot-reloadable Sigma-compatible YAML rules configuration (`backend/data/rules.yaml`) with zero code modifications needed. |

---

## 2. Quickstart with Docker Compose

Run the entire PathWarden ecosystem (FastAPI backend + DuckDB storage + Next.js frontend console) with a single command:

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/) v2.0+

### 1. Launch the Stack

```bash
# Clone the repository
git clone https://github.com/Vedant-Panchal/PathWarden.git
cd PathWarden

# Build and start all containers in detached mode
docker compose up --build -d
```

### 2. Verify Container Health

```bash
# Check running containers
docker compose ps
```

The stack exposes:
- **Frontend SOC Console**: [http://localhost:3000](http://localhost:3000)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **System Telemetry & Health**: [http://localhost:8000/status](http://localhost:8000/status)

### 3. Stop or Restart Containers

```bash
# View live logs
docker compose logs -f

# Stop containers
docker compose down
```

---

## 3. Bonus B-2: On-Device GPU LLM & Tri-Agent Architecture

PathWarden introduces an **On-Device Agentic Synthesis Architecture** for generating authoritative, plain-English incident briefings without leaking sensitive telemetry to third-party cloud APIs.

```
+-----------------------------------------------------------------+
|                     RAW INCIDENT & ATTACK DAG                   |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| [AGENT 1: Detection Analyst Agent]                              |
| - Evaluates MITRE ATT&CK techniques, raw detection alerts,      |
|   confidence scores, and false positive risk ratings.           |
| - Quantifies Bonus B-3 alert merging and noise reduction.       |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| [AGENT 2: Forensics & Blast Radius Agent]                       |
| - Traces timeline from root-cause host to crown jewels.         |
| - Differentiates observed access from potential reachability.   |
+-----------------------------------------------------------------+
                                |
                                v
+-----------------------------------------------------------------+
| [AGENT 3: Executive Reporter Agent]                             |
| - Synthesizes findings into human-readable Plain English.       |
| - Outputs: Executive Summary, Chronological Walkthrough,        |
|   Blast Radius Assessment, and Prioritized Remediation Plan.    |
+-----------------------------------------------------------------+
```

### Connecting a Local GPU LLM (e.g. Ollama)
PathWarden automatically detects local GPU models running via [Ollama](https://ollama.ai/):

```bash
# On your host workstation with a GPU (NVIDIA / Apple Silicon):
ollama run qwen2.5-coder:1.5b
# Or serve in background:
ollama serve
```

When Docker Compose runs, `docker-compose.yml` routes `OLLAMA_HOST=http://host.docker.internal:11434`. 
- If Ollama is active on your GPU, the **Executive Reporter Agent** queries `qwen2.5-coder:1.5b` locally.
- If no GPU server is running, PathWarden's built-in **Deterministic Tri-Agent Engine** immediately produces the report with 0 ms lag and zero external dependencies.

---

## 4. Side-by-Side Dual Canvas Enlargement

When investigating large attacks with 10–20 steps:
1. Click **`ENLARGE CANVAS`** (or the Enlarge button on the Cytoscape toolbar / Timeline header).
2. The entire investigation view expands into a **full-window side-by-side workspace**:
   - **Left Canvas**: Full-height interactive Cytoscape.js attack DAG (pan, zoom, auto-fit).
   - **Right Canvas**: Step Inspector and complete Chronological Timeline side-by-side, allowing endless vertical scrolling without cramping the graph.
3. Press **`Esc`** or click **`EXIT FULLSCREEN`** to immediately restore the standard HUD.

---

## 5. Processing 15 GB / 30 GB Log Datasets

To run an end-to-end investigation run on a log file:

### Using Docker Compose
```bash
# Place your log file in the ./data directory:
cp firex-30g.log ./data/

# Execute investigation inside the backend container:
docker compose exec backend python run_investigation.py --input /app/data/firex-30g.log --workers 3
```

### Running Locally without Docker

#### Backend Setup
```bash
# Create virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run test suite
python -m pytest -q

# Start FastAPI server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

---

## 6. Documented API Contracts

PathWarden exposes the following RESTful endpoints:

- `GET /status`: System RAM telemetry, active enclave memory budget, and worker states.
- `GET /incidents`: Correlated incident clusters sorted by **Risk Score DESC [Bonus B-1]**.
- `GET /incidents/{id}`: Detailed incident payload including attack steps, causal edges, and **Raw Alerts Merged [Bonus B-3]**.
- `GET /incidents/{id}/path`: Reconstructed Cytoscape DAG nodes and edges.
- `GET /incidents/{id}/report`: Auto-written plain English executive incident briefing **[Bonus B-2]**.
- `GET /incidents/{id}/reach`: Confirmed observed sessions vs. potential reachability.
- `GET /data-quality`: 6-stage record accounting funnel and 4-way reconciliation invariant check.
- `GET /rules`: Active detection rules loaded from configuration YAML **[Bonus B-4]**.
- `GET /bench`: Target Matrix competition benchmarks and query latency metrics.
- `GET /evidence?event_uid=...&ctx=5`: Inspectable source records for any graph node or edge.

---

## 7. Security Measures

PathWarden follows a security-first approach to protect its application, APIs, data, and log-processing pipeline.
- **Authentication & Authorization**: JWT-based authentication, role-based access control (RBAC), and MFA for administrative accounts.
- **API Security**: Rate limiting, strict input validation, secure CORS configuration, and protection against unauthorized data access.
- **Secure File Ingestion**: File type and size validation, safe file handling, and isolated log processing.
- **Data Protection**: HTTPS/TLS, encrypted sensitive data, secure password hashing, and environment-based secrets management.
- **Attack Prevention**: Protection against SQL injection, XSS, CSRF, SSRF, and path traversal vulnerabilities.
- **Audit Logging**: Track login attempts, file uploads, investigation activities, and administrative actions.
- **Self-Security Monitoring**: Monitor application logs to detect suspicious login attempts, unusual API activity, and potential privilege escalation.

### Security Testing Tools
OWASP ZAP, Bandit, Semgrep, and pip-audit for identifying application vulnerabilities and dependency risks.

