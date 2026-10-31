# PATHWARDEN

> **Trace the attack. Expose the path. Defend what matters.**

PathWarden is an evidence-driven cyberattack reconstruction and threat investigation platform. It transforms large volumes of heterogeneous security logs into correlated incidents, ordered attack paths, explainable detections, and evidence-backed reachability assessments.

---

## 1. Product Capabilities & Architecture

PathWarden answers the 10 critical operational questions for security investigators:

1. **What happened?** - Coherent multi-stage intrusion reconstruction.
2. **Where did the attack begin?** - Initial access vector and root cause identification.
3. **Which users, hosts, and processes were involved?** - Contextual entity correlation.
4. **What happened next?** - Directed causal attack sequence (not raw timestamp guessing).
5. **Why are these events considered related?** - Explicit non-temporal relationship evidence (process lineage, session tokens, lateral movement, RPC streams).
6. **Which MITRE ATT&CK techniques and Cyber Kill Chain stages are supported?** - Grounded mapping with confidence ratings.
7. **What evidence supports each relationship?** - Inspectable source records for every node and edge.
8. **Which systems have demonstrated access?** - Confirmed **Observed Access** (`OBSERVED_SESSION`).
9. **Which systems are only potentially reachable?** - Inferred **Potential Reachability** (`NETWORK_REACHABLE`, `PRIVILEGE_RELATIONSHIP`).
10. **What limitations or missing data could affect the investigation?** - Explicit data quality caveats (`HOST_INFERRED`, `TIMESTAMP_UNCERTAIN`, `UNKNOWN_EVENT_TYPE`).

---

## 2. Visual Design System

The PathWarden UI is engineered with an **experimental modern brutalist** aesthetic tailored for high-intensity Security Operations Centers (SOC):

- **Palette Tokens**:
  - `Electric Blue (#2563FF)`: Primary investigative actions and interactive states.
  - `Cyan Blue (#00C8FF)`: Attack path highlights and selected graph elements.
  - `Acid Green (#B7FF3C)`: Confirmed observed sessions and high-confidence metrics.
  - `Deep Navy (#07111F)`: Dark mode primary backdrop.
  - `Dark Surface (#0D1B2A)`: Layered dark panels with fine blue-gray borders (`#1E3550`).
  - `Light Background (#F5F8F6)` & `Light Surface (#FFFFFF)`: Independent light mode with dark charcoal text (`#101820`).
- **Typography**:
  - Headings: Space Grotesk / Sora
  - Interface text: Inter
  - Metadata & Telemetry: IBM Plex Mono
- **Themes**:
  - Full Dark and Light theme implementations with instant toggle, OS preference detection, and localStorage persistence.
  - Non-color-alone status communication: Colors paired with shapes, tags, and monospaced labels.

---

## 3. Investigation Workspace Pages

| Route | Page | Purpose |
|---|---|---|
| `/` | **Overview Dashboard** | Real-time processing funnel, key metrics, recent intrusions, dataset health & terminal dispositions reconciliation. |
| `/incidents` | **Incident Explorer** | Filterable, searchable workspace with multi-attribute filtering (Severity, Tactic, Host, User, Confidence). |
| `/incidents/[id]` | **Incident Investigation** | **Centerpiece workspace**: Interactive Cytoscape.js directed attack graph, synchronized chronological timeline, attack-step explanation panel, and evidence inspection drawer. |
| `/reachability` | **Reachability Analysis** | Strict separation of confirmed **Observed Access** from **Potential Reachability** (hops, policy assumptions, and privilege exposure). |
| `/data-quality` | **Data Quality & Observability** | Ingestion accounting funnel (`records_read = malformed + duplicate_dropped + valid_excluded + eligible`), telemetry quality flags, and source-level breakdown. |
| `/benchmarks` | **Performance & Accuracy** | 30 GB Advanced Tier competition targets vs measured results (runtime, 8.3 MB/s sustained throughput, 8 GB container memory budget, detection recall, ATT&CK label accuracy, false alarms). |

---

## 4. Dataset Integration & Demonstration Mode

PathWarden is pre-configured to operate seamlessly in two modes:

1. **Synthetic Demo Mode (`DEMO DATA - SYNTHETIC SCENARIO`)**:
   - An internally consistent, evidence-backed synthetic scenario modeling an Advanced Persistent Threat (APT) lateral intrusion from workstation macro execution (`WS-EXEC-04`), LSASS credential dumping, Pass-the-Hash onto `SRV-APP-PROD01`, directory replication (DCSync) to domain controller `DC01.CORP.LOCAL`, Golden Ticket generation, and periodic C2 beaconing.
   - Grounded in real Elastic Common Schema (ECS) EDR telemetry matching `edr_events.json`.
2. **Live Backend API Mode (`LIVE BACKEND API`)**:
   - Connects directly to the PathWarden FastAPI backend (`http://localhost:8000` configurable via `NEXT_PUBLIC_API_BASE_URL`).
   - One-click toggle in the top navigation bar with persistent indicator.

---

## 5. Getting Started

### Prerequisites

- **Node.js**: v18.0.0+ (Tested on v24.18.0)
- **npm**: v9.0.0+ (Tested on v11.6.2)

### Installation

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install
```

### Running the Development Console

```bash
# Start Next.js development server
npm run dev

# Open in browser:
# http://localhost:3000
```

### Running Type Checks & Linting

```bash
# Type check with strict TypeScript
npm run typecheck

# Lint with ESLint
npm run lint
```

### Creating Production Build

```bash
# Build optimized production bundle
npm run build

# Start production server
npm start
```

---

## 6. Documented Backend API Contracts

PathWarden integrates with the following FastAPI endpoints documented in `ChainSight_v5_Refined_Implementation_Plan_v5.1.md`:

- `POST /run`: Initiate ingestion and attack path reconstruction run.
- `GET /status`: Retrieve current processing run stage, records processed, and memory usage.
- `GET /incidents`: Retrieve list of correlated incident clusters.
- `GET /incidents/{id}`: Retrieve incident summary and details.
- `GET /incidents/{id}/path`: Retrieve precomputed attack graph nodes and directed edges.
- `GET /incidents/{id}/reach`: Retrieve observed and potential reachability assessments.
- `GET /incidents/{id}/report`: Retrieve deterministic incident markdown report.
- `GET /data-quality`: Retrieve record reconciliation funnel and quality flags breakdown.
- `GET /bench`: Retrieve benchmark runtime, throughput, memory peak, and scorer accuracy.
- `GET /evidence?event_uid=...&ctx=5`: Retrieve raw and normalized telemetry record for any step or edge.
