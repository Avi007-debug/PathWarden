import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and display total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 755, "PATHWARDEN | Technical Architecture & System Design Interview Master Guide")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 747, 558, 747)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "CONFIDENTIAL & PROPRIETARY — FOR TECHNICAL INTERVIEW PREPARATION")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()


def build_pdf(filename="PathWarden_Technical_Interview_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    c_primary = colors.HexColor("#0f172a")     # Deep slate navy
    c_accent = colors.HexColor("#0284c7")      # Tech cyan/blue
    c_accent_dark = colors.HexColor("#0369a1")
    c_text = colors.HexColor("#1e293b")        # Dark slate
    c_muted = colors.HexColor("#64748b")       # Muted gray
    c_card_bg = colors.HexColor("#f8fafc")     # Light slate card
    c_card_border = colors.HexColor("#e2e8f0")
    c_badge_bg = colors.HexColor("#e0f2fe")
    c_badge_text = colors.HexColor("#0369a1")

    # Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_primary,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceAfter=15,
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=c_accent_dark,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_text,
        spaceAfter=5,
    )
    body_bold = ParagraphStyle(
        "BodyBold_Custom",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=c_text,
        spaceAfter=4,
    )
    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=c_text,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3,
    )
    qa_q_style = ParagraphStyle(
        "QA_Question",
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13.5,
        textColor=c_primary,
        spaceBefore=6,
        spaceAfter=2,
        keepWithNext=True,
    )
    qa_a_style = ParagraphStyle(
        "QA_Answer",
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=c_text,
        leftIndent=10,
        spaceAfter=6,
    )
    table_cell = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=c_text,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )
    code_inline = ParagraphStyle(
        "CodeInline",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=c_accent_dark,
    )

    story = []

    # Title Banner Block
    banner_data = [
        [
            Paragraph("<b>PATHWARDEN</b>", ParagraphStyle("Logo", fontName="Helvetica-Bold", fontSize=26, leading=28, textColor=colors.white)),
            Paragraph("<b>SYSTEM DESIGN & TECHNICAL INTERVIEW GUIDE</b><br/><font size=8 color='#bae6fd'>Evidence-Driven Attack Path Reconstruction & Threat Investigation</font>", ParagraphStyle("Sub", fontName="Helvetica", fontSize=9, leading=13, textColor=colors.white, alignment=2))
        ]
    ]
    banner_table = Table(banner_data, colWidths=[200, 304])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_primary),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 10))

    # Meta badges table
    meta_data = [
        [
            Paragraph("<b>Core Domain:</b> Cybersecurity / SOC Forensics", table_cell),
            Paragraph("<b>Dataset Scale:</b> 30 GB (20M+ logs)", table_cell),
            Paragraph("<b>Memory Constraint:</b> Strict 8.0 GB RAM lock", table_cell),
            Paragraph("<b>Architecture:</b> DuckDB + Parquet + FastAPI + React", table_cell),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[126, 126, 126, 126])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_card_bg),
        ("BOX", (0, 0), (-1, -1), 0.5, c_card_border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_card_border),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # SECTION 1: The 2-Minute Elevator Pitch
    story.append(Paragraph("1. Executive Overview & The 2-Minute Elevator Pitch", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))
    
    pitch_text = (
        "<b>\"What is PathWarden?\"</b><br/>"
        "PathWarden is an evidence-driven cyberattack path reconstruction and threat investigation engine. "
        "Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue—drowning in tens of thousands of "
        "disconnected alerts from EDR, Windows event logs, and perimeter firewalls. Traditional SIEMs are costly, "
        "charge per gigabyte ingested, and fail to reconstruct chronological causal attack paths.<br/><br/>"
        "PathWarden ingests multi-gigabyte forensic datasets (e.g. 30 GB / 20M+ records), runs vectorized detection rules, "
        "maps behaviors to the MITRE ATT&CK framework and Lockheed Martin Cyber Kill Chain, correlates evidence across entities, "
        "and reconstructs a <b>deterministic Directed Acyclic Graph (DAG)</b> of the attack path. "
        "Crucially, it achieves <b>56% to 86% noise reduction</b> while operating strictly under an <b>8.0 GB RAM limit</b> "
        "using streaming chunking and DuckDB over columnar Parquet, complemented by an air-gapped on-device AI tri-agent for "
        "instant plain-English executive briefings."
    )
    story.append(Paragraph(pitch_text, body_style))
    story.append(Spacer(1, 8))

    # SECTION 2: End-to-End System Architecture (FR-1 through FR-7)
    story.append(Paragraph("2. Functional Architecture & Pipeline Progression", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))

    fr_data = [
        [Paragraph("Feature", table_header), Paragraph("Role & Objective", table_header), Paragraph("Core Implementation & Technologies", table_header)],
        [
            Paragraph("<b>FR-1: Ingestion & Normalization</b>", table_cell),
            Paragraph("Stream, parse, and normalize heterogeneous logs (firewall text, Windows JSONL) to a single unified schema without OOM.", table_cell),
            Paragraph("<code>chunk_reader.py</code> (64 MB newline-safe buffer), <code>JSONLParser</code> (orjson), <code>event_normalizer.py</code>, PyArrow Parquet writer.", table_cell),
        ],
        [
            Paragraph("<b>FR-2: Rule Detection Engine</b>", table_cell),
            Paragraph("Identify suspicious adversary behaviors with zero row-by-row Python looping overhead.", table_cell),
            Paragraph("<code>sql_compiler.py</code>, <code>detection_engine.py</code>. Compiles YAML rules into vectorized DuckDB SQL queries over Parquet.", table_cell),
        ],
        [
            Paragraph("<b>FR-3: Threat Mapping</b>", table_cell),
            Paragraph("Ground alerts in MITRE ATT&CK techniques and Lockheed Martin 7-stage Cyber Kill Chain.", table_cell),
            Paragraph("<code>attack_mapper.py</code>, <code>kill_chain_mapper.py</code>, local <code>enterprise-attack.json</code> database. Zero external API calls.", table_cell),
        ],
        [
            Paragraph("<b>FR-4: Evidence Correlation</b>", table_cell),
            Paragraph("Link individual detections into multi-stage attack campaigns using causal entity, process, and network joins.", table_cell),
            Paragraph("<code>candidate_generator.py</code> (DuckDB windowed equi-joins), <code>anti_hub_filter.py</code>, <code>incident_clusterer.py</code> (Union-Find).", table_cell),
        ],
        [
            Paragraph("<b>FR-5: Timeline & Attack Graph</b>", table_cell),
            Paragraph("Visualize chronological attack progression and directed attack DAGs for human analysts.", table_cell),
            Paragraph("Next.js frontend console, Cytoscape.js with Dagre hierarchical layout, synchronized step timeline, on-demand evidence drawer.", table_cell),
        ],
        [
            Paragraph("<b>FR-6: Reachability Assessment</b>", table_cell),
            Paragraph("Calculate attacker blast radius with strict semantic separation of observed vs. potential access.", table_cell),
            Paragraph("<code>reachability_engine.py</code>: Bounded BFS (max_depth=2, max_results=50, timeout=2.0s) over pre-indexed topology and privilege graphs.", table_cell),
        ],
        [
            Paragraph("<b>FR-7: Persistence & Packaging</b>", table_cell),
            Paragraph("Expose production REST API, manage asynchronous worker executions, and ensure crash recovery.", table_cell),
            Paragraph("FastAPI service, <code>JobRegistry</code> (SQLite), <code>CheckpointManager</code> (atomic batch commits), Docker Compose containerization.", table_cell),
        ],
    ]
    fr_table = Table(fr_data, colWidths=[110, 194, 200])
    fr_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("BOX", (0, 0), (-1, -1), 0.5, c_card_border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_card_border),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_card_bg]),
    ]))
    story.append(fr_table)
    story.append(Spacer(1, 12))

    # SECTION 3: Deep Dive into Scalable Optimizations
    story.append(PageBreak())
    story.append(Paragraph("3. Deep Dive: All Scalable Optimizations (FR-1 to FR-7)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))
    story.append(Paragraph(
        "To process 30 GB of security telemetry on standard single-node hardware without memory exhaustion, "
        "every layer of the stack implements bounded resource constraints and sub-linear processing algorithms:",
        body_style
    ))
    story.append(Spacer(1, 4))

    opt_items = [
        ("1. Boundary-Safe Streaming Chunk Reader (FR-1)",
         "<b>File:</b> <code>backend/ingestion/chunk_reader.py</code><br/>"
         "• <b>Mechanism:</b> Reads fixed 64 MB binary slices from disk. Scans backwards for the final newline (<code>b'\\n'</code>) and adjusts file pointer so records are never bisected.<br/>"
         "• <b>Impact:</b> Prevents loading entire multi-gigabyte logs into memory, keeping ingestion RAM strictly under 500 MB."),

        ("2. Vectorized Columnar Joins via DuckDB (FR-2 & FR-4)",
         "<b>File:</b> <code>backend/correlation/candidate_generator.py</code><br/>"
         "• <b>Mechanism:</b> Pairwise comparison of 100K detections in Python is O(N²) (10¹⁰ comparisons). PathWarden delegates all candidate generation to DuckDB columnar equi-joins with temporal window pruning (<code>b.event_ts BETWEEN a.event_ts AND a.event_ts + 600</code>).<br/>"
         "• <b>Impact:</b> Evaluates 20M+ records in seconds; streams candidates via lazy Python generators (<code>Iterator[CandidatePair]</code>) without materializing full arrays."),

        ("3. Anti-Hub Logarithmic Degree Damping (FR-4 Decoy Resistance)",
         "<b>File:</b> <code>backend/correlation/anti_hub_filter.py</code><br/>"
         "• <b>Mechanism:</b> High-degree infrastructure nodes (Domain Controllers, NAT gateways, jumpboxes) cause 'supernode explosion' that collapses unrelated alerts. PathWarden applies a logarithmic penalty for degree > 40: <i>Score_penalized = Score * max(0.1, 1.0 - 0.5 * ln(1 + excess) * 0.15)</i>. Nodes with degree > 50 require ≥ 2 independent corroborations.<br/>"
         "• <b>Impact:</b> Prevents artificial alert clustering and graph poisoning from noisy network hubs."),

        ("4. Sliding-Window Cross-Batch Correlation State (FR-4)",
         "<b>File:</b> <code>backend/correlation/cross_batch_state.py</code><br/>"
         "• <b>Mechanism:</b> Tracks open sessions and active process trees across batch boundaries using a thread-safe sliding window with TTL pruning (default 600s). Expired entities are purged automatically.<br/>"
         "• <b>Impact:</b> Solves split-batch attack correlation with constant bounded memory overhead."),

        ("5. Near-Linear Disjoint-Set Union-Find Clustering (FR-4)",
         "<b>File:</b> <code>backend/correlation/incident_clusterer.py</code><br/>"
         "• <b>Mechanism:</b> Implements Union-Find with path compression and union-by-rank running in O(α(N)) time (inverse Ackermann, effectively linear). Validates each cluster against the incident gate (≥ 2 Kill Chain stages or ≥ 3 steps + at least 1 high-confidence non-temporal causal edge).<br/>"
         "• <b>Impact:</b> Instantaneous campaign partitioning even with 100,000+ candidate edges."),

        ("6. Incident-Scoped UI & Lazy Evidence Loading (FR-5)",
         "<b>Files:</b> <code>routes_incidents.py</code>, <code>EvidenceDrawer.tsx</code>, <code>cytoscape-theme.ts</code><br/>"
         "• <b>Mechanism:</b> The frontend NEVER loads global enterprise graphs. Endpoints are strictly scoped to single incidents (≤ 100 nodes). Raw EDR payloads and command lines are deferred and fetched on-demand only when an analyst clicks an edge.<br/>"
         "• <b>Impact:</b> Sub-second client render times, zero DOM bloat, lightweight Cytoscape Dagre hierarchical rendering."),

        ("7. Strictly Bounded BFS Reachability Traversal (FR-6)",
         "<b>File:</b> <code>backend/reachability/reachability_engine.py</code><br/>"
         "• <b>Mechanism:</b> Replaces exhaustive all-pairs pathfinding with bounded BFS: hard depth limit (max_depth=2), max result cap (max_results=50), strict timeout (timeout_sec=2.0), and a hash-set visited tracker for cycle detection.<br/>"
         "• <b>Impact:</b> Guaranteed bounded latency (< 50ms) regardless of network topology density."),

        ("8. Decoupled Asynchronous Worker & Idempotent Crash Checkpoints (FR-7)",
         "<b>Files:</b> <code>backend/worker/task_worker.py</code>, <code>checkpoint_manager.py</code><br/>"
         "• <b>Mechanism:</b> FastAPI delegates analysis to a daemon worker thread, immediately returning <code>202 Accepted</code> with a job UUID. Batch progress is atomically recorded in SQLite with <code>UNIQUE(run_id, batch_id)</code>.<br/>"
         "• <b>Impact:</b> If the host crashes or suffers an OOM event at batch 40 of 50, the pipeline resumes at batch 41 without recomputing past batches or corrupting Parquet outputs.")
    ]

    for title, desc in opt_items:
        story.append(Paragraph(title, h2_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 3))

    # SECTION 4: Deep Dive into Security Features & Guarantees
    story.append(PageBreak())
    story.append(Paragraph("4. Deep Dive: Security Features & Guarantees Provided", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))

    sec_items = [
        ("1. Deterministic Evidence Provenance & Zero Data Loss",
         "Every single detection and correlation edge retains an unbroken chain of custody back to raw logs via <code>evidence_event_uids</code> and <code>raw_event_reference</code> (format: <code>ref:file_id:start_byte:line_num</code>). Unmapped fields are never discarded; they are retained in an <code>extra</code> JSON map to prevent forensic loss."),

        ("2. Air-Gapped On-Device AI Synthesis (Zero Telemetry Leakage)",
         "Incident reports and executive briefings are generated using a local Tri-Agent architecture powered by on-premise LLMs (Ollama / Qwen 2.5 Coder 1.5B). Not a single internal IP, hostname, or credential ever leaves the corporate perimeter, fully complying with GDPR, HIPAA, and defense compliance standards."),

        ("3. Anti-Hub Graph Poisoning & Decoy Resistance",
         "Adversaries frequently attempt to confuse graph-based correlation by triggering alerts through shared Domain Controllers or load balancers. PathWarden's logarithmic degree damping and multi-evidence corroboration rules prevent attackers from poisoning the incident clusterer to hide high-severity campaigns."),

        ("4. Strict Reachability Semantics (Defensible Blast-Radius)",
         "PathWarden strictly forbids labeling potential paths as observed access. Assets are marked <code>OBSERVED</code> only when explicit authentication or network sessions exist in the evidence. Unconfirmed routable paths are explicitly tagged <code>NETWORK_REACHABLE</code>. This prevents panicked over-isolation of critical business infrastructure during active incidents."),

        ("5. Defense Against Timestamp Manipulation & Clock Drift",
         "Adversaries modify system clocks (timestomping) to break chronological correlation. PathWarden flags any events with temporal offsets ≤ 2 seconds as 'temporally uncertain' and prioritizes causal process parentage and network handshake evidence over bare timestamps.")
    ]

    for title, desc in sec_items:
        story.append(Paragraph(title, h2_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 4))

    # SECTION 5: Architectural Trade-Offs & "Why" Decisions
    story.append(Spacer(1, 8))
    story.append(Paragraph("5. Key Architectural Trade-Offs & 'Why' Decisions", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))

    tradeoff_data = [
        [Paragraph("Decision", table_header), Paragraph("Alternative Considered", table_header), Paragraph("Rationale & Interview Defense", table_header)],
        [
            Paragraph("<b>DuckDB + Parquet</b><br/>over Graph DB (Neo4j)", table_cell),
            Paragraph("Neo4j, Memgraph, TigerGraph", table_cell),
            Paragraph("Graph databases have severe memory amplification (10-20x raw data size) and poor tabular scanning performance. DuckDB evaluates columnar analytical queries at native C++ speeds under 8 GB RAM with zero external server dependencies.", table_cell),
        ],
        [
            Paragraph("<b>SQLite State Registry</b><br/>over Redis / PostgreSQL", table_cell),
            Paragraph("Redis, Postgres, Celery", table_cell),
            Paragraph("Eliminates operational complexity. SQLite with WAL mode provides atomic, zero-overhead ACID transactions for checkpoints, perfectly suited for single-node containerized deployment without network latency.", table_cell),
        ],
        [
            Paragraph("<b>Bounded BFS</b><br/>over Dijkstra / A*", table_cell),
            Paragraph("All-Pairs Shortest Path, A*", table_cell),
            Paragraph("Incident responders need to know immediate blast radius (1-2 hops), not theoretical 15-hop paths. Bounded BFS with a visited set runs in O(V + E) within a 2-second timeout, completely immune to cyclic loops.", table_cell),
        ],
        [
            Paragraph("<b>Local Tri-Agent LLM</b><br/>over Cloud API (OpenAI/Anthropic)", table_cell),
            Paragraph("GPT-4, Claude 3.5 Sonnet", table_cell),
            Paragraph("Sending proprietary network logs, hostnames, and user identities to third-party cloud APIs violates strict cybersecurity compliance. Local inference ensures total data sovereignty and works in air-gapped SCIF environments.", table_cell),
        ],
    ]
    tradeoff_table = Table(tradeoff_data, colWidths=[120, 114, 270])
    tradeoff_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("BOX", (0, 0), (-1, -1), 0.5, c_card_border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_card_border),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_card_bg]),
    ]))
    story.append(tradeoff_table)

    # SECTION 6: High-Impact Technical Interview Q&A
    story.append(PageBreak())
    story.append(Paragraph("6. Hard Technical Interview Questions & High-Impact Model Answers", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))

    qa_list = [
        ("Q1: How do you handle 30 GB of heterogeneous logs under a strict 8.0 GB RAM constraint without crashing?",
         "<b>Model Answer:</b> \"We enforce a zero-memory-amplification rule across three architectural layers: "
         "(1) Ingestion uses a binary chunk reader that slices files into 64 MB blocks with newline boundary safety, decoding and parsing in localized worker processes. "
         "(2) Parsed events are immediately flushed to compressed Apache Parquet columnar files on disk rather than kept as Python objects. "
         "(3) All detection and correlation operations run directly inside DuckDB via vectorized SQL over Parquet views. DuckDB manages its own out-of-core memory buffer, "
         "meaning Python only receives lightweight iterators of correlated candidate pairs. At no point in time does Python hold more than a few thousand rows in memory.\""),

        ("Q2: What is the 'Supernode' or 'Anti-Hub' problem in cyber attack graphs, and how did you solve it mathematically?",
         "<b>Model Answer:</b> \"In enterprise networks, certain entities like Active Directory Domain Controllers, NAT routers, or DNS servers have very high node degrees—connecting to thousands of endpoints. "
         "If you correlate naively based on shared IP or user interaction, these high-degree hubs will merge dozens of completely unrelated security alerts into a single catastrophic mega-incident (graph collapse). "
         "We solved this by implementing an Anti-Hub Filter that tracks entity degree in real time. For any entity exceeding degree 40, we apply a sub-linear logarithmic penalty: "
         "<i>Score_adj = Score * max(0.1, 1.0 - 0.5 * ln(1 + excess) * 0.15)</i>. "
         "Furthermore, for entities with degree > 50, we mandate a strict corroboration gate requiring at least 2 independent non-temporal evidence events before an edge is permitted.\""),

        ("Q3: How does your incident clustering algorithm work? Why choose Union-Find over standard graph clustering?",
         "<b>Model Answer:</b> \"We chose a Disjoint-Set Union-Find data structure with path compression and union-by-rank. "
         "It runs in nearly linear time—specifically O(α(N)) where α is the inverse Ackermann function, which is functionally ≤ 4 for all practical datasets. "
         "Standard graph clustering algorithms like Louvain or spectral clustering require building complete adjacency matrices and run in O(N² or N³), which is completely unacceptable for streaming forensic analysis. "
         "Once candidate edges are scored, Union-Find partitions them into connected components. Then, each component must pass our strict Incident Gate: it must span ≥ 2 distinct Kill Chain stages or ≥ 3 correlated steps, "
         "AND possess at least one high-confidence non-temporal causal edge. This filters out isolated false positives while passing short, high-fidelity breaches.\""),

        ("Q4: How do you maintain attack correlation across batch boundaries in a streaming pipeline?",
         "<b>Model Answer:</b> \"We created a dedicated <code>CrossBatchState</code> module that implements an in-memory sliding window cache. "
         "When an authentication event or process spawn occurs near the boundary of a 64 MB chunk, its metadata (session ID, PID, user, host, timestamp) is registered with a 600-second TTL (Time-To-Live). "
         "When the next batch is processed, the candidate generator queries both the current DuckDB view and the sliding-window state. "
         "Entities whose timestamp delta exceeds the TTL are automatically pruned, guaranteeing that open attack chains across chunks are linked without causing memory leaks over a 30 GB stream.\""),

        ("Q5: How do you differentiate 'Observed' from 'Potential' reachability, and why is this critical for SOC teams?",
         "<b>Model Answer:</b> \"During a breach, the biggest mistake a SOC can make is either under-isolating (allowing the attacker to pivot) or over-isolating (shutting down revenue-critical servers based on guesswork). "
         "Our reachability engine uses a bounded BFS that categorizes assets into strict states: "
         "An asset is tagged <code>OBSERVED</code> only if telemetry confirms interactive sessions, remote RPC calls, or authenticated SMB shares. "
         "Conversely, if an asset is merely routable at Layer 3 or shares a domain group without logon activity, it is explicitly classified as <code>NETWORK_REACHABLE</code> or <code>PRIVILEGE_RELATIONSHIP</code>. "
         "We enforce this in code: potential reachability can NEVER be upgraded to observed without an immutable <code>evidence_uid</code> citation.\""),

        ("Q6: How does the system recover if a crash or power failure occurs mid-pipeline?",
         "<b>Model Answer:</b> \"We built an idempotent checkpointing system backed by SQLite in WAL (Write-Ahead Logging) mode. "
         "Each batch completion executes an atomic commit containing <code>(run_id, batch_id, byte_offset)</code> guarded by a <code>UNIQUE</code> constraint. "
         "When a job starts or resumes after a crash, the pipeline checks <code>CheckpointManager.get_resume_point()</code>. "
         "If batch 35 was previously committed, batches 1 through 35 are skipped instantly via seek offsets, and processing resumes at batch 36. "
         "Because writes to Parquet are batch-partitioned and commits are idempotent, restarting an interrupted run causes zero duplicate data and zero state corruption.\"")
    ]

    for q, a in qa_list:
        story.append(Paragraph(q, qa_q_style))
        story.append(Paragraph(a, qa_a_style))

    # SECTION 7: Key Metrics & Interview Cheat Sheet
    story.append(Spacer(1, 8))
    story.append(Paragraph("7. Key Metrics & Interview Cheat Sheet (Numbers to Memorize)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=1, spaceAfter=8))

    cheat_data = [
        [Paragraph("Metric / Parameter", table_header), Paragraph("Production Value", table_header), Paragraph("Architectural Significance", table_header)],
        [
            Paragraph("Dataset Volume", table_cell),
            Paragraph("<b>30 GB / 20M+ logs</b>", table_cell),
            Paragraph("Competition benchmark scale (Firewall text + Windows JSONL).", table_cell),
        ],
        [
            Paragraph("Memory Budget", table_cell),
            Paragraph("<b>< 8.0 GB RAM</b>", table_cell),
            Paragraph("Strict hard cap maintained via 64 MB streaming chunker and DuckDB.", table_cell),
        ],
        [
            Paragraph("Alert Noise Reduction", table_cell),
            Paragraph("<b>56% to 86%</b>", table_cell),
            Paragraph("Clusters raw alerts into unified, prioritized attack campaigns.", table_cell),
        ],
        [
            Paragraph("Candidate Time Window", table_cell),
            Paragraph("<b>300s - 600s</b>", table_cell),
            Paragraph("Temporal bounding window for localized causal equi-joins.", table_cell),
        ],
        [
            Paragraph("Anti-Hub Degree Threshold", table_cell),
            Paragraph("<b>Degree > 40</b>", table_cell),
            Paragraph("Applies logarithmic penalty; degree > 50 requires ≥ 2 evidence corroborations.", table_cell),
        ],
        [
            Paragraph("Reachability BFS Bounds", table_cell),
            Paragraph("<b>Depth ≤ 2, Results ≤ 50</b>", table_cell),
            Paragraph("2.0s execution timeout; visited set prevents cyclic looping.", table_cell),
        ],
        [
            Paragraph("Local AI Model", table_cell),
            Paragraph("<b>Qwen 2.5 Coder 1.5B</b>", table_cell),
            Paragraph("On-device GPU/CPU inference via Ollama; zero cloud data egress.", table_cell),
        ],
    ]
    cheat_table = Table(cheat_data, colWidths=[130, 114, 260])
    cheat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("BOX", (0, 0), (-1, -1), 0.5, c_card_border),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, c_card_border),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_card_bg]),
    ]))
    story.append(cheat_table)

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully built: {filename}")


if __name__ == "__main__":
    build_pdf()

