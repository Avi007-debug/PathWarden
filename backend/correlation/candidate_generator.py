"""PathWarden FR-4: DuckDB-backed candidate pair generator.

All heavy joins run entirely in DuckDB over Parquet views — no Python-side
list comprehensions on full datasets. Returns lazy iterators of CandidatePair
named-tuples to keep memory bounded under 8.0 GB.
"""

from __future__ import annotations

import os
import glob
from dataclasses import dataclass, field
from typing import Iterator, Optional
import duckdb

from common.logger import get_logger

logger = get_logger("CandidateGenerator")


@dataclass(frozen=True)
class CandidatePair:
    """A pair of detection records that may be causally related."""
    src_detection_id: str
    dst_detection_id: str
    src_event_uid: str
    dst_event_uid: str
    src_host: str
    dst_host: str
    src_user: str
    dst_user: str
    src_ts: float          # epoch seconds
    dst_ts: float
    delta_seconds: float
    candidate_type: str    # process_parent | same_session | lateral_auth | network_follow
    join_key: str          # what matched (PID+host, session_id, user+dst_ip, etc.)
    raw_evidence_uids: tuple = field(default_factory=tuple)


# Maximum temporal gap for ANY candidate (seconds).
# Cross-batch state handles open sessions beyond this.
_MAX_DELTA = 600


class CandidateGenerator:
    """Generates correlated event pairs using DuckDB windowed SQL joins."""

    def __init__(self, data_dir: str, time_window_sec: int = 300) -> None:
        self.data_dir = data_dir
        self.time_window_sec = time_window_sec
        self._con: Optional[duckdb.DuckDBPyConnection] = None

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "CandidateGenerator":
        self._con = duckdb.connect(":memory:")
        self._register_views()
        return self

    def __exit__(self, *_) -> None:
        if self._con:
            self._con.close()
            self._con = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_candidates(self) -> Iterator[CandidatePair]:
        """Yield all candidate pairs across all join strategies."""
        if self._con is None:
            raise RuntimeError("Use CandidateGenerator as a context manager.")
        yield from self._process_parent_child()
        yield from self._same_session_continuation()
        yield from self._lateral_auth_followup()
        yield from self._network_connection_followup()
        yield from self._same_host_temporal_continuation()

    def _same_host_temporal_continuation(self) -> Iterator[CandidatePair]:
        """Detect sequential detections on same host within temporal window."""
        sql = f"""
            SELECT
                a.detection_id   AS src_detection_id,
                b.detection_id   AS dst_detection_id,
                a.event_uid      AS src_event_uid,
                b.event_uid      AS dst_event_uid,
                a.host_name      AS src_host,
                b.host_name      AS dst_host,
                a.user_name      AS src_user,
                b.user_name      AS dst_user,
                a.event_ts       AS src_ts,
                b.event_ts       AS dst_ts,
                (b.event_ts - a.event_ts) AS delta_seconds,
                'same_host_time' AS candidate_type,
                a.host_name      AS join_key
            FROM detections a
            JOIN detections b
              ON  a.host_name    = b.host_name
              AND a.host_name   <> ''
              AND b.event_ts    >= a.event_ts
              AND b.event_ts    <= a.event_ts + {self.time_window_sec}
              AND a.detection_id < b.detection_id
        """
        yield from self._run_query(sql, "same_host_time")

    # ------------------------------------------------------------------
    # View registration with resilient schema adapter
    # ------------------------------------------------------------------

    def _register_views(self) -> None:
        events_glob = os.path.join(self.data_dir, "events", "*.parquet").replace("\\", "/")
        detections_glob = os.path.join(self.data_dir, "detections", "*.parquet").replace("\\", "/")

        if not glob.glob(os.path.join(self.data_dir, "events", "*.parquet")):
            logger.warning("No events parquet files found at %s — using empty view", events_glob)
            self._con.execute("""
                CREATE OR REPLACE VIEW events AS
                SELECT
                    ''   AS event_uid,
                    ''   AS detection_id,
                    ''   AS host_name,
                    ''   AS user_name,
                    ''   AS process_name,
                    NULL::BIGINT AS process_id,
                    NULL::BIGINT AS parent_process_id,
                    ''   AS session_id,
                    ''   AS src_ip,
                    ''   AS dst_ip,
                    ''   AS event_type,
                    0.0  AS event_ts,
                    ''   AS command_line
                WHERE 1=0
            """)
        else:
            self._con.execute(f"CREATE OR REPLACE VIEW raw_events AS SELECT * FROM read_parquet('{events_glob}')")
            ev_cols = [r[1] for r in self._con.execute("PRAGMA table_info('raw_events')").fetchall()]
            ts_expr = "epoch(try_cast(event_ts AS TIMESTAMP))" if "event_ts" in ev_cols else ("epoch(try_cast(timestamp AS TIMESTAMP))" if "timestamp" in ev_cols else "0.0")
            uid_expr = "event_uid" if "event_uid" in ev_cols else ("event_id" if "event_id" in ev_cols else "''")
            host_expr = "host_name" if "host_name" in ev_cols else ("host" if "host" in ev_cols else "''")
            user_expr = "user_name" if "user_name" in ev_cols else ("user" if "user" in ev_cols else "''")
            proc_expr = "process_name" if "process_name" in ev_cols else "''"
            pid_expr = "try_cast(process_id AS BIGINT)" if "process_id" in ev_cols else ("try_cast(pid AS BIGINT)" if "pid" in ev_cols else "NULL::BIGINT")
            ppid_expr = "try_cast(parent_process_id AS BIGINT)" if "parent_process_id" in ev_cols else ("try_cast(parent_pid AS BIGINT)" if "parent_pid" in ev_cols else "NULL::BIGINT")
            sess_expr = "session_id" if "session_id" in ev_cols else "''"
            src_expr = "src_ip" if "src_ip" in ev_cols else "''"
            dst_expr = "dst_ip" if "dst_ip" in ev_cols else ("dest_ip" if "dest_ip" in ev_cols else "''")
            type_expr = "event_type" if "event_type" in ev_cols else "''"
            cmd_expr = "command_line" if "command_line" in ev_cols else "''"

            self._con.execute(f"""
                CREATE OR REPLACE VIEW events AS
                SELECT
                    COALESCE(try_cast({uid_expr} AS VARCHAR), '') AS event_uid,
                    COALESCE(try_cast({host_expr} AS VARCHAR), '') AS host_name,
                    COALESCE(try_cast({user_expr} AS VARCHAR), '') AS user_name,
                    COALESCE(try_cast({proc_expr} AS VARCHAR), '') AS process_name,
                    {pid_expr} AS process_id,
                    {ppid_expr} AS parent_process_id,
                    COALESCE(try_cast({sess_expr} AS VARCHAR), '') AS session_id,
                    COALESCE(try_cast({src_expr} AS VARCHAR), '') AS src_ip,
                    COALESCE(try_cast({dst_expr} AS VARCHAR), '') AS dst_ip,
                    COALESCE(try_cast({type_expr} AS VARCHAR), '') AS event_type,
                    COALESCE({ts_expr}, 0.0) AS event_ts,
                    COALESCE(try_cast({cmd_expr} AS VARCHAR), '') AS command_line
                FROM raw_events
            """)

        if not glob.glob(os.path.join(self.data_dir, "detections", "*.parquet")):
            logger.warning("No detections parquet found at %s — using empty view", detections_glob)
            self._con.execute("""
                CREATE OR REPLACE VIEW detections AS
                SELECT
                    ''   AS detection_id,
                    ''   AS event_uid,
                    ''   AS host_name,
                    ''   AS user_name,
                    ''   AS process_name,
                    NULL::BIGINT AS process_id,
                    NULL::BIGINT AS parent_process_id,
                    ''   AS session_id,
                    ''   AS src_ip,
                    ''   AS dst_ip,
                    ''   AS kill_chain_stage,
                    ''   AS technique_id,
                    ''   AS severity,
                    0.0  AS event_ts
                WHERE 1=0
            """)
        else:
            self._con.execute(f"CREATE OR REPLACE VIEW raw_detections AS SELECT * FROM read_parquet('{detections_glob}')")
            det_cols = [r[1] for r in self._con.execute("PRAGMA table_info('raw_detections')").fetchall()]
            det_id_expr = "detection_id" if "detection_id" in det_cols else "''"
            det_ev_expr = "primary_event_uid" if "primary_event_uid" in det_cols else ("event_uid" if "event_uid" in det_cols else ("list_element(event_uids, 1)" if "event_uids" in det_cols else "''"))
            det_ts_expr = "epoch(try_cast(detected_at AS TIMESTAMP))" if "detected_at" in det_cols else ("epoch(try_cast(event_ts AS TIMESTAMP))" if "event_ts" in det_cols else "0.0")
            det_kc_expr = "kill_chain_stage" if "kill_chain_stage" in det_cols else "''"
            det_tech_expr = "mitre_technique_id" if "mitre_technique_id" in det_cols else ("technique_id" if "technique_id" in det_cols else "''")
            det_sev_expr = "severity" if "severity" in det_cols else "'MEDIUM'"

            has_host = "host_name" in det_cols or "host" in det_cols
            has_proc = "process_id" in det_cols or "pid" in det_cols

            if has_host and has_proc:
                host_e = "host_name" if "host_name" in det_cols else "host"
                user_e = "user_name" if "user_name" in det_cols else "user"
                proc_e = "process_name" if "process_name" in det_cols else "''"
                pid_e = "try_cast(process_id AS BIGINT)" if "process_id" in det_cols else "try_cast(pid AS BIGINT)"
                ppid_e = "try_cast(parent_process_id AS BIGINT)" if "parent_process_id" in det_cols else "try_cast(parent_pid AS BIGINT)"
                sess_e = "session_id" if "session_id" in det_cols else "''"
                src_e = "src_ip" if "src_ip" in det_cols else "''"
                dst_e = "dst_ip" if "dst_ip" in det_cols else ("dest_ip" if "dest_ip" in det_cols else "''")

                self._con.execute(f"""
                    CREATE OR REPLACE VIEW detections AS
                    SELECT
                        COALESCE(try_cast({det_id_expr} AS VARCHAR), '') AS detection_id,
                        COALESCE(try_cast({det_ev_expr} AS VARCHAR), '') AS event_uid,
                        COALESCE(try_cast({host_e} AS VARCHAR), '') AS host_name,
                        COALESCE(try_cast({user_e} AS VARCHAR), '') AS user_name,
                        COALESCE(try_cast({proc_e} AS VARCHAR), '') AS process_name,
                        {pid_e} AS process_id,
                        {ppid_e} AS parent_process_id,
                        COALESCE(try_cast({sess_e} AS VARCHAR), '') AS session_id,
                        COALESCE(try_cast({src_e} AS VARCHAR), '') AS src_ip,
                        COALESCE(try_cast({dst_e} AS VARCHAR), '') AS dst_ip,
                        COALESCE(try_cast({det_kc_expr} AS VARCHAR), '') AS kill_chain_stage,
                        COALESCE(try_cast({det_tech_expr} AS VARCHAR), '') AS technique_id,
                        COALESCE(try_cast({det_sev_expr} AS VARCHAR), 'MEDIUM') AS severity,
                        COALESCE({det_ts_expr}, 0.0) AS event_ts
                    FROM raw_detections
                """)
            else:
                self._con.execute(f"""
                    CREATE OR REPLACE VIEW detections AS
                    SELECT
                        COALESCE(try_cast(d.{det_id_expr} AS VARCHAR), '') AS detection_id,
                        COALESCE(try_cast(d.{det_ev_expr} AS VARCHAR), e.event_uid, '') AS event_uid,
                        COALESCE(e.host_name, '') AS host_name,
                        COALESCE(e.user_name, '') AS user_name,
                        COALESCE(e.process_name, '') AS process_name,
                        e.process_id AS process_id,
                        e.parent_process_id AS parent_process_id,
                        COALESCE(e.session_id, '') AS session_id,
                        COALESCE(e.src_ip, '') AS src_ip,
                        COALESCE(e.dst_ip, '') AS dst_ip,
                        COALESCE(try_cast(d.{det_kc_expr} AS VARCHAR), '') AS kill_chain_stage,
                        COALESCE(try_cast(d.{det_tech_expr} AS VARCHAR), '') AS technique_id,
                        COALESCE(try_cast(d.{det_sev_expr} AS VARCHAR), 'MEDIUM') AS severity,
                        COALESCE({det_ts_expr}, e.event_ts, 0.0) AS event_ts
                    FROM raw_detections d
                    LEFT JOIN events e ON try_cast(d.{det_ev_expr} AS VARCHAR) = e.event_uid
                """)

    # ------------------------------------------------------------------
    # Join strategies
    # ------------------------------------------------------------------

    def _process_parent_child(self) -> Iterator[CandidatePair]:
        """Detect parent→child process relationships on same host."""
        sql = f"""
            SELECT
                p.detection_id   AS src_detection_id,
                c.detection_id   AS dst_detection_id,
                p.event_uid      AS src_event_uid,
                c.event_uid      AS dst_event_uid,
                p.host_name      AS src_host,
                c.host_name      AS dst_host,
                p.user_name      AS src_user,
                c.user_name      AS dst_user,
                p.event_ts       AS src_ts,
                c.event_ts       AS dst_ts,
                (c.event_ts - p.event_ts) AS delta_seconds,
                'process_parent' AS candidate_type,
                p.process_id::VARCHAR || ':' || p.host_name AS join_key
            FROM detections p
            JOIN detections c
              ON  p.host_name      = c.host_name
              AND p.process_id     = c.parent_process_id
              AND c.event_ts      >= p.event_ts
              AND c.event_ts      <= p.event_ts + {self.time_window_sec}
            WHERE p.detection_id != c.detection_id
              AND p.process_id IS NOT NULL
        """
        yield from self._run_query(sql, "process_parent")

    def _same_session_continuation(self) -> Iterator[CandidatePair]:
        """Detect sequential detections sharing the same session_id."""
        sql = f"""
            SELECT
                a.detection_id   AS src_detection_id,
                b.detection_id   AS dst_detection_id,
                a.event_uid      AS src_event_uid,
                b.event_uid      AS dst_event_uid,
                a.host_name      AS src_host,
                b.host_name      AS dst_host,
                a.user_name      AS src_user,
                b.user_name      AS dst_user,
                a.event_ts       AS src_ts,
                b.event_ts       AS dst_ts,
                (b.event_ts - a.event_ts) AS delta_seconds,
                'same_session'   AS candidate_type,
                a.session_id     AS join_key
            FROM detections a
            JOIN detections b
              ON  a.session_id   = b.session_id
              AND a.session_id  <> ''
              AND b.event_ts    >= a.event_ts
              AND b.event_ts    <= a.event_ts + {self.time_window_sec}
              AND a.detection_id < b.detection_id
        """
        yield from self._run_query(sql, "same_session")

    def _lateral_auth_followup(self) -> Iterator[CandidatePair]:
        """Detect lateral movement: auth event on src followed by activity on dst."""
        sql = f"""
            SELECT
                a.detection_id      AS src_detection_id,
                b.detection_id      AS dst_detection_id,
                a.event_uid         AS src_event_uid,
                b.event_uid         AS dst_event_uid,
                a.host_name         AS src_host,
                b.host_name         AS dst_host,
                a.user_name         AS src_user,
                b.user_name         AS dst_user,
                a.event_ts          AS src_ts,
                b.event_ts          AS dst_ts,
                (b.event_ts - a.event_ts) AS delta_seconds,
                'lateral_auth'      AS candidate_type,
                a.user_name || ':' || a.dst_ip AS join_key
            FROM detections a
            JOIN detections b
              ON  (a.dst_ip = b.host_name OR a.dst_ip = b.src_ip)
              AND a.user_name  = b.user_name
              AND b.event_ts  >= a.event_ts
              AND b.event_ts  <= a.event_ts + {self.time_window_sec}
              AND a.dst_ip    <> ''
              AND a.host_name <> b.host_name
        """
        yield from self._run_query(sql, "lateral_auth")

    def _network_connection_followup(self) -> Iterator[CandidatePair]:
        """Detect network connection followed by activity on destination host."""
        sql = f"""
            SELECT
                n.detection_id        AS src_detection_id,
                h.detection_id        AS dst_detection_id,
                n.event_uid           AS src_event_uid,
                h.event_uid           AS dst_event_uid,
                n.host_name           AS src_host,
                h.host_name           AS dst_host,
                n.user_name           AS src_user,
                h.user_name           AS dst_user,
                n.event_ts            AS src_ts,
                h.event_ts            AS dst_ts,
                (h.event_ts - n.event_ts) AS delta_seconds,
                'network_follow'      AS candidate_type,
                n.dst_ip || ':' || n.host_name AS join_key
            FROM detections n
            JOIN detections h
              ON  (n.dst_ip = h.host_name OR n.dst_ip = h.src_ip)
              AND h.event_ts  >= n.event_ts
              AND h.event_ts  <= n.event_ts + {self.time_window_sec}
              AND n.dst_ip   <> ''
              AND n.host_name <> h.host_name
        """
        yield from self._run_query(sql, "network_follow")

    # ------------------------------------------------------------------
    # Query runner
    # ------------------------------------------------------------------

    def _run_query(self, sql: str, label: str) -> Iterator[CandidatePair]:
        try:
            result = self._con.execute(sql).fetchall()
            logger.debug("CandidateGenerator[%s]: %d pairs found", label, len(result))
            for row in result:
                (
                    src_did, dst_did, src_eu, dst_eu,
                    src_h, dst_h, src_u, dst_u,
                    src_ts, dst_ts, delta, ctype, jkey,
                ) = row
                if delta < 0 or delta > _MAX_DELTA:
                    continue
                yield CandidatePair(
                    src_detection_id=src_did or "",
                    dst_detection_id=dst_did or "",
                    src_event_uid=src_eu or "",
                    dst_event_uid=dst_eu or "",
                    src_host=src_h or "",
                    dst_host=dst_h or "",
                    src_user=src_u or "",
                    dst_user=dst_u or "",
                    src_ts=float(src_ts or 0),
                    dst_ts=float(dst_ts or 0),
                    delta_seconds=float(delta or 0),
                    candidate_type=ctype or label,
                    join_key=jkey or "",
                    raw_evidence_uids=(src_eu, dst_eu),
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("CandidateGenerator[%s] query error: %s", label, exc)
