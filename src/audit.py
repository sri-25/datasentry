"""
DataSentry v2 — Layer 4: SQLite Audit Trail
"""

import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

CREATE_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS detection_runs (
    run_id          TEXT PRIMARY KEY,
    source_label    TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    source_text_len INTEGER,
    total_pii       INTEGER DEFAULT 0,
    total_phi       INTEGER DEFAULT 0,
    entity_count    INTEGER DEFAULT 0,
    layers_used     TEXT,
    processing_ms   REAL
);
"""

CREATE_ENTITIES_TABLE = """
CREATE TABLE IF NOT EXISTS detected_entities (
    entity_id       TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    entity_text     TEXT NOT NULL,
    entity_type     TEXT NOT NULL,
    category        TEXT NOT NULL,
    char_start      INTEGER,
    char_end        INTEGER,
    confidence      REAL,
    detection_layer TEXT,
    escalated       INTEGER DEFAULT 0,
    claude_override INTEGER DEFAULT 0,
    rationale       TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES detection_runs(run_id)
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_runs_label ON detection_runs(source_label);",
    "CREATE INDEX IF NOT EXISTS idx_entities_run ON detected_entities(run_id);",
    "CREATE INDEX IF NOT EXISTS idx_entities_type ON detected_entities(entity_type);",
    "CREATE INDEX IF NOT EXISTS idx_entities_category ON detected_entities(category);",
]


class AuditLogger:

    def __init__(self, db_path="datasentry_audit.db"):
        self.db_path = db_path
        # For :memory: keep one persistent connection
        # For file-based DB open fresh connections per call
        if db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:")
            self._memory_conn.row_factory = sqlite3.Row
            self._init_db_conn(self._memory_conn)
        else:
            self._memory_conn = None
            self._init_db_file()

    def _init_db_file(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(CREATE_RUNS_TABLE)
        conn.execute(CREATE_ENTITIES_TABLE)
        for idx in CREATE_INDEXES:
            conn.execute(idx)
        conn.commit()
        conn.close()

    def _init_db_conn(self, conn):
        conn.execute(CREATE_RUNS_TABLE)
        conn.execute(CREATE_ENTITIES_TABLE)
        for idx in CREATE_INDEXES:
            conn.execute(idx)
        conn.commit()

    def _conn(self):
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _close(self, conn):
        # Never close the persistent memory connection
        if self._memory_conn is None:
            conn.close()

    def log(self, result, source_label):
        ts = datetime.utcnow().isoformat()
        try:
            conn = self._conn()
            conn.execute(
                """INSERT INTO detection_runs
                   (run_id, source_label, timestamp, source_text_len,
                    total_pii, total_phi, entity_count, layers_used, processing_ms)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    result.run_id,
                    source_label,
                    result.timestamp,
                    len(result.source_text),
                    result.total_pii,
                    result.total_phi,
                    len(result.entities),
                    json.dumps(list(set(result.layers_used))),
                    result.processing_ms,
                )
            )
            for ent in result.entities:
                conn.execute(
                    """INSERT INTO detected_entities
                       (entity_id, run_id, entity_text, entity_type, category,
                        char_start, char_end, confidence, detection_layer,
                        escalated, claude_override, rationale, timestamp)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ent.entity_id,
                        result.run_id,
                        ent.text,
                        ent.entity_type,
                        ent.category,
                        ent.start,
                        ent.end,
                        ent.confidence,
                        ent.detection_layer,
                        int(ent.escalated),
                        int(ent.claude_override),
                        ent.rationale,
                        ts,
                    )
                )
            conn.commit()
            self._close(conn)
        except sqlite3.Error as e:
            logger.error("Audit log failed for run %s: %s", result.run_id, e)
            raise

    def get_run(self, run_id):
        conn = self._conn()
        row = conn.execute(
            "SELECT * FROM detection_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        self._close(conn)
        return dict(row) if row else None

    def get_entities_for_run(self, run_id):
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM detected_entities WHERE run_id = ? ORDER BY char_start",
            (run_id,)
        ).fetchall()
        self._close(conn)
        return [dict(r) for r in rows]

    def get_recent_runs(self, limit=50):
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM detection_runs ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        self._close(conn)
        return [dict(r) for r in rows]

    def get_stats(self):
        conn = self._conn()
        stats = conn.execute("""
            SELECT
                COUNT(*) as total_runs,
                SUM(total_pii) as total_pii_found,
                SUM(total_phi) as total_phi_found,
                SUM(entity_count) as total_entities,
                AVG(processing_ms) as avg_processing_ms
            FROM detection_runs
        """).fetchone()

        escalation_count = conn.execute(
            "SELECT COUNT(*) FROM detected_entities WHERE escalated = 1"
        ).fetchone()[0]

        type_breakdown = conn.execute("""
            SELECT entity_type, COUNT(*) as cnt
            FROM detected_entities
            GROUP BY entity_type
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
        self._close(conn)

        return {
            "total_runs": stats["total_runs"],
            "total_pii_found": stats["total_pii_found"] or 0,
            "total_phi_found": stats["total_phi_found"] or 0,
            "total_entities": stats["total_entities"] or 0,
            "avg_processing_ms": round(stats["avg_processing_ms"] or 0, 2),
            "escalated_to_claude": escalation_count,
            "top_entity_types": [
                {"type": r["entity_type"], "count": r["cnt"]}
                for r in type_breakdown
            ],
        }

    def search_entities(self, entity_type=None, category=None,
                        min_confidence=0.0, limit=100):
        query = "SELECT * FROM detected_entities WHERE confidence >= ?"
        params = [min_confidence]
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        conn = self._conn()
        rows = conn.execute(query, params).fetchall()
        self._close(conn)
        return [dict(r) for r in rows]