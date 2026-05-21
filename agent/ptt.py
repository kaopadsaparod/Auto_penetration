"""
Pentest Tree (PTT) — Schema and SQLite persistence.

This is the single source of truth for the entire agent.
Every agent reads from and writes to this store.

Schema:
  PentestNode — A single node in the pentest tree (one action/finding).
  PTTStore    — SQLite-backed CRUD for nodes with tree traversal.
"""

import json
import logging
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
# PentestNode — one step in the pentest tree
# ════════════════════════════════════════════════════════════════

@dataclass
class PentestNode:
    """
    A single node in the Pentest Tree.

    Each node represents one action (scan, exploit attempt, etc.)
    and its results. Nodes form a tree via parent_id for full
    attack path traceability.
    """
    # 12 hex chars = 48 bits → collision-safe for thousands of nodes
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    phase: Literal["recon", "enum", "exploit", "post", "report"] = "recon"
    status: Literal["pending", "running", "success", "failed", "skipped"] = "pending"

    parent_id: Optional[str] = None
    tool_used: Optional[str] = None
    command_run: Optional[str] = None       # Exact command for replay
    raw_output: Optional[str] = None

    # Structured data — stored as JSON in SQLite
    findings: list = field(default_factory=list)
    next_hypotheses: list = field(default_factory=list)

    tokens_used: int = 0                    # Track cost per node
    error_message: Optional[str] = None     # If status == "failed"
    notes: Optional[str] = None             # Human or agent annotations

    created_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    def to_dict(self) -> dict:
        """Convert to dict with JSON-serializable list fields."""
        d = asdict(self)
        d["findings"] = json.dumps(d["findings"])
        d["next_hypotheses"] = json.dumps(d["next_hypotheses"])
        return d

    @classmethod
    def from_row(cls, row: dict) -> "PentestNode":
        """Reconstruct from a SQLite row dict."""
        row = dict(row)
        row["findings"] = json.loads(row.get("findings", "[]") or "[]")
        row["next_hypotheses"] = json.loads(
            row.get("next_hypotheses", "[]") or "[]"
        )
        return cls(**row)


# ════════════════════════════════════════════════════════════════
# PTTStore — SQLite persistence
# ════════════════════════════════════════════════════════════════

# Phase priority: earlier phases get processed first
PHASE_PRIORITY = {
    "recon": 0,
    "enum": 1,
    "exploit": 2,
    "post": 3,
    "report": 4,
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS pentest_nodes (
    id              TEXT PRIMARY KEY,
    phase           TEXT NOT NULL DEFAULT 'recon',
    status          TEXT NOT NULL DEFAULT 'pending',
    parent_id       TEXT,
    tool_used       TEXT,
    command_run     TEXT,
    raw_output      TEXT,
    findings        TEXT DEFAULT '[]',
    next_hypotheses TEXT DEFAULT '[]',
    tokens_used     INTEGER DEFAULT 0,
    error_message   TEXT,
    notes           TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES pentest_nodes(id)
);
"""

CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_status ON pentest_nodes(status);",
    "CREATE INDEX IF NOT EXISTS idx_phase ON pentest_nodes(phase);",
    "CREATE INDEX IF NOT EXISTS idx_parent ON pentest_nodes(parent_id);",
]


class PTTStore:
    """
    SQLite-backed storage for the Pentest Tree.

    Uses WAL mode for safe concurrent reads. All list fields
    (findings, next_hypotheses) are stored as JSON strings.
    """

    def __init__(self, db_path: Optional[str] = None, target_ip: Optional[str] = None):
        if db_path is None:
            if target_ip:
                safe_ip = target_ip.replace(".", "_").replace(":", "_").replace("/", "_")
                db_path = f"./data/ptt_{safe_ip}.db"
            else:
                db_path = "./data/ptt.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")  # Safe concurrency
        self.conn.execute("PRAGMA foreign_keys=ON;")

        self._create_tables()
        logger.info("PTTStore initialized at %s", self.db_path)

    def _create_tables(self) -> None:
        """Create tables and indexes if they don't exist."""
        self.conn.execute(CREATE_TABLE_SQL)
        for idx_sql in CREATE_INDEXES_SQL:
            self.conn.execute(idx_sql)
        self.conn.commit()

    # ── CRUD ─────────────────────────────────────────────────

    def save(self, node: PentestNode) -> None:
        """
        Upsert a node. Updates `updated_at` automatically.
        """
        node.updated_at = datetime.now().isoformat()
        d = node.to_dict()
        columns = ", ".join(d.keys())
        placeholders = ", ".join(["?"] * len(d))
        update_clause = ", ".join(
            f"{k}=excluded.{k}" for k in d.keys() if k != "id"
        )

        sql = f"""
            INSERT INTO pentest_nodes ({columns})
            VALUES ({placeholders})
            ON CONFLICT(id) DO UPDATE SET {update_clause}
        """
        self.conn.execute(sql, list(d.values()))
        self.conn.commit()
        logger.debug("Saved node %s (phase=%s, status=%s)",
                      node.id, node.phase, node.status)

    def get(self, node_id: str) -> Optional[PentestNode]:
        """Retrieve a single node by ID."""
        row = self.conn.execute(
            "SELECT * FROM pentest_nodes WHERE id = ?", (node_id,)
        ).fetchone()
        return PentestNode.from_row(row) if row else None

    def delete(self, node_id: str) -> bool:
        """Delete a node by ID. Returns True if a row was deleted."""
        cursor = self.conn.execute(
            "DELETE FROM pentest_nodes WHERE id = ?", (node_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    # ── Query methods ────────────────────────────────────────

    def get_next_pending(self) -> Optional[PentestNode]:
        """
        Get the highest-priority pending node.

        Priority order:
          1. Earlier phases first (recon → enum → exploit → post → report)
          2. Oldest nodes first within same phase
        """
        row = self.conn.execute(
            """
            SELECT * FROM pentest_nodes
            WHERE status = 'pending'
            ORDER BY
                CASE phase
                    WHEN 'recon'   THEN 0
                    WHEN 'enum'    THEN 1
                    WHEN 'exploit' THEN 2
                    WHEN 'post'    THEN 3
                    WHEN 'report'  THEN 4
                END,
                created_at ASC
            LIMIT 1
            """,
        ).fetchone()
        return PentestNode.from_row(row) if row else None

    def get_all_by_status(
        self, status: str
    ) -> list[PentestNode]:
        """Get all nodes with a given status."""
        rows = self.conn.execute(
            "SELECT * FROM pentest_nodes WHERE status = ? ORDER BY created_at",
            (status,),
        ).fetchall()
        return [PentestNode.from_row(r) for r in rows]

    def get_all_by_phase(
        self, phase: str
    ) -> list[PentestNode]:
        """Get all nodes in a given phase."""
        rows = self.conn.execute(
            "SELECT * FROM pentest_nodes WHERE phase = ? ORDER BY created_at",
            (phase,),
        ).fetchall()
        return [PentestNode.from_row(r) for r in rows]

    def get_children(self, parent_id: str) -> list[PentestNode]:
        """Get all direct children of a node."""
        rows = self.conn.execute(
            "SELECT * FROM pentest_nodes WHERE parent_id = ? ORDER BY created_at",
            (parent_id,),
        ).fetchall()
        return [PentestNode.from_row(r) for r in rows]

    def get_all(self) -> list[PentestNode]:
        """Get all nodes, ordered by creation time."""
        rows = self.conn.execute(
            "SELECT * FROM pentest_nodes ORDER BY created_at"
        ).fetchall()
        return [PentestNode.from_row(r) for r in rows]

    # ── Stats & budget tracking ──────────────────────────────

    def get_total_tokens(self) -> int:
        """Total tokens used across all nodes."""
        row = self.conn.execute(
            "SELECT COALESCE(SUM(tokens_used), 0) as total FROM pentest_nodes"
        ).fetchone()
        return row["total"]

    def get_stats(self) -> dict:
        """Summary statistics for the current run."""
        return {
            "total_nodes": self.conn.execute(
                "SELECT COUNT(*) as c FROM pentest_nodes"
            ).fetchone()["c"],
            "pending": self.conn.execute(
                "SELECT COUNT(*) as c FROM pentest_nodes WHERE status='pending'"
            ).fetchone()["c"],
            "running": self.conn.execute(
                "SELECT COUNT(*) as c FROM pentest_nodes WHERE status='running'"
            ).fetchone()["c"],
            "success": self.conn.execute(
                "SELECT COUNT(*) as c FROM pentest_nodes WHERE status='success'"
            ).fetchone()["c"],
            "failed": self.conn.execute(
                "SELECT COUNT(*) as c FROM pentest_nodes WHERE status='failed'"
            ).fetchone()["c"],
            "total_tokens": self.get_total_tokens(),
            "by_phase": {
                phase: self.conn.execute(
                    "SELECT COUNT(*) as c FROM pentest_nodes WHERE phase=?",
                    (phase,),
                ).fetchone()["c"]
                for phase in PHASE_PRIORITY
            },
        }

    # ── Tree export ──────────────────────────────────────────

    def export_tree(self) -> list[dict]:
        """
        Export full PTT as a list of dicts (for reporting).
        Sensitive fields (raw_output) are truncated.
        """
        nodes = self.get_all()
        result = []
        for n in nodes:
            d = asdict(n)
            # Truncate raw output for reports
            if d["raw_output"] and len(d["raw_output"]) > 500:
                d["raw_output"] = d["raw_output"][:500] + "... [truncated]"
            result.append(d)
        return result

    # ── Cleanup ──────────────────────────────────────────────

    def reset(self) -> None:
        """Delete ALL nodes. Use with caution."""
        self.conn.execute("DELETE FROM pentest_nodes")
        self.conn.commit()
        logger.warning("PTTStore RESET — all nodes deleted")

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
        logger.info("PTTStore connection closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
