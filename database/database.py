# ===================================
#  Trust Me Bro — Database Layer
#  SQLite storage for scan results
# ===================================

import json
import sqlite3
from datetime import datetime

from config import DATABASE_PATH


def _connect():
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the scans table if it does not exist."""
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT    NOT NULL,
            risk_score      INTEGER NOT NULL,
            classification  TEXT    NOT NULL,
            badge_class     TEXT    NOT NULL,
            reasons         TEXT    NOT NULL,
            recommendations TEXT    NOT NULL,
            scanned_at      TEXT    NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(url, risk_score, classification, badge_class, reasons, recommendations):
    """Insert a scan record and return its ID."""
    conn = _connect()
    cursor = conn.execute(
        """
        INSERT INTO scans (url, risk_score, classification, badge_class,
                           reasons, recommendations, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            risk_score,
            classification,
            badge_class,
            json.dumps(reasons),
            json.dumps(recommendations),
            datetime.now().isoformat(),
        ),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_scan(scan_id):
    """Retrieve a single scan by ID. Returns a dict or None."""
    conn = _connect()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "url": row["url"],
        "risk_score": row["risk_score"],
        "classification": row["classification"],
        "badge_class": row["badge_class"],
        "reasons": json.loads(row["reasons"]),
        "recommendations": json.loads(row["recommendations"]),
        "scanned_at": row["scanned_at"],
    }


def get_latest_scan():
    """Return the most recent scan record, or None."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "url": row["url"],
        "risk_score": row["risk_score"],
        "classification": row["classification"],
        "badge_class": row["badge_class"],
        "reasons": json.loads(row["reasons"]),
        "recommendations": json.loads(row["recommendations"]),
        "scanned_at": row["scanned_at"],
    }
