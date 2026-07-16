# ===================================
#  Trust Me Bro — Trainer
#  Self-learning module that adjusts
#  scoring weights from scan history
# ===================================

import json
import sqlite3
from collections import defaultdict

from config import DATABASE_PATH, SCORING_WEIGHTS


def _connect():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_training():
    """Create the training_data table if it does not exist."""
    conn = _connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS training_data (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            url         TEXT    NOT NULL,
            risk_score  INTEGER NOT NULL,
            indicators  TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS learned_weights (
            indicator   TEXT PRIMARY KEY,
            weight      INTEGER NOT NULL,
            confidence  REAL    NOT NULL DEFAULT 0.0,
            updated_at  TEXT    NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS learned_keywords (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword     TEXT    NOT NULL UNIQUE,
            frequency   INTEGER NOT NULL DEFAULT 1,
            added_at    TEXT    NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def record_scan(scan_id, url, risk_score, triggered_indicators):
    """Record a scan's indicator data for training."""
    from datetime import datetime

    conn = _connect()
    indicator_keys = [ind["key"] for ind in triggered_indicators]
    conn.execute(
        """
        INSERT INTO training_data (scan_id, url, risk_score, indicators, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            url,
            risk_score,
            json.dumps(indicator_keys),
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def learn_from_history():
    """Analyze all past scans and adjust indicator weights.

    The learning algorithm:
    1. Counts how often each indicator appears in high-risk (>=60) vs safe (<30) scans
    2. Indicators that appear predominantly in high-risk scans get weight boosts
    3. Indicators that appear in safe scans get slight penalties
    4. Extracts suspicious keywords from high-risk URLs not already in the keyword list
    """
    from datetime import datetime
    from config import SUSPICIOUS_KEYWORDS

    conn = _connect()
    rows = conn.execute(
        "SELECT url, risk_score, indicators FROM training_data"
    ).fetchall()
    conn.close()

    if len(rows) < 3:
        return {"status": "needs_more_data", "scans": len(rows), "min_required": 3}

    # Count indicator frequency per risk tier
    indicator_high = defaultdict(int)   # risk_score >= 60
    indicator_safe = defaultdict(int)   # risk_score < 30
    total_high = 0
    total_safe = 0
    high_risk_urls = []

    for row in rows:
        score = row["risk_score"]
        indicators = json.loads(row["indicators"])

        if score >= 60:
            total_high += 1
            for key in indicators:
                indicator_high[key] += 1
            high_risk_urls.append(row["url"])
        elif score < 30:
            total_safe += 1
            for key in indicators:
                indicator_safe[key] += 1

    # Update weights based on indicator correlation
    new_weights = {}
    conn = _connect()
    now = datetime.now().isoformat()

    for key, (base_points, label) in SCORING_WEIGHTS.items():
        high_count = indicator_high.get(key, 0)
        safe_count = indicator_safe.get(key, 0)

        # Calculate a learned adjustment
        # If indicator appears mostly in high-risk scans, boost it
        # If it appears in safe scans, slightly reduce it
        if total_high > 0 and total_safe > 0:
            high_rate = high_count / total_high
            safe_rate = safe_count / total_safe
            # Positive boost: indicator is predictive of phishing
            adjustment = round((high_rate - safe_rate) * 10)
        elif total_high > 0:
            high_rate = high_count / total_high
            adjustment = round(high_rate * 8)
        else:
            adjustment = 0

        # Clamp: don't go below 2 or above 30 for any single indicator
        learned_weight = max(2, min(30, base_points + adjustment))
        confidence = min(1.0, (high_count + safe_count) / max(len(rows), 1))

        new_weights[key] = (learned_weight, label)

        conn.execute(
            """
            INSERT INTO learned_weights (indicator, weight, confidence, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                weight = excluded.weight,
                confidence = excluded.confidence,
                updated_at = excluded.updated_at
            """,
            (key, learned_weight, round(confidence, 3), now),
        )

    conn.commit()
    conn.close()

    # Learn new keywords from high-risk URLs
    learned_count = _learn_keywords(high_risk_urls, SUSPICIOUS_KEYWORDS)

    return {
        "status": "trained",
        "total_scans": len(rows),
        "high_risk_scans": total_high,
        "safe_scans": total_safe,
        "weights_updated": len(new_weights),
        "keywords_learned": learned_count,
    }


def _learn_keywords(high_risk_urls, existing_keywords):
    """Extract common substrings from high-risk URLs as new suspicious keywords."""
    from datetime import datetime

    # Collect path segments and query params from high-risk URLs
    from urllib.parse import urlparse, parse_qs

    candidate_words = defaultdict(int)

    for url in high_risk_urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path
        query = parsed.query

        # Extract words from hostname (excluding TLD)
        parts = hostname.split(".")
        for part in parts:
            if len(part) >= 4 and part not in ("www", "com", "org", "net", "co"):
                candidate_words[part.lower()] += 1

        # Extract words from path segments
        for segment in path.split("/"):
            segment = segment.strip("-_")
            if len(segment) >= 4:
                candidate_words[segment.lower()] += 1

        # Extract words from query parameters
        for key in parse_qs(query):
            if len(key) >= 4:
                candidate_words[key.lower()] += 1

    # Save keywords that appear at least twice and aren't already known
    new_count = 0
    conn = _connect()
    now = datetime.now().isoformat()

    for word, freq in candidate_words.items():
        if freq < 2 or word in existing_keywords:
            continue
        try:
            conn.execute(
                """
                INSERT INTO learned_keywords (keyword, frequency, added_at)
                VALUES (?, ?, ?)
                ON CONFLICT(keyword) DO UPDATE SET
                    frequency = excluded.frequency
                """,
                (word, freq, now),
            )
            new_count += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    return new_count


def get_learned_weight(indicator_key):
    """Get the learned weight for an indicator, or None if not yet learned."""
    conn = _connect()
    row = conn.execute(
        "SELECT weight, confidence FROM learned_weights WHERE indicator = ?",
        (indicator_key,),
    ).fetchone()
    conn.close()

    if row is None:
        return None
    return {"weight": row["weight"], "confidence": row["confidence"]}


def get_all_learned_weights():
    """Return all learned weights as a dict."""
    conn = _connect()
    rows = conn.execute("SELECT indicator, weight, confidence FROM learned_weights").fetchall()
    conn.close()
    return {
        row["indicator"]: {"weight": row["weight"], "confidence": row["confidence"]}
        for row in rows
    }


def get_learned_keywords():
    """Return all learned keywords."""
    conn = _connect()
    rows = conn.execute(
        "SELECT keyword, frequency FROM learned_keywords ORDER BY frequency DESC"
    ).fetchall()
    conn.close()
    return [{"keyword": row["keyword"], "frequency": row["frequency"]} for row in rows]


def get_training_stats():
    """Return overall training statistics."""
    conn = _connect()
    total = conn.execute("SELECT COUNT(*) as c FROM training_data").fetchone()["c"]
    weights = conn.execute("SELECT COUNT(*) as c FROM learned_weights").fetchone()["c"]
    keywords = conn.execute("SELECT COUNT(*) as c FROM learned_keywords").fetchone()["c"]

    avg_score = conn.execute(
        "SELECT AVG(risk_score) as avg FROM training_data"
    ).fetchone()["avg"]

    high_risk = conn.execute(
        "SELECT COUNT(*) as c FROM training_data WHERE risk_score >= 60"
    ).fetchone()["c"]

    conn.close()

    return {
        "total_scans": total,
        "learned_weights": weights,
        "learned_keywords": keywords,
        "avg_risk_score": round(avg_score or 0, 1),
        "high_risk_scans": high_risk,
    }
