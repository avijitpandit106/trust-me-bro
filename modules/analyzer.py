# ===================================
#  Trust Me Bro — Analyzer
#  Orchestrates the full analysis
#  pipeline:  collect → score → explain
# ===================================

import sys
import os

# Ensure project root is on sys.path so config can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.collector import collect
from modules.scorer import score
from modules.explainer import explain
from database.database import save_scan


def analyze_url(url):
    """
    Run the full phishing analysis pipeline on a URL.

    Pipeline:
        url → collect() → score() → explain() → save_scan()

    Returns a dict ready for template rendering:
        url, risk_score, classification, badge_class,
        reasons, recommendations, scan_id
    """
    # Step 1 — Collect raw data
    collected = collect(url)

    # Step 2 — Score the data
    risk_score, triggered = score(collected)

    # Step 3 — Explain the results
    explanation = explain(risk_score, triggered)

    # Step 4 — Persist to database
    scan_id = save_scan(
        url=url,
        risk_score=risk_score,
        classification=explanation["classification"],
        badge_class=explanation["badge_class"],
        reasons=explanation["reasons"],
        recommendations=explanation["recommendations"],
    )

    # Build result dict matching template variable names
    return {
        "url": url,
        "risk_score": risk_score,
        "classification": explanation["classification"],
        "badge_class": explanation["badge_class"],
        "reasons": explanation["reasons"],
        "recommendations": explanation["recommendations"],
        "scan_id": scan_id,
    }
