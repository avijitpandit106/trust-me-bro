# ===================================
#  Trust Me Bro — Explainer
#  Translates scores into human-
#  readable classifications and advice
# ===================================

from config import CLASSIFICATIONS, RECOMMENDATIONS


def explain(risk_score, triggered_indicators):
    """
    Convert a numeric risk score and raw indicator list into
    user-friendly output for the frontend templates.

    Returns a dict:
        classification  — "Safe" | "Suspicious" | "High Risk" | "Critical"
        badge_class     — CSS class for the badge element
        reasons         — list of human-readable reason strings
        recommendations — list of actionable advice strings
    """

    # Determine classification from score
    classification = "Critical"
    badge_class = "malicious"

    for max_score, label, css_class in CLASSIFICATIONS:
        if risk_score <= max_score:
            classification = label
            badge_class = css_class
            break

    # Build human-readable reasons
    reasons = [ind["label"] for ind in triggered_indicators]

    if not reasons:
        reasons = ["No phishing indicators were detected."]

    # Get recommendations for this classification level
    recommendations = RECOMMENDATIONS.get(classification, [])

    return {
        "classification": classification,
        "badge_class": badge_class,
        "reasons": reasons,
        "recommendations": recommendations,
    }
