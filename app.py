# ===================================
#  Trust Me Bro — Flask Application
#  Phishing Detection Web Server
# ===================================

import os
from datetime import datetime

from flask import Flask, render_template, request, send_from_directory, redirect, url_for

from config import REPORTS_DIR
from database.database import init_db, get_scan, get_latest_scan
from modules.analyzer import analyze_url
from modules.report_generator import generate_pdf
from modules.trainer import init_training, get_training_stats, get_all_learned_weights, get_learned_keywords

app = Flask(__name__)

# Initialize the database and training tables on startup
init_db()
init_training()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()

    if not url:
        return redirect(url_for("home"))

    # Run the full analysis pipeline
    result = analyze_url(url)

    return render_template(
        "result.html",
        url=result["url"],
        risk_score=result["risk_score"],
        classification=result["classification"],
        badge_class=result["badge_class"],
        reasons=result["reasons"],
        recommendations=result["recommendations"],
        scan_id=result["scan_id"],
    )


@app.route("/report")
def report():
    # Try to load a specific scan by ID, otherwise use the latest
    scan_id = request.args.get("scan_id", type=int)

    if scan_id:
        scan = get_scan(scan_id)
    else:
        scan = get_latest_scan()

    if scan is None:
        return redirect(url_for("home"))

    # Parse the timestamp for display
    scanned_at = datetime.fromisoformat(scan["scanned_at"])

    return render_template(
        "report.html",
        url=scan["url"],
        risk_score=scan["risk_score"],
        classification=scan["classification"],
        badge_class=scan["badge_class"],
        reasons=scan["reasons"],
        recommendations=scan["recommendations"],
        generated_date=scanned_at.strftime("%d %B %Y"),
        generated_time=scanned_at.strftime("%I:%M %p"),
    )


@app.route("/download")
def download_report():
    """Generate a PDF incident report and serve it for download."""
    scan_id = request.args.get("scan_id", type=int)

    if scan_id:
        scan = get_scan(scan_id)
    else:
        scan = get_latest_scan()

    if scan is None:
        return redirect(url_for("home"))

    filename = generate_pdf(scan)

    return send_from_directory(
        REPORTS_DIR,
        filename,
        as_attachment=True,
        download_name=f"TrustMeBro_Report_{scan['id']}.pdf",
    )


@app.route("/stats")
def stats():
    """Show training statistics and learned intelligence."""
    training = get_training_stats()
    weights = get_all_learned_weights()
    keywords = get_learned_keywords()
    return render_template(
        "stats.html",
        training=training,
        weights=weights,
        keywords=keywords,
    )


if __name__ == "__main__":
    app.run(debug=True)
