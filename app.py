from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "")

    # Placeholder data — replace with real analysis logic later
    risk_score = 82
    classification = "High Risk"
    badge_class = "high-risk"
    reasons = [
        "Recently registered domain",
        "Invalid SSL Certificate",
        "Contains suspicious keywords",
        "Redirect detected",
        "Domain resembles a popular brand",
    ]
    recommendations = [
        "Do not visit this website.",
        "Do not submit credentials.",
        "Report this URL to your administrator.",
    ]

    return render_template(
        "result.html",
        url=url,
        risk_score=risk_score,
        classification=classification,
        badge_class=badge_class,
        reasons=reasons,
        recommendations=recommendations,
    )

@app.route("/report")
def report():
    url = "https://paypal-login.xyz"
    risk_score = 82
    classification = "High Risk"
    badge_class = "high-risk"
    reasons = [
        "Recently Registered Domain",
        "Invalid SSL Certificate",
        "Redirect Detected",
        "Suspicious Keywords Found",
        "Brand Impersonation Detected",
    ]
    recommendations = [
        "Do not visit the website.",
        "Do not enter passwords or payment details.",
        "Report the URL to your administrator.",
        "Block the domain if necessary.",
    ]

    from datetime import datetime
    now = datetime.now()

    return render_template(
        "report.html",
        url=url,
        risk_score=risk_score,
        classification=classification,
        badge_class=badge_class,
        reasons=reasons,
        recommendations=recommendations,
        generated_date=now.strftime("%d %B %Y"),
        generated_time=now.strftime("%I:%M %p"),
    )

if __name__ == "__main__":
    app.run(debug=True)
