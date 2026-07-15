from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"]

    print(url)

    return f"You entered {url}"

if __name__ == "__main__":
    app.run(debug=True)