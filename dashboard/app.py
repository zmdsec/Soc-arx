from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    with open("../logs/events.log") as f:
        logs = f.readlines()
    return "<br>".join(logs[-50:])

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
