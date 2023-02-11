from flask import Flask, request
from base64 import b64decode
import json
import requests


app = Flask(__name__)


@app.route('/', methods=["GET"])
def index():
    with open("index.html", "r") as f:
        return f.read()


@app.route('/login', methods=["POST"])
def login():
    data = json.loads(b64decode(request.json["data"]))
    requests.post("http://localhost:8080/login", json=data)
    return ""


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8888)
