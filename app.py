import os

from flask import Flask, jsonify, request

from policy import decide

app = Flask(__name__)


@app.post("/release-gate")
def release_gate():
    body = request.get_json(silent=True) or {}
    result = decide(body)
    return jsonify(result), 200


@app.get("/healthz")
def healthz():
    return "ok", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
