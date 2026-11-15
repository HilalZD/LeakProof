from flask import Flask, request
import os

app = Flask(__name__)
client_key = os.environ["OPENAI_API_KEY"]


@app.post("/api/summarize")
def summarize():
    email = request.json["email"]
    print(email)
    return {"ok": True}
