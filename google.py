from flask import Flask, redirect, request, session, jsonify
from config import SECRET_KEY
from providers.google import google_oauth

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)
app.secret_key = SECRET_KEY

if __name__ == "__main__":
    app.run(port=8000)
