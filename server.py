import os, secrets, hashlib, re
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("SESSION_SECRET", "")
if not app.secret_key:
    raise RuntimeError("Set SESSION_SECRET to a long random value before starting.")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
if not APP_PASSWORD:
    raise RuntimeError("Set APP_PASSWORD to protect your hosted scanner.")
app.config.update(
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)
limiter = Limiter(get_remote_address, app=app, default_limits=["120 per hour"], storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))
VT = "https://www.virustotal.com/api/v3"
TIMEOUT = 60

def require_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify(error="Please sign in again."), 401
        if request.method in ("POST", "PUT", "DELETE"):
            token = request.headers.get("X-CSRF-Token", "")
            if not token or not secrets.compare_digest(token, session.get("csrf", "")):
                return jsonify(error="Security token expired. Refresh and sign in again."), 403
        return fn(*args, **kwargs)
    return wrapped

def headers():
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY is not configured in the hosting environment.")
    return {"x-apikey": VT_API_KEY}

@app.get("/")
def home():
    return send_from_directory("static", "index.html")

@app.get("/health")
def health():
    return jsonify(status="ok", service="guardian-scan")

@app.get("/api/me")
def me():
    if session.get("authenticated"):
        return jsonify(authenticated=True, csrf_token=session.get("csrf"))
    return jsonify(authenticated=False)

@app.post("/api/login")
@limiter.limit("10 per minute")
def login():
    body = request.get_json(silent=True) or {}
    supplied = body.get("password", "")
    if not secrets.compare_digest(str(supplied), APP_PASSWORD):
        return jsonify(error="Incorrect password."), 401
    session.clear()
    session["authenticated"] = True
    session["csrf"] = secrets.token_urlsafe(32)
    return jsonify(authenticated=True, csrf_token=session["csrf"])

@app.post("/api/logout")
@require_login
def logout():
    session.clear()
    return jsonify(ok=True)

@app.post("/api/scan-url")
@require_login
@limiter.limit("10 per minute")
def scan_url():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()
    if len(url) > 2048 or not re.match(r"^https?://[^\\s]+$", url, re.I):
        return jsonify(error="Enter a valid HTTP or HTTPS URL (maximum 2048 characters)."), 400
    try:
        r = requests.post(VT + "/urls", headers=headers(), data={"url": url}, timeout=TIMEOUT)
        return vt_response(r, submission=True)
    except requests.RequestException as e:
        return jsonify(error="Could not reach VirusTotal: " + str(e)), 502
    except RuntimeError as e:
        return jsonify(error=str(e)), 500

@app.post("/api/scan-file")
@require_login
@limiter.limit("5 per minute")
def scan_file():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose a file to scan."), 400
    try:
        content = f.read(32 * 1024 * 1024 + 1)
        if len(content) > 32 * 1024 * 1024:
            return jsonify(error="File exceeds the 32 MB upload limit."), 413
        digest = hashlib.sha256(content).hexdigest()
        # Bytes are streamed to VirusTotal in-memory; the server does not save or execute them.
        r = requests.post(VT + "/files", headers=headers(),
                         files={"file": (f.filename, content, f.mimetype or "application/octet-stream")},
                         timeout=TIMEOUT)
        result = vt_response(r, submission=True)
        if isinstance(result, tuple):
            return result
        result_json = result.get_json()
        result_json["sha256"] = digest
        return jsonify(result_json)
    except requests.RequestException as e:
        return jsonify(error="Could not reach VirusTotal: " + str(e)), 502
    except RuntimeError as e:
        return jsonify(error=str(e)), 500

@app.get("/api/analysis/<path:analysis_id>")
@require_login
@limiter.limit("60 per minute")
def analysis(analysis_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", analysis_id):
        return jsonify(error="Invalid analysis identifier."), 400
    try:
        r = requests.get(VT + "/analyses/" + analysis_id, headers=headers(), timeout=TIMEOUT)
        return vt_response(r)
    except requests.RequestException as e:
        return jsonify(error="Could not retrieve analysis: " + str(e)), 502
    except RuntimeError as e:
        return jsonify(error=str(e)), 500

@app.get("/api/hash/<sha256>")
@require_login
@limiter.limit("30 per minute")
def hash_lookup(sha256):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return jsonify(error="Invalid SHA-256 hash."), 400
    try:
        r = requests.get(VT + "/files/" + sha256.lower(), headers=headers(), timeout=TIMEOUT)
        return vt_response(r)
    except requests.RequestException as e:
        return jsonify(error="Could not retrieve hash report: " + str(e)), 502
    except RuntimeError as e:
        return jsonify(error=str(e)), 500

def vt_response(r, submission=False):
    try:
        data = r.json()
    except ValueError:
        return jsonify(error="VirusTotal returned a non-JSON response."), 502
    if not r.ok:
        err = (data.get("error") or {}).get("message") or "VirusTotal API request failed."
        return jsonify(error=f"VirusTotal API ({r.status_code}): {err}"), r.status_code
    if submission:
        item = data.get("data") or {}
        return jsonify(analysis_id=item.get("id"), data=item)
    return jsonify(data)

@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Upload exceeds the configured size limit."), 413

if __name__ == "__main__":
    # Local test only. Deploy with gunicorn behind HTTPS in production.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
