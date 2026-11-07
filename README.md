# Guardian Scan — Advanced web deployment

A responsive single-page dashboard backed by Flask and VirusTotal API v3.

## Real features
- URL submission: `POST /api/scan-url` → VirusTotal `POST /urls`
- File upload: `POST /api/scan-file` → VirusTotal `POST /files`
- Analysis polling: `GET /api/analysis/{id}` → VirusTotal `GET /analyses/{id}`
- SHA-256 lookup: `GET /api/hash/{sha256}` → VirusTotal `GET /files/{sha256}`
- Browser-side SHA-256 via Web Crypto; scan history in localStorage; JSON report export.
- Password-protected session, CSRF token checks, request rate limits, API key kept server-side.

## Deploy to Render
1. Put this folder in a Git repository you control.
2. Create a new Web Service on Render and connect the repository.
3. Render can use `render.yaml`, or set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn server:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
4. Add environment variables in the Render dashboard:
   - `VT_API_KEY`: your VirusTotal API key
   - `APP_PASSWORD`: a strong, unique password to access the scanner
   - `SESSION_SECRET`: long random secret (Render blueprint can generate it)
   - `COOKIE_SECURE`: `true`
5. Deploy and open the service URL. Sign in with `APP_PASSWORD`.

## Local test
For localhost only, set `COOKIE_SECURE=false` then:
- `pip install -r requirements.txt`
- macOS/Linux: `export VT_API_KEY='...' APP_PASSWORD='...' SESSION_SECRET='a-long-random-secret' COOKIE_SECURE=false`
- Windows PowerShell:
  `$env:VT_API_KEY='...'`
  `$env:APP_PASSWORD='...'`
  `$env:SESSION_SECRET='use-a-long-random-random-secret'`
  `$env:COOKIE_SECURE='false'`
- `python server.py`
- Open `http://127.0.0.1:5000`

## Important operational limits
- VirusTotal API key and plan govern quotas, permissions, upload sizes, and rate limits. This template caps uploads at 32 MB; larger files need the VirusTotal upload URL workflow and an account/plan that supports it.
- File uploads are held in memory and forwarded to VirusTotal; they are not saved to disk or executed by this backend.
- VirusTotal submissions may be shared with its security partners/community. Never submit confidential, personal, or proprietary files or URLs.
- This is a security triage interface, not a replacement for endpoint antivirus. Engine results may be false positives or miss threats.
- Before public production use, configure persistent rate-limit storage (Redis via `RATELIMIT_STORAGE_URI`), monitor abuse, set a strong app password and session secret, use HTTPS, and restrict access to trusted users. The simple password gate is a basic access barrier, not a full multi-user identity system.
- Only scan files and sites you own or are authorized to assess.
