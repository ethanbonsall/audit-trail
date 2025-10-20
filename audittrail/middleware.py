from cryptography.fernet import Fernet
import os, hashlib, json, sqlite3
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime, timezone

# Load or create encryption key
KEY_PATH = os.path.expanduser("~/.audittrail.key")
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_PATH, "rb") as f:
    CIPHER = Fernet(f.read())

class AuditTrailMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, storage_path="audit_log.db"):
        super().__init__(app)
        self.storage_path = storage_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.storage_path)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
        ts TEXT,
        method TEXT,
        path TEXT,
        user TEXT,
        status INT,
        body TEXT,
        response TEXT,
        hash TEXT,
        prev_hash TEXT
        )
        """)
        conn.commit()
        conn.close()

    async def dispatch(self, request, call_next):
        # --- capture body ---
        raw_body = await request.body()
        try:
            body_json = json.loads(raw_body.decode()) if raw_body else {}
        except Exception:
            body_json = {"raw": str(raw_body)}
        body_str = json.dumps(body_json, sort_keys=True)

        # --- call the endpoint ---
        response = await call_next(request)
        response_body = b"".join([chunk async for chunk in response.body_iterator]) or b""
        async def new_body_iterator():
            yield response_body

        response.body_iterator = new_body_iterator()


        # --- encrypt request/response ---
        enc_body = CIPHER.encrypt(body_str.encode()).decode()
        enc_response = CIPHER.encrypt(response_body).decode()

        # --- hash chain ---
        conn = sqlite3.connect(self.storage_path)
        cur = conn.cursor()
        cur.execute("SELECT hash FROM ledger ORDER BY ts DESC LIMIT 1")
        prev = cur.fetchone()
        prev_hash = prev[0] if prev else ""

        ts = datetime.now(timezone.utc).isoformat()

        entry_str = f"{ts}|{request.method}|{request.url.path}|{request.client.host}|{response.status_code}|{enc_body}|{enc_response}|{prev_hash}"
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()

        cur.execute(
            "INSERT INTO ledger (ts, method, path, user, status, body, response, hash, prev_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, request.method, request.url.path, request.client.host,
            response.status_code, enc_body, enc_response, entry_hash, prev_hash),
        )

        conn.commit()
        conn.close()

        return response
