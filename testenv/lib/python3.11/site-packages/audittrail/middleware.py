"""
AuditTrail middleware with optional compliance features.
"""

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

# Import compliance modules (optional)
try:
    from .signatures import sign_entry, initialize_signing_keys
    from .timestamp import create_local_timestamp
    from .worm import protect_entry
    from .anomaly import record_anomaly
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False


class AuditTrailMiddleware(BaseHTTPMiddleware):
    """
    AuditTrail middleware for FastAPI with optional compliance features.
    
    Args:
        app: FastAPI application
        storage_path: Path to SQLite database
        enable_compliance: Enable digital signatures, timestamps, and WORM protection (default: True)
    
    Example:
        app = FastAPI()
        app.add_middleware(AuditTrailMiddleware, storage_path="audit_log.db", enable_compliance=True)
    """
    
    def __init__(self, app, storage_path="audit_log.db", enable_compliance=True):
        super().__init__(app)
        self.storage_path = storage_path
        self.enable_compliance = enable_compliance
        self._init_db()
        
        # Initialize signing keys if compliance is enabled
        if self.enable_compliance and COMPLIANCE_AVAILABLE:
            try:
                initialize_signing_keys()
            except Exception:
                pass

    def _init_db(self):
        conn = sqlite3.connect(self.storage_path)
        
        # Schema with optional compliance columns
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
        prev_hash TEXT,
        key_id TEXT DEFAULT 'local',
        signature TEXT,
        timestamp_token TEXT,
        worm_protected INTEGER DEFAULT 0
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
        key_id = os.getenv("AUDITTRAIL_KEY_ID", "local")

        entry_str = f"{ts}|{request.method}|{request.url.path}|{request.client.host}|{response.status_code}|{enc_body}|{enc_response}|{prev_hash}|{key_id}"
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()

        # --- Compliance features (optional) ---
        signature = None
        timestamp_token = None
        worm_protected = 0

        if self.enable_compliance and COMPLIANCE_AVAILABLE:
            # Digital signature
            try:
                signature_data = {
                    "ts": ts,
                    "method": request.method,
                    "path": request.url.path,
                    "user": request.client.host,
                    "status": response.status_code,
                    "hash": entry_hash,
                    "prev_hash": prev_hash
                }
                signature = sign_entry(signature_data)
            except Exception as e:
                record_anomaly("signature_error", "high",
                             f"Failed to sign entry: {str(e)}", self.storage_path)

            # Timestamp
            try:
                ts_info = create_local_timestamp(entry_hash, {"path": request.url.path})
                timestamp_token = ts_info["token"]
            except Exception:
                pass

            worm_protected = 1

        # --- Insert entry ---
        cur.execute(
            "INSERT INTO ledger (ts, method, path, user, status, body, response, hash, prev_hash, key_id, signature, timestamp_token, worm_protected) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, request.method, request.url.path, request.client.host,
            response.status_code, enc_body, enc_response, entry_hash, prev_hash, key_id,
            signature, timestamp_token, worm_protected),
        )

        row_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Apply WORM protection
        if worm_protected and COMPLIANCE_AVAILABLE:
            try:
                protect_entry(self.storage_path, entry_hash, row_id, {"ts": ts})
            except Exception:
                pass

        return response
