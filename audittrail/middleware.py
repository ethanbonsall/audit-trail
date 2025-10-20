import json
import datetime
from starlette.middleware.base import BaseHTTPMiddleware
from .ledger import add_entry

class AuditTrailMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, storage_path="audit_log.db"):
        super().__init__(app)
        self.storage_path = storage_path

    async def dispatch(self, request, call_next):
        start_time = datetime.datetime.utcnow()
        response = await call_next(request)

        user = request.headers.get("x-user", "anonymous")
        log_entry = {
            "method": request.method,
            "path": request.url.path,
            "user": user,
            "status": response.status_code,
        }

        add_entry(self.storage_path, log_entry)
        return response