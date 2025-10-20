from dataclasses import dataclass
from typing import Protocol, Dict
from cryptography.fernet import Fernet

class KeySource(Protocol):
    def get_key(self, key_id: str) -> bytes: ...

@dataclass
class EnvKeySource:
    env: Dict[str, str]
    def get_key(self, key_id: str) -> bytes:
        k = self.env.get(f"AUDITTRAIL_KEY_{key_id}")
        if not k:
            raise RuntimeError(f"Missing key for {key_id}")
        return k.encode()

# default fallbacks (dev)
def default_key_source():
    # preserves your ~/.audittrail.key for dev
    # but runs through the same interface
    from pathlib import Path, PurePosixPath
    p = Path(PurePosixPath("~/.audittrail.key").expanduser())
    if not p.exists():
        p.write_bytes(Fernet.generate_key())
    return lambda _key_id="local": p.read_bytes()
