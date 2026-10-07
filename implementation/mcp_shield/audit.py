"""
Tamper-evident audit trail.

Every guard decision is appended as a JSON record whose `mac` is
HMAC-SHA256(key, previous_mac || canonical_json(record)). Changing, deleting,
re-ordering or inserting any record breaks every MAC after it, and
`verify()` pinpoints the first broken line. Without the key an attacker
cannot forge a consistent chain.

Key: MCP_SHIELD_AUDIT_KEY (hex) if set, otherwise a random per-run key that
is kept in memory (good for one run / one demo; set the env var to verify
logs later).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _key() -> bytes:
    env = os.getenv("MCP_SHIELD_AUDIT_KEY", "").strip()
    if env:
        try:
            return bytes.fromhex(env)
        except ValueError:
            return env.encode("utf-8")
    return secrets.token_bytes(32)


def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


@dataclass
class AuditLog:
    path: Path | None = None
    key: bytes = field(default_factory=_key, repr=False)
    records: list[dict] = field(default_factory=list)
    _last: str = GENESIS
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append(self, event: str, **data: Any) -> dict:
        with self._lock:
            body = {"seq": len(self.records), "ts": round(time.time(), 3), "event": event, **data}
            mac = hmac.new(self.key, self._last.encode() + _canonical(body), hashlib.sha256).hexdigest()
            record = {**body, "prev": self._last, "mac": mac}
            self.records.append(record)
            self._last = mac
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, default=str) + "\n")
            return record

    @property
    def head(self) -> str:
        return self._last


def verify(records: list[dict], key: bytes) -> tuple[bool, int | None]:
    """(ok, index_of_first_bad_record)."""
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: v for k, v in rec.items() if k not in {"prev", "mac"}}
        expected = hmac.new(key, prev.encode() + _canonical(body), hashlib.sha256).hexdigest()
        if rec.get("prev") != prev or not hmac.compare_digest(rec.get("mac", ""), expected):
            return False, i
        prev = rec["mac"]
    return True, None


def verify_file(path: str | Path, key: bytes) -> tuple[bool, int | None]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return verify([json.loads(line) for line in lines if line.strip()], key)
