from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

ROOT = os.path.join(os.getcwd(), "pct_cas")
os.makedirs(ROOT, exist_ok=True)


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def put(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = _h(data)
    path = os.path.join(ROOT, h[:2], h[2:4])
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, h), "wb") as f:
        f.write(data)
    return h


def get(h: str) -> Optional[Any]:
    path = os.path.join(ROOT, h[:2], h[2:4], h)
    if not os.path.exists(path):
        return None
    return json.load(open(path, "r", encoding="utf-8"))
