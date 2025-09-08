from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List


def link(parent_root: str, child_proof: Dict[str, Any]) -> Dict[str, Any]:
    blk = {"parent": parent_root, "child": child_proof.get("root")}
    blk["hash"] = hashlib.sha256(json.dumps(blk, sort_keys=True).encode()).hexdigest()
    return blk


def verify_chain(blocks: List[Dict[str, Any]]) -> bool:
    prev = None
    for b in blocks:
        if prev and b.get("parent") != prev.get("child"):
            return False
        payload = {k: b[k] for k in ("parent", "child")}
        h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if b.get("hash") != h:
            return False
        prev = b
    return True


def sign_link(blk: Dict[str, Any], hex_sk: str) -> Dict[str, Any]:
    payload = {k: blk[k] for k in ("parent", "child")}
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()
    DOMAIN = b"PCT:link:ed25519\x00"
    msg = DOMAIN + h
    try:
        from .sign import derive_verify_key
        from .sign import sign as _sign
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Signing support not available") from e
    sig = _sign(hex_sk, msg)
    vk = derive_verify_key(hex_sk)
    import hashlib as _hl
    kid = _hl.sha256(vk.encode()).hexdigest()[:16]
    out = dict(blk)
    out.setdefault("sigs", []).append(
        {"alg": "ed25519-pynacl-hex", "sig": sig, "vk": vk, "kid": kid}
    )
    return out


def verify_chain_with_sigs(blocks: List[Dict[str, Any]]) -> bool:
    if not verify_chain(blocks):
        return False
    try:
        from .sign import verify as _verify
    except Exception:
        return False
    DOMAIN = b"PCT:link:ed25519\x00"
    for b in blocks:
        payload = {k: b[k] for k in ("parent", "child")}
        h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).digest()
        msg = DOMAIN + h
        sigs = b.get("sigs") or []
        if not sigs:
            return False
        ok_any = any(
            _verify(s.get("vk"), msg, s.get("sig")) for s in sigs if s.get("vk") and s.get("sig")
        )
        if not ok_any:
            return False
    return True
