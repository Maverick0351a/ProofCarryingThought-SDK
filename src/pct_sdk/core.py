from __future__ import annotations

import functools
import hashlib
import json
import os
import time
from typing import Any, Callable, Dict

CANON_MODE = os.environ.get("PCT_CANON_MODE", "auto").lower()  # auto|json|dcbor


def set_canonical_mode(mode: str) -> None:
    global CANON_MODE
    mode = mode.lower()
    if mode not in ("auto", "json", "dcbor"):
        raise ValueError("mode must be one of: auto, json, dcbor")
    CANON_MODE = mode


def get_canonical_mode() -> str:
    return CANON_MODE


def _canonical_bytes(obj: Any) -> bytes:
    # dCBOR if required or preferred and available; else strict JSON
    if CANON_MODE in ("dcbor", "auto"):
        try:
            import cbor2  # type: ignore
            if CANON_MODE == "dcbor":
                return cbor2.dumps(obj, canonical=True)
            # auto: prefer cbor2 if import succeeded
            return cbor2.dumps(obj, canonical=True)
        except Exception:
            if CANON_MODE == "dcbor":
                raise RuntimeError("dCBOR required but cbor2 is not installed")
            # else fall through to JSON
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def merkle_root(evidence: Dict[str, Any]) -> str:
    leaves = []
    for k in sorted(evidence):
        leaf = hashlib.sha256(_canonical_bytes({k: evidence[k]})).digest()
        leaves.append(leaf)
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    layer = leaves
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else a
            nxt.append(hashlib.sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()


def pct_wrap(include: Callable[[Dict[str, Any]], Dict[str, Any]]):
    """
    Decorator: include(ctx) -> evidence dict
    ctx contains {"args","kwargs","out"}; YOU decide which evidence to emit.
    """
    def deco(fn: Callable):
        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            t0 = time.perf_counter()
            out = fn(*args, **kwargs)
            ctx = {"args": args, "kwargs": kwargs, "out": out}
            ev = include(ctx) or {}
            root = merkle_root(ev)
            proof = {
                "version": "pct_v1.0",
                "root": root,
                "sample": {k: ev[k] for k in sorted(ev)[:4]}  # keep small for logs/UI
            }
            return {"result": out, "pct_proof": proof, "lat_ms": (time.perf_counter()-t0)*1000.0}
        return _wrapped
    return deco


def verify(proof: Dict[str, Any], evidence: Dict[str, Any]) -> bool:
    try:
        return proof and proof.get("root") == merkle_root(evidence)
    except Exception:
        return False


def attach_signature(proof: Dict[str, Any], hex_sk: str) -> Dict[str, Any]:
    """Attach an Ed25519 signature (PyNaCl) over the Merkle root to the proof.

    Adds fields: alg, sig, vk.
    Returns a new dict; does not mutate the input.
    """
    p = dict(proof)
    root = p.get("root")
    if not root:
        raise ValueError("proof missing root")
    try:
        from .sign import derive_verify_key
        from .sign import sign as _sign
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Signing support not available") from e
    # Domain-separated message: scheme + raw root bytes
    DOMAIN = b"PCT:root:ed25519\x00"
    msg = DOMAIN + bytes.fromhex(root)
    sig_hex = _sign(hex_sk, msg)
    vk_hex = derive_verify_key(hex_sk)
    # kid: short identifier derived from verify key
    import hashlib as _hl
    kid = _hl.sha256(vk_hex.encode()).hexdigest()[:16]
    p.update({
        "alg": "ed25519-pynacl-hex",
        "sig": sig_hex,
        "vk": vk_hex,
        "kid": kid,
    })
    return p


def verify_with_signature(proof: Dict[str, Any], evidence: Dict[str, Any]) -> bool:
    """Verify Merkle root against evidence; if signature present, verify it too.

    Accepts proofs with optional fields: sig, vk, alg. If sig is present, vk must be provided.
    """
    if not verify(proof, evidence):
        return False
    sig = proof.get("sig")
    if not sig:
        return True
    vk = proof.get("vk")
    if not vk:
        return False
    try:
        from .sign import verify as _verify
    except Exception:
        return False
    DOMAIN = b"PCT:root:ed25519\x00"
    msg = DOMAIN + bytes.fromhex(proof["root"])
    return _verify(vk, msg, sig)


def proof_with_cas(proof: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Store full evidence in CAS and add pointer to proof as 'evidence_cas'."""
    p = dict(proof)
    try:
        from . import cas
    except Exception as e:  # pragma: no cover
        raise RuntimeError("CAS module unavailable") from e
    addr = cas.put(evidence)
    p["evidence_cas"] = addr
    return p


def verify_from_cas(proof: Dict[str, Any]) -> bool:
    """Fetch evidence via CAS pointer in proof and verify (including signature if present)."""
    addr = proof.get("evidence_cas")
    if not addr:
        return False
    try:
        from . import cas
    except Exception:
        return False
    ev = cas.get(addr)
    if ev is None:
        return False
    return verify_with_signature(proof, ev)


def attach_signature2(proof: Dict[str, Any], hex_sk: str) -> Dict[str, Any]:
    """Attach signature as an entry in proof['sigs'] list (multi-sig friendly)."""
    p = dict(proof)
    signed = attach_signature(p, hex_sk)
    entry = {k: signed[k] for k in ("alg", "sig", "vk", "kid") if k in signed}
    sigs = list(p.get("sigs", []))
    sigs.append(entry)
    p["sigs"] = sigs
    return p


def verify_with_signatures(
    proof: Dict[str, Any], evidence: Dict[str, Any], require_kids: list[str] | None = None
) -> bool:
    if not verify(proof, evidence):
        return False
    # If a single signature schema is present, check it too
    if proof.get("sig") and proof.get("vk"):
        if not verify_with_signature(proof, evidence):
            return False
    sigs = proof.get("sigs") or []
    if not sigs:
        return require_kids is None or len(require_kids) == 0
    # Domain-separated root
    DOMAIN = b"PCT:root:ed25519\x00"
    msg = DOMAIN + bytes.fromhex(proof["root"]) if proof.get("root") else None
    try:
        from .sign import verify as _verify
    except Exception:
        return False
    ok_all = True
    seen_kids = set()
    for s in sigs:
        vk = s.get("vk")
        sig = s.get("sig")
        kid = s.get("kid")
        if not (vk and sig and msg):
            ok_all = False
            break
        if _verify(vk, msg, sig):
            if kid:
                seen_kids.add(kid)
        else:
            ok_all = False
            break
    if not ok_all:
        return False
    if require_kids:
        return all(k in seen_kids for k in require_kids)
    return True
