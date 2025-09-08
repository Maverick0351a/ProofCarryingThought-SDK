from __future__ import annotations

from typing import Any, Dict


def require_pct(proof: Dict[str, Any], checks: Dict[str, Any], evidence: Dict[str, Any]) -> None:
    if not proof or proof.get("version") != "pct_v1.0":
        raise PermissionError("Missing/invalid PCT")
    # Recompute root from provided evidence (caller reconstructs or loads from CAS)
    from pct_sdk.core import merkle_root
    if proof.get("root") != merkle_root(evidence):
        raise PermissionError("PCT mismatch: root != recomputed")
    sample = proof.get("sample", {})
    if checks.get("units_ok") and not bool(sample.get("units_ok")):
        raise PermissionError("Denied: units_ok is False or missing")
    ocap_req = checks.get("ocap")
    if ocap_req and ocap_req not in (sample.get("ocap_list") or []):
        raise PermissionError(f"Denied: missing ocap {ocap_req}")
    # Arbitrary key equality checks (e.g., model version)
    for k, v in checks.get("equals", {}).items():
        if sample.get(k) != v:
            raise PermissionError(f"Denied: {k} != {v}")
