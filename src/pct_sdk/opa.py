from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict


class OPAUnavailable(Exception):
    pass


def opa_eval(
    policy_path: str, input_data: Dict[str, Any], entrypoint: str = "data.main.allow"
) -> bool:
    """Evaluate an OPA/Rego policy using the opa CLI. Returns True if allow is truthy.

    Requires `opa` CLI on PATH.
    """
    if not shutil.which("opa"):
        raise OPAUnavailable("opa CLI not found")
    with tempfile.TemporaryDirectory() as td:
        in_path = os.path.join(td, "input.json")
        with open(in_path, "w", encoding="utf-8") as f:
            json.dump(input_data, f)
        # opa eval -I -d policy.rego -i input.json 'data.main.allow'
        cmd = [
            "opa",
            "eval",
            "-I",
            "-d",
            policy_path,
            "-i",
            in_path,
            entrypoint,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return False
        out = res.stdout.strip()
        # crude parse: look for "true" literal
        return "true" in out.splitlines()[-1].lower()


def require_opa(
    proof: Dict[str, Any],
    evidence: Dict[str, Any],
    policy_path: str,
    entrypoint: str = "data.main.allow",
) -> None:
    """Raise PermissionError if OPA policy denies access.

    Input to OPA includes: {"proof": proof, "evidence": evidence}
    """
    ok = opa_eval(policy_path, {"proof": proof, "evidence": evidence}, entrypoint=entrypoint)
    if not ok:
        raise PermissionError("Denied by OPA policy")
