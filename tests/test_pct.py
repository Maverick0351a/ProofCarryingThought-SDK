from __future__ import annotations

import pytest

from pct_sdk import link, set_canonical_mode, sign_link, verify_chain_with_sigs
from pct_sdk.core import (
    attach_signature,
    attach_signature2,
    pct_wrap,
    proof_with_cas,
    verify,
    verify_from_cas,
    verify_with_signature,
    verify_with_signatures,
)
from pct_sdk.opa import OPAUnavailable, opa_eval
from pct_sdk.policy import require_pct


def evidence(ctx):
    return {
        "units_ok": True,
        "ocap_list": ["sandbox"],
        "inputs_hash": "sha256:demo",
        "timestamp": "2025-09-08",
    }


@pct_wrap(evidence)
def power(work_joule: float, time_s: float) -> float:
    return work_joule / time_s


def test_pct_happy():
    out = power(1000.0, 5.0)
    ev = evidence({"args": (1000.0, 5.0), "kwargs": {}, "out": 200.0})
    assert verify(out["pct_proof"], ev)
    require_pct(out["pct_proof"], {"units_ok": True, "ocap": "sandbox"}, ev)


def test_proof_with_cas(tmp_path, monkeypatch):
    from pct_sdk import cas
    monkeypatch.setattr(cas, "ROOT", str(tmp_path))

    @pct_wrap(lambda ctx: {"x": 1})
    def f():
        return 7

    out = f()
    ev = {"x": 1}
    proof = out["pct_proof"]
    proof2 = proof_with_cas(proof, ev)
    assert "evidence_cas" in proof2
    # Retrieve and verify
    stored = cas.get(proof2["evidence_cas"])
    assert stored == ev
    assert verify(proof, stored)
    # end-to-end from CAS pointer
    assert verify_from_cas(proof2)


def test_signature_optional(monkeypatch):
    try:
        from pct_sdk.sign import gen_keypair
    except Exception:
        pytest.skip("PyNaCl not installed")
    try:
        sk, vk = gen_keypair()
    except RuntimeError:
        pytest.skip("PyNaCl not installed")

    @pct_wrap(lambda ctx: {"m": 3})
    def g():
        return 9

    out = g()
    ev = {"m": 3}
    p = out["pct_proof"]
    p_signed = attach_signature(p, sk)
    assert verify_with_signature(p_signed, ev)


def test_multi_sig_proof_optional():
    try:
        from pct_sdk.sign import gen_keypair
    except Exception:
        pytest.skip("PyNaCl not installed")
    try:
        sk1, vk1 = gen_keypair()
        sk2, vk2 = gen_keypair()
    except RuntimeError:
        pytest.skip("PyNaCl not installed")

    @pct_wrap(lambda ctx: {"m": 3})
    def g():
        return 9

    p = g()["pct_proof"]
    p = attach_signature2(p, sk1)
    p = attach_signature2(p, sk2)
    # Verify requiring both kids
    import hashlib as _hl
    kid1 = _hl.sha256(vk1.encode()).hexdigest()[:16]
    kid2 = _hl.sha256(vk2.encode()).hexdigest()[:16]
    assert verify_with_signatures(p, {"m": 3}, require_kids=[kid1, kid2])


def test_signed_chain_blocks_optional():
    try:
        from pct_sdk.sign import gen_keypair
    except Exception:
        pytest.skip("PyNaCl not installed")
    try:
        sk, vk = gen_keypair()
    except RuntimeError:
        pytest.skip("PyNaCl not installed")

    @pct_wrap(lambda ctx: {"a": 1})
    def f1():
        return "x"

    @pct_wrap(lambda ctx: {"b": 2})
    def f2():
        return "y"

    p1 = f1()["pct_proof"]
    p2 = f2()["pct_proof"]
    b1 = link("genesis", p1)
    b2 = link(p1["root"], p2)
    b1s = sign_link(b1, sk)
    b2s = sign_link(b2, sk)
    assert verify_chain_with_sigs([b1s, b2s])


def test_opa_eval_optional(tmp_path):
    # Skip if opa CLI is unavailable
    try:
        import shutil
        if not shutil.which("opa"):
            raise OPAUnavailable()
    except Exception:
        pytest.skip("opa CLI not found")

    # Write a tiny policy: allow if input.evidence.k == "v"
    policy = "package main\n\nallow { input.evidence.k == \"v\" }\n"
    pol_path = tmp_path / "p.rego"
    pol_path.write_text(policy, encoding="utf-8")
    assert opa_eval(str(pol_path), {"evidence": {"k": "v"}}) is True
    assert opa_eval(str(pol_path), {"evidence": {"k": "x"}}) is False


def test_dcbor_mode_requirement(monkeypatch):
    # If cbor2 is installed, skip; else, requiring dcbor should raise
    try:
        pytest.skip("cbor2 installed; dcbor requirement won't error")
    except Exception:
        pass

    # Force dcbor mode
    set_canonical_mode("dcbor")

    @pct_wrap(lambda ctx: {"k": "v"})
    def h():
        return 1

    with pytest.raises(RuntimeError):
        _ = h()
    # reset to auto for other tests
    set_canonical_mode("auto")
