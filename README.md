# ProofCarryingThought-SDK

Minimal Proof-Carrying Thought (PCT) SDK: canonical bytes, Merkle, local CAS, optional Ed25519 signing, policy gates, and chain-of-custody.

## Install

- Base:
	- pip install -e .
- Optional extras:
	- pip install -e .[crypto]  # PyNaCl for Ed25519
	- pip install -e .[dcbor]   # cbor2 for canonical CBOR

## Canonicalization

- Modes: auto (default, prefers dCBOR if installed), json (strict JSON), dcbor (requires cbor2)
- Programmatic: from pct_sdk import set_canonical_mode; set_canonical_mode("auto"|"json"|"dcbor")
- Env: set PCT_CANON_MODE=auto|json|dcbor

## Quick start

from pct_sdk import pct_wrap, verify

evidence = {"units_ok": True, "ocap_list": ["sandbox"]}
res = pct_wrap(lambda ev: {"result": "ok"}, include=["units_ok", "ocap_list"])  # noqa: E501
assert verify(res["pct_proof"], evidence)

With crypto:

from pct_sdk.sign import gen_keypair, sign, verify as sig_verify
sk_hex, vk_hex = gen_keypair()
sig_hex = sign(sk_hex, b"msg")
assert sig_verify(vk_hex, b"msg", sig_hex)

## CAS usage

from pct_sdk import cas
hid = cas.put({"hello": "world"})
obj = cas.get(hid)

## Tests

pytest
