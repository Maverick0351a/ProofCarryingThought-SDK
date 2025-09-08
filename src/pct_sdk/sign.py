from __future__ import annotations

from typing import Tuple

try:
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey, VerifyKey
except Exception:
    SigningKey = VerifyKey = HexEncoder = None  # soft opt


def gen_keypair() -> Tuple[str, str]:
    if not SigningKey:
        raise RuntimeError("PyNaCl not installed")
    sk = SigningKey.generate()
    vk = sk.verify_key
    return (sk.encode(encoder=HexEncoder).decode(), vk.encode(encoder=HexEncoder).decode())


def sign(hex_sk: str, msg: bytes) -> str:
    if not SigningKey:
        raise RuntimeError("PyNaCl not installed")
    sk = SigningKey(hex_sk, encoder=HexEncoder)
    return sk.sign(msg).signature.hex()


def verify(hex_vk: str, msg: bytes, sig_hex: str) -> bool:
    if not VerifyKey:
        return False
    vk = VerifyKey(hex_vk, encoder=HexEncoder)
    try:
        vk.verify(msg, bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


def derive_verify_key(hex_sk: str) -> str:
    """Derive hex verify key from a hex signing key."""
    if not SigningKey:
        raise RuntimeError("PyNaCl not installed")
    sk = SigningKey(hex_sk, encoder=HexEncoder)
    return sk.verify_key.encode(encoder=HexEncoder).decode()
