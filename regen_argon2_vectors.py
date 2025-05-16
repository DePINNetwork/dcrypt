#!/usr/bin/env python3
"""
regen_argon2_vectors.py – dump Argon2 RFC 9106 reference digests (A.1‑A.7)
==========================================================================

Run:
    python regen_argon2_vectors.py

The script prints
  • H₀ for RFC A.1
  • 32‑byte tags for A.1 (Argon2d), A.3 (Argon2i), A.5 (Argon2id)
  • A.7 (Argon2id with *secret* & *associated data*) **if the installed
    Argon2 backend supports it**.

### Requirements
* **argon2‑cffi ≥ 23.1** (pip install argon2‑cffi)
* Optional: **phc‑winner‑argon2 CLI** in $PATH – used only when the
  Python binding lacks the “secret/ad” feature needed for A.7.

Set `DETAIL = True` inside the script for extra values (B[0][0] first
32 bytes, etc.).
"""

import inspect
import struct
import subprocess
import sys
from binascii import hexlify
from hashlib import blake2b

try:
    from argon2.low_level import hash_secret_raw, Type
except ImportError:  # pragma: no cover – argon2‑cffi not installed
    sys.exit("argon2‑cffi is required — pip install argon2‑cffi")

PWD = b"password"
SALT_8 = b"somesalt"
SALT_16 = SALT_8 + b"\0" * 8  # RFC A.7 uses 16‑byte salt
SECRET = b"secret key"
AD = b"associated data"

COMMON = dict(time_cost=2, memory_cost=32, parallelism=4,
              hash_len=32, version=19)  # 0x13

DETAIL = False

def hx(b: bytes) -> str:
    return hexlify(b).decode()

# ----------------------------------------------------------------------
# Helper: Argon2 digest via argon2‑cffi, detecting secret/ad capability.
# ----------------------------------------------------------------------

SIG = inspect.signature(hash_secret_raw)
PARAMS = list(SIG.parameters)
FIRST_POS_NAME = PARAMS[0]  # usually "password" or "secret"
KW_SUPPORTS_SECRET = "secret" in SIG.parameters and SIG.parameters["secret"].kind == inspect.Parameter.KEYWORD_ONLY
KW_SUPPORTS_AD = "ad" in SIG.parameters and SIG.parameters["ad"].kind == inspect.Parameter.KEYWORD_ONLY


def hash_via_cffi(pwd: bytes, salt: bytes, *, t: Type, secret=None, ad=None):
    """Return digest using argon2‑cffi if it supports the requested inputs.

    If associated data or a separate *secret* is requested but the binding
    lacks those keyword‑only parameters, we signal NotImplementedError so
    the caller can fall back to the reference CLI.  We no longer try to
    shoe‑horn values into the positional signature because that cannot
    convey *ad*.
    """
    # Simple case – no extra inputs
    if secret is None and ad is None:
        return hash_secret_raw(pwd, salt, type=t, **COMMON)

    # Binding exposes both kwargs → use them directly.
    if KW_SUPPORTS_SECRET and KW_SUPPORTS_AD:
        return hash_secret_raw(pwd, salt, type=t, secret=secret, ad=ad, **COMMON)

    # Otherwise not supported.
    raise NotImplementedError  # let caller try CLI

# ----------------------------------------------------------------------
# Helper: Argon2 digest via phc‑winner‑argon2 CLI (if available)
# ----------------------------------------------------------------------
CLI_CMD = [
    "argon2",  # executable
    "-id", "-t", str(COMMON["time_cost"]), "-m", str(COMMON["memory_cost"]),
    "-p", str(COMMON["parallelism"]), "-l", str(COMMON["hash_len"]),
    "-k", SECRET.decode(), "-a", AD.decode(), "-e"  # -e => raw hex tag
]


def hash_via_cli():
    try:
        proc = subprocess.run(CLI_CMD + [SALT_16.decode(), PWD.decode()],
                              check=True, capture_output=True, text=True)
        tag_hex = proc.stdout.strip()
        return bytes.fromhex(tag_hex)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

# ----------------------------------------------------------------------
# Compute H₀ (fixed for RFC A.1)
# ----------------------------------------------------------------------

def compute_h0():
    buf = struct.pack("<IIIIII", 4, 32, 32, 2, 19, 0)
    buf += struct.pack("<I", len(PWD)) + PWD
    buf += struct.pack("<I", len(SALT_8)) + SALT_8
    buf += struct.pack("<I", 0) * 2  # |secret| & |ad|
    return blake2b(buf, digest_size=64).digest()

# ----------------------------------------------------------------------
# Main pretty‑printer
# ----------------------------------------------------------------------

def main():
    print("=== Argon2 RFC 9106 vectors ===")
    h0 = compute_h0()
    print("RFC A.1 H0       ", hx(h0))
    print()

    # A.1 – A.5 (no secret, no ad) — always supported.
    for label, t in (
        ("Argon2d A.1", Type.D),
        ("Argon2i A.3", Type.I),
        ("Argon2id A.5", Type.ID),
    ):
        digest = hash_via_cffi(PWD, SALT_8, t=t)
        print(f"{label:<14} {hx(digest)}")

    # A.7 – try binding first, then CLI.
    try:
        digest = hash_via_cffi(PWD, SALT_16, t=Type.ID, secret=SECRET, ad=AD)
        print(f"Argon2id A.7    {hx(digest)}")
    except NotImplementedError:
        digest = hash_via_cli()
        if digest is not None:
            print(f"Argon2id A.7    {hx(digest)}   (via CLI)")
        else:
            print("Argon2id A.7    **secret/ad unsupported in both binding and CLI**")

    if DETAIL:
        seed = h0 + struct.pack("<II", 0, 0)
        b0 = hash_secret_raw(seed, b"", type=Type.D, hash_len=1024, **COMMON)
        print("B[0][0] first 32", hx(b0[:32]))


if __name__ == "__main__":  # pragma: no cover
    main()
