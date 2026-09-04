#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standalone Ed25519 verifier for the firmware's /sign endpoint.

The device signs the UTF-8 message

    <challenge>:<context>:<timestamp>:<device_001>

with the Ed25519 key embedded in the firmware (TweetNaCl crypto_sign) and
returns {"signature": "<base64 of the raw 64-byte signature>", ...}.

Usage:
    python sign_verify.py '<message>' '<signature_base64>'

Standard library only; implements the RFC 8032 verification math directly
(pure Python, small integers only - fine for one-off verification).

The public key below is the one compiled into the firmware (see
web_server.c, /sign section); override with --pk if a different device key
is in use.
"""

import argparse
import base64
import hashlib

# --- RFC 8032 Ed25519 field/group constants ---
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)

BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960

DEFAULT_PK_B64 = "f/LmPWawjJ9QjK6GniT26UdCcgIEd2tcoy3lbvCThNQ="


def _inv(x):
    return pow(x, P - 2, P)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + D * x1 * x2 * y1 * y2) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - D * x1 * x2 * y1 * y2) % P
    return (x3, y3)


def _mul(n, p):
    r = None
    while n:
        if n & 1:
            r = _add(r, p)
        p = _add(p, p)
        n >>= 1
    return r


def _decompress(encoded):
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = (encoded[31] >> 7) & 1
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        raise ValueError("public key is not a valid curve point")
    if (x & 1) != sign:
        x = P - x
    return (x, y)


def verify(pk_bytes, message, sig_bytes):
    """Raises ValueError when the Ed25519 signature does not verify."""
    if len(pk_bytes) != 32:
        raise ValueError("public key must be 32 bytes")
    if len(sig_bytes) != 64:
        raise ValueError("signature must be 64 bytes")
    a = _decompress(pk_bytes)
    r = _decompress(sig_bytes[:32])
    s = int.from_bytes(sig_bytes[32:], "little")
    if s >= L:
        raise ValueError("signature scalar out of range")
    h = int.from_bytes(hashlib.sha512(sig_bytes[:32] + pk_bytes + message).digest(), "little") % L
    if _mul(s, (BX, BY)) != _add(r, _mul(h, a)):
        raise ValueError("signature invalid")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("message", help="the exact signed message, e.g. "
                                     "challenge:context:timestamp:device_001")
    ap.add_argument("signature", help="base64 signature returned by /sign")
    ap.add_argument("--pk", default=DEFAULT_PK_B64,
                    help="base64 Ed25519 public key (default: the firmware's embedded key)")
    args = ap.parse_args()

    try:
        pk = base64.b64decode(args.pk, validate=True)
        sig = base64.b64decode(args.signature, validate=True)
    except Exception as e:
        ap.error(f"invalid base64: {e}")

    try:
        verify(pk, args.message.encode("utf-8"), sig)
    except ValueError as e:
        print(f"FAIL: {e}")
        return 1
    print("OK: signature is valid for this message and key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
