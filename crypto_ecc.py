"""
crypto_ecc.py
Pure-Python implementation of NIST P-256 (secp256r1) Elliptic Curve Cryptography,
SHA3-256, PBKDF2-HMAC-SHA3-256, HMAC-SHA3-256, and ElGamal-over-ECC
for the Lightweight Smart Office Two-Factor Authentication Protocol.

Zero third-party dependencies (uses Python Standard Library only).
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional, Tuple

# ==============================================================================
# NIST P-256 (secp256r1) Domain Parameters (FIPS 186-4 / SEC 2)
# Curve equation: y^2 = x^3 + a*x + b (mod p)
# ==============================================================================
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC  # -3 mod P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

Point = Optional[Tuple[int, int]]  # None represents the point at infinity O
G: Point = (GX, GY)

HASH_CHAIN_LEN = 256
PBKDF2_ITERATIONS = 100_000


# ==============================================================================
# Elliptic Curve Arithmetic (Jacobian Coordinates for Fast Scalar Multiplication)
# ==============================================================================
def is_on_curve(pt: Point) -> bool:
    """Verify that an affine point lies on NIST P-256."""
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def _jacobian_double(X1: int, Y1: int, Z1: int) -> Tuple[int, int, int]:
    """Point doubling in Jacobian coordinates (optimized for a = -3 mod p)."""
    if Y1 == 0 or Z1 == 0:
        return (0, 1, 0)
    S = (4 * X1 * Y1 * Y1) % P
    Z1_sq = (Z1 * Z1) % P
    M = (3 * (X1 - Z1_sq) * (X1 + Z1_sq)) % P  # Valid because a = -3
    X3 = (M * M - 2 * S) % P
    Y1_4 = pow(Y1, 4, P)
    Y3 = (M * (S - X3) - 8 * Y1_4) % P
    Z3 = (2 * Y1 * Z1) % P
    return (X3, Y3, Z3)


def _jacobian_add(
    p1: Tuple[int, int, int], p2: Tuple[int, int, int]
) -> Tuple[int, int, int]:
    """Point addition in Jacobian coordinates."""
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    if Z1 == 0:
        return p2
    if Z2 == 0:
        return p1

    Z1_sq = (Z1 * Z1) % P
    Z2_sq = (Z2 * Z2) % P
    U1 = (X1 * Z2_sq) % P
    U2 = (X2 * Z1_sq) % P
    S1 = (Y1 * Z2_sq * Z2) % P
    S2 = (Y2 * Z1_sq * Z1) % P

    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)  # Point at infinity
        return _jacobian_double(X1, Y1, Z1)

    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H_sq = (H * H) % P
    H_cu = (H * H_sq) % P
    U1_H_sq = (U1 * H_sq) % P

    X3 = (R * R - H_cu - 2 * U1_H_sq) % P
    Y3 = (R * (U1_H_sq - X3) - S1 * H_cu) % P
    Z3 = (H * Z1 * Z2) % P
    return (X3, Y3, Z3)


def _from_jacobian(pt: Tuple[int, int, int]) -> Point:
    """Convert Jacobian point (X, Y, Z) back to affine (x, y)."""
    X, Y, Z = pt
    if Z == 0:
        return None
    z_inv = pow(Z, P - 2, P)
    z_inv2 = (z_inv * z_inv) % P
    z_inv3 = (z_inv2 * z_inv) % P
    return ((X * z_inv2) % P, (Y * z_inv3) % P)


def point_add(p1: Point, p2: Point) -> Point:
    """Affine point addition P1 + P2."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = ((3 * x1 * x1 + A) * pow(2 * y1, P - 2, P)) % P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_neg(pt: Point) -> Point:
    """Point negation -P."""
    if pt is None:
        return None
    return (pt[0], (-pt[1]) % P)


def point_sub(p1: Point, p2: Point) -> Point:
    """Point subtraction P1 - P2."""
    return point_add(p1, point_neg(p2))


def scalar_mult(k: int, pt: Point) -> Point:
    """Compute k * pt using double-and-add in Jacobian coordinates."""
    k = k % N
    if k == 0 or pt is None:
        return None
    result = (0, 1, 0)
    addend = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(*addend)
        k >>= 1
    return _from_jacobian(result)


def generate_keypair() -> Tuple[int, Point]:
    """Generate a NIST P-256 private scalar d in [1, N-1] and public point P = d*G."""
    d = secrets.randbelow(N - 1) + 1
    pub = scalar_mult(d, G)
    return d, pub


def point_to_bytes(pt: Point) -> bytes:
    """Serialize affine point to uncompressed SEC1 format (65 bytes: 0x04 || x || y)."""
    if pt is None:
        return b"\x00"
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def bytes_to_point(data: bytes) -> Point:
    """Deserialize uncompressed SEC1 point and validate it lies on NIST P-256."""
    if data == b"\x00":
        return None
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("Invalid uncompressed SEC1 point encoding")
    x = int.from_bytes(data[1:33], "big")
    y = int.from_bytes(data[33:65], "big")
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("Point does not lie on NIST P-256 curve")
    return pt


def point_to_hex(pt: Point) -> str:
    return point_to_bytes(pt).hex()


def hex_to_point(hex_str: str) -> Point:
    return bytes_to_point(bytes.fromhex(hex_str))


# ==============================================================================
# Symmetric Primitives: SHA3-256, PBKDF2-SHA3-256, HMAC-SHA3-256, XOR
# ==============================================================================
def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def hash_chain(x: bytes, steps: int) -> bytes:
    """Compute H^(steps)(x) using SHA3-256."""
    val = x
    for _ in range(steps):
        val = hashlib.sha3_256(val).digest()
    return val


def derive_secret_xa(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive 256-bit root secret x_A = PBKDF2-HMAC-SHA3-256(PW_A, salt_A)."""
    return hashlib.pbkdf2_hmac(
        "sha3_256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


def compute_session_key(n1: str, q_point: Point) -> bytes:
    """KS = SHA3-256(N1 || Q)."""
    return sha3_256(n1.encode("utf-8") + point_to_bytes(q_point))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR inputs must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def compute_mac(
    ks: bytes,
    ct: bytes,
    c1: Point,
    c2: Point,
    ts1: int,
    id_a: str,
) -> bytes:
    """MAC_A = HMAC-SHA3-256(KS, CT || C1 || C2 || ts1 || ID_A)."""
    msg = (
        ct
        + point_to_bytes(c1)
        + point_to_bytes(c2)
        + str(ts1).encode("utf-8")
        + id_a.encode("utf-8")
    )
    return hmac.new(ks, msg, hashlib.sha3_256).digest()


def verify_mac(
    ks: bytes,
    ct: bytes,
    c1: Point,
    c2: Point,
    ts1: int,
    id_a: str,
    received_mac: bytes,
) -> bool:
    expected = compute_mac(ks, ct, c1, c2, ts1, id_a)
    return hmac.compare_digest(expected, received_mac)


# ==============================================================================
# Protocol High-Level Helpers (ElGamal over ECC + Hash Chain Verification)
# ==============================================================================
def elgamal_encrypt_point(q_point: Point, pb_point: Point) -> Tuple[int, Point, Point]:
    """
    Choose random r in [1, N-1], compute:
      C1 = r * G
      C2 = r * P_B + Q
    """
    r = secrets.randbelow(N - 1) + 1
    c1 = scalar_mult(r, G)
    c2 = point_add(scalar_mult(r, pb_point), q_point)
    return r, c1, c2


def elgamal_decrypt_point(c1: Point, c2: Point, db: int) -> Point:
    """Recover Q = C2 - d_B * C1."""
    if not is_on_curve(c1) or not is_on_curve(c2):
        raise ValueError("Ciphertext points are not on NIST P-256")
    return point_sub(c2, scalar_mult(db, c1))


def verify_hash_chain(r_val: bytes, pa_target: bytes, max_steps: int = HASH_CHAIN_LEN) -> Tuple[bool, int]:
    """
    Iteratively hash R with SHA3-256 up to max_steps times.
    If H^(k)(R) == P_A for some 1 <= k < max_steps, return (True, k).
    """
    cur = r_val
    for step in range(1, max_steps):
        cur = sha3_256(cur)
        if hmac.compare_digest(cur, pa_target):
            return True, step
    return False, -1


def generate_otp_6digits() -> str:
    """Generate a cryptographically secure 6-digit OTP N1."""
    return f"{secrets.randbelow(1_000_000):06d}"
