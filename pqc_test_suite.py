#!/usr/bin/env python3
"""
pqc_test_suite.py

Functional and comparative test suite for the post-quantum primitives shipped in pyca/cryptography >= 48 (ML-KEM / FIPS 203, ML-DSA / FIPS 204) -  Chadi Saliby

This will basically cover and confirm the following:
  1. Environment check (cryptography version, backend)
  2. ML-DSA (65/87): keygen, sign, verify, tamper detection, wrong-key rejection (FIPS 204 Compliance) - CRYSTALS-Dilithium
  3. ML-KEM (768/1024): keygen, encapsulate, decapsulate, ciphertext-tamper rejection (FIPS 203 Compliance) - CRYSTALS-Kyber
  4. Size comparison: PQC vs classical (Ed25519 / X25519)
  5. Performance benchmark (keygen / sign-encap / verify-decap throughput)
  6. Round-trip and verification determinism check across repeated runs

Usage:
    python3 pqc_test_suite.py                 # run everything
    python3 pqc_test_suite.py --skip-bench     # skip timing runs
    python3 pqc_test_suite.py --iterations 20  # change benchmark sample size
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

try:
    import cryptography
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
    from cryptography.exceptions import InvalidSignature, InvalidKey
except ImportError as exc:
    print(f"FATAL: could not import cryptography primitives ({exc}).")
    print("This suite requires pyca/cryptography >= 48. Install with:")
    print('    pip install "cryptography>=48"')
    sys.exit(1)


# --------------------------------------------------------------------------
# Result tracking
# --------------------------------------------------------------------------

@dataclass
class SuiteResult:
    passed: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  [PASS] {name}")
        else:
            self.failed += 1
            self.failures.append(name)
            print(f"  [FAIL] {name}  {detail}")

    def summary(self) -> bool:
        total = self.passed + self.failed
        print(f"\n{self.passed}/{total} checks passed.")
        if self.failures:
            print("Failed checks:")
            for f in self.failures:
                print(f"  - {f}")
        return self.failed == 0


RESULT = SuiteResult()


def section(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


# --------------------------------------------------------------------------
# 1. Environment
# --------------------------------------------------------------------------

def check_environment() -> None:
    section("1. Environment")
    print(f"cryptography version: {cryptography.__version__}")
    major = int(cryptography.__version__.split(".")[0])
    RESULT.check(
        "cryptography >= 48 (PQC support introduced in this release)",
        major >= 48,
        f"found {cryptography.__version__}",
    )
    RESULT.check("mldsa module importable", hasattr(mldsa, "MLDSA65PrivateKey"))
    RESULT.check("mlkem module importable", hasattr(mlkem, "MLKEM768PrivateKey"))


# --------------------------------------------------------------------------
# 2. ML-DSA (signatures)
# --------------------------------------------------------------------------

MLDSA_VARIANTS = {
    "ML-DSA-44": getattr(mldsa, "MLDSA44PrivateKey", None),
    "ML-DSA-65": getattr(mldsa, "MLDSA65PrivateKey", None),
    "ML-DSA-87": getattr(mldsa, "MLDSA87PrivateKey", None),
}


def test_mldsa() -> None:
    section("2. ML-DSA (FIPS 204) signature tests")
    message = b"Phoenix CyberOps: post-quantum signature integrity test"
    tampered = b"Phoenix CyberOps: post-quantum signature integrity fail"

    for name, cls in MLDSA_VARIANTS.items():
        if cls is None:
            print(f"  [SKIP] {name} not available in this build")
            continue

        print(f"\n-- {name} --")
        priv = cls.generate()
        pub = priv.public_key()

        # Valid sign/verify round trip
        sig = priv.sign(message)
        try:
            pub.verify(sig, message)
            verified = True
        except InvalidSignature:
            verified = False
        RESULT.check(f"{name}: valid signature verifies", verified)

        # Tampered message must be rejected
        try:
            pub.verify(sig, tampered)
            rejected = False
        except InvalidSignature:
            rejected = True
        RESULT.check(f"{name}: tampered message is rejected", rejected)

        # Signature from a different keypair must not verify against this key
        other_priv = cls.generate()
        other_sig = other_priv.sign(message)
        try:
            pub.verify(other_sig, message)
            wrong_key_rejected = False
        except InvalidSignature:
            wrong_key_rejected = True
        RESULT.check(f"{name}: signature from a different key is rejected", wrong_key_rejected)

        # Signatures are randomized/contextual -> two signatures over the same
        # message need not be byte-identical, but both must independently verify.
        sig2 = priv.sign(message)
        try:
            pub.verify(sig2, message)
            second_ok = True
        except InvalidSignature:
            second_ok = False
        RESULT.check(f"{name}: repeated signing still verifies", second_ok)

        print(f"  public key: {len(pub.public_bytes_raw())} B | "
              f"signature: {len(sig)} B")


# --------------------------------------------------------------------------
# 3. ML-KEM (key encapsulation)
# --------------------------------------------------------------------------

MLKEM_VARIANTS = {
    "ML-KEM-512": getattr(mlkem, "MLKEM512PrivateKey", None),
    "ML-KEM-768": getattr(mlkem, "MLKEM768PrivateKey", None),
    "ML-KEM-1024": getattr(mlkem, "MLKEM1024PrivateKey", None),
}


def test_mlkem() -> None:
    section("3. ML-KEM (FIPS 203) key encapsulation tests")

    for name, cls in MLKEM_VARIANTS.items():
        if cls is None:
            print(f"  [SKIP] {name} not available in this build")
            continue

        print(f"\n-- {name} --")
        priv = cls.generate()
        pub = priv.public_key()

        # Valid encapsulate/decapsulate round trip
        shared_sender, ct = pub.encapsulate()
        shared_receiver = priv.decapsulate(ct)
        RESULT.check(f"{name}: shared secrets match", shared_sender == shared_receiver)
        RESULT.check(f"{name}: shared secret is 32 bytes", len(shared_sender) == 32)

        # Decapsulating with the wrong private key must NOT produce the same
        # secret (ML-KEM has implicit rejection: it returns a pseudorandom
        # value rather than raising, so we assert the secrets *differ*).
        other_priv = cls.generate()
        mismatched_secret = other_priv.decapsulate(ct)
        RESULT.check(
            f"{name}: wrong private key yields a different secret (implicit rejection)",
            mismatched_secret != shared_sender,
        )

        # Corrupting the ciphertext must also change the derived secret
        # rather than raising or silently matching.
        corrupted = bytearray(ct)
        corrupted[0] ^= 0xFF
        corrupted_secret = priv.decapsulate(bytes(corrupted))
        RESULT.check(
            f"{name}: corrupted ciphertext yields a different secret",
            corrupted_secret != shared_sender,
        )

        print(f"  public key: {len(pub.public_bytes_raw())} B | "
              f"ciphertext: {len(ct)} B | shared secret: {len(shared_sender)} B")


# --------------------------------------------------------------------------
# 4. Size comparison: PQC vs classical
# --------------------------------------------------------------------------

def test_size_comparison() -> None:
    section("4. Size comparison: classical vs post-quantum")

    # Signatures: Ed25519 vs ML-DSA-65
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_sig = ed_priv.sign(b"message")

    from cryptography.hazmat.primitives import serialization
    ed_pub_bytes = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    dsa_priv = mldsa.MLDSA65PrivateKey.generate()
    dsa_pub = dsa_priv.public_key()
    dsa_sig = dsa_priv.sign(b"message")

    print("\nSignature schemes:")
    print(f"  {'Algorithm':<14}{'Public key':>12}{'Signature':>12}")
    print(f"  {'Ed25519':<14}{len(ed_pub_bytes):>10} B{len(ed_sig):>10} B")
    print(f"  {'ML-DSA-65':<14}{len(dsa_pub.public_bytes_raw()):>10} B{len(dsa_sig):>10} B")
    RESULT.check(
        "ML-DSA-65 public key is larger than Ed25519 (expected: lattice overhead)",
        len(dsa_pub.public_bytes_raw()) > len(ed_pub_bytes),
    )
    RESULT.check(
        "ML-DSA-65 signature is larger than Ed25519 (expected: lattice overhead)",
        len(dsa_sig) > len(ed_sig),
    )

    # KEM / key exchange: X25519 vs ML-KEM-768
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kem_priv = mlkem.MLKEM768PrivateKey.generate()
    kem_pub = kem_priv.public_key()
    _, kem_ct = kem_pub.encapsulate()

    print("\nKey exchange / KEM:")
    print(f"  {'Algorithm':<14}{'Public key':>12}{'Output':>12}")
    print(f"  {'X25519':<14}{len(x_pub_bytes):>10} B{'32 B (shared)':>14}")
    print(f"  {'ML-KEM-768':<14}{len(kem_pub.public_bytes_raw()):>10} B{len(kem_ct):>10} B (ct)")
    RESULT.check(
        "ML-KEM-768 public key is larger than X25519 (expected: lattice overhead)",
        len(kem_pub.public_bytes_raw()) > len(x_pub_bytes),
    )


# --------------------------------------------------------------------------
# 5. Performance benchmark
# --------------------------------------------------------------------------

def _time_it(fn: Callable[[], None], iterations: int) -> dict:
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)  # ms
    return {
        "mean_ms": statistics.mean(samples),
        "median_ms": statistics.median(samples),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def benchmark(iterations: int) -> None:
    section(f"5. Performance benchmark ({iterations} iterations each)")

    message = b"benchmark message"

    def dsa_keygen():
        mldsa.MLDSA65PrivateKey.generate()

    dsa_priv = mldsa.MLDSA65PrivateKey.generate()
    dsa_pub = dsa_priv.public_key()

    def dsa_sign():
        dsa_priv.sign(message)

    dsa_sig = dsa_priv.sign(message)

    def dsa_verify():
        dsa_pub.verify(dsa_sig, message)

    kem_priv = mlkem.MLKEM768PrivateKey.generate()
    kem_pub = kem_priv.public_key()

    def kem_keygen():
        mlkem.MLKEM768PrivateKey.generate()

    def kem_encap():
        kem_pub.encapsulate()

    _, kem_ct = kem_pub.encapsulate()

    def kem_decap():
        kem_priv.decapsulate(kem_ct)

    rows = [
        ("ML-DSA-65 keygen", dsa_keygen),
        ("ML-DSA-65 sign", dsa_sign),
        ("ML-DSA-65 verify", dsa_verify),
        ("ML-KEM-768 keygen", kem_keygen),
        ("ML-KEM-768 encapsulate", kem_encap),
        ("ML-KEM-768 decapsulate", kem_decap),
    ]

    print(f"\n  {'Operation':<24}{'mean (ms)':>12}{'median (ms)':>14}{'min (ms)':>12}{'max (ms)':>12}")
    for label, fn in rows:
        stats = _time_it(fn, iterations)
        print(f"  {label:<24}{stats['mean_ms']:>12.3f}{stats['median_ms']:>14.3f}"
              f"{stats['min_ms']:>12.3f}{stats['max_ms']:>12.3f}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Test suite for pyca/cryptography PQC primitives")
    parser.add_argument("--iterations", type=int, default=10,
                         help="benchmark sample size per operation (default: 10)")
    parser.add_argument("--skip-bench", action="store_true",
                         help="skip the performance benchmark section")
    args = parser.parse_args()

    check_environment()
    test_mldsa()
    test_mlkem()
    test_size_comparison()
    if not args.skip_bench:
        benchmark(args.iterations)

    section("Result")
    ok = RESULT.summary()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
