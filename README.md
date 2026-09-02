# Python Post-Quantum Cryptography

![PQC](https://img.shields.io/badge/PQC-ML--KEM%20%7C%20ML--DSA-6f42c1)
![FIPS 203](https://img.shields.io/badge/FIPS-203-blue)
![FIPS 204](https://img.shields.io/badge/FIPS-204-blue)
![pyca/cryptography](https://img.shields.io/badge/pyca%2Fcryptography-%3E%3D48-informational)
![Python](https://img.shields.io/badge/python-3.9%2B-yellow)

A simple proof of concept for post-quantum cryptography via `pip`, to be used for any Python code, and nothing else.

Testing ML-KEM and ML-DSA in `pyca/cryptography` 48+, the two post-quantum algorithms currently supported.

```bash
pip install "cryptography>=48"
```

That's the whole install. No Rust toolchain, no vendored PQC library, no separate build step.

---

## Algorithms

Both ML-DSA and ML-KEM are lattice-based, and both trace back to NIST's Post-Quantum Cryptography standardization project (2016–2024).

| Algorithm   | Full name                                              | FIPS      | Replaces                          | Status in `pyca/cryptography` |
| ----------- | ------------------------------------------------------- | --------- | ---------------------------------- | ------------------------------ |
| **ML-DSA**  | Module-Lattice-Based Digital Signature Algorithm         | FIPS 204  | RSA, ECDSA, Ed25519 (signing)      | ✅ Supported (48+)              |
| **ML-KEM**  | Module-Lattice-Based Key-Encapsulation Mechanism         | FIPS 203  | DH, ECDH, X25519 (key exchange)    | ✅ Supported (48+)              |
| **SLH-DSA** | Stateless Hash-based Digital Signature Algorithm         | FIPS 205  | RSA, ECDSA, Ed25519 (conservative backstop) | ⏳ Not yet supported (in progress upstream) |

Both ML-DSA and ML-KEM rest on the hardness of **Module-LWE** (Learning With Errors) and related lattice problems. Solving certain high-dimensional lattice problems is believed to stay hard even for a quantum computer.

---

## Scope

> [!IMPORTANT]
> This is a **functional / API-correctness suite**, not a cryptanalytic audit.
>
> It confirms the bindings behave per spec (FIPS 203 / FIPS 204) and that your environment is correctly wired up.
>
> It says **nothing** about side-channel resistance, constant-time behavior, or the security of the underlying AWS-LC / Rust implementation itself.
>
> Many thanks to Sovereign Tech (sovereign.tech)
---

## Topics

`post-quantum-cryptography` `ml-kem` `ml-dsa` `fips203` `fips204` `pyca-cryptography`

---


https://github.com/user-attachments/assets/e4fbc769-d693-489f-bdba-eacd194c85df


