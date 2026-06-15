## 0.0.1

- Initial release.
- 43 public cryptographic methods via FFI: AES-CBC, AES-GCM, RSA, ECDSA, ML-KEM (Kyber), ML-DSA (Dilithium).
- X.509 certificate parsing, CMS/PKCS#7 signing and encryption, CAdES-BES.
- CRL verification, OCSP request construction, CSR generation, RFC 3161 timestamps.
- SHA-256, SHA-512, SHA3-256, SHA3-512 hashing.
- Direct `dart:ffi` bindings — no method channels for crypto operations.
- Linux x86_64 and Android arm64-v8a support.
- Prebuilt OpenSSL 4.0.0 shared libraries with oqsprovider for post-quantum algorithms.
- 41 test zones with 515+ unit tests (Linux) and 177 integration tests (Android).
- Metrics collection with JSON export.
