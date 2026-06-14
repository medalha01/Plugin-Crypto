<p align="center">
  <img src="https://img.shields.io/badge/OpenSSL-4.0.0-721412?style=for-the-badge&logo=openssl" alt="OpenSSL 4.0.0">
  <img src="https://img.shields.io/badge/Flutter-FFI-02569B?style=for-the-badge&logo=flutter" alt="Flutter FFI">
  <img src="https://img.shields.io/badge/Dart-3.11-0175C2?style=for-the-badge&logo=dart" alt="Dart 3.11"><br>
  <img src="https://img.shields.io/badge/Linux-x86__64-FCC624?style=flat-square&logo=linux" alt="Linux x86_64">
  <img src="https://img.shields.io/badge/Android-API_29+-3DDC84?style=flat-square&logo=android" alt="Android API 29+">
  <img src="https://img.shields.io/badge/iOS-help_wanted-999999?style=flat-square&logo=apple" alt="iOS help wanted"><br>
  A <i>Flutter FFI plugin</i> wrapping <b>OpenSSL 4.0.0</b> for native cryptographic operations<br>
  with post-quantum algorithm support and a fully typed Dart API.
</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api-overview">API Overview</a> •
  <a href="#platform-support">Platform Support</a> •
  <a href="#cryptographic-capabilities">Capabilities</a> •
  <a href="#installation">Installation</a> •
  <a href="#testing">Testing</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Key Features

- **43 public methods** — symmetric encryption (AES-CBC, AES-GCM), asymmetric (RSA, ECDSA, ML-KEM, ML-DSA), X.509 certificates, CMS/PKCS#7 signing and encryption, CRL, OCSP, CSR, RFC 3161 timestamps, ASN.1 parsing, and cryptographic hashing (SHA-256, SHA-512, SHA3-256, SHA3-512).
- **Direct FFI bindings** — calls OpenSSL C functions via `dart:ffi` with no method channels, no serialization overhead, and no platform-specific bridge code for crypto operations.
- **Post-quantum ready** — ML-KEM (FIPS 203, Kyber) for key encapsulation and ML-DSA (FIPS 204) for signatures, compiled from `oqsprovider`.
- **Three security levels** — ML-KEM-512/768/1024 and ML-DSA-44/65/87 covering NIST levels 1 through 5.
- **CAdES-BES** — CMS advanced electronic signatures with signing-time and message-digest attributes.
- **Streaming file signing** — signs large files in 8 KB chunks via `BIO` chain, avoiding full-file copies into memory.
- **Certificate chain validation** — verifies entire X.509 chains with depth tracking and per-certificate error reporting.
- **Unified error handling** — 13 sealed error types (`CryptoError`) with OpenSSL error queue capture, plus a `CryptoResult<T>` monad for operations that distinguish semantic failures from exceptions.
- **LRU certificate cache with TTL** — threaded through CRL/OCSP/CSR/timestamp operations via `PluginCryptoContext`.
- **Metrics collection** — 12 modules measuring latency, throughput, memory, security bits, and algorithm characteristics, exported as JSON (`schema v1.2.0`).
- **Reproducible builds** — `tool/reproduce_all.sh` (981 lines) rebuilds OpenSSL `.so` files from verified tarballs with pinned commit hashes.

---

## Quick Start

Add to your `pubspec.yaml`:

```yaml
dependencies:
  plugin_crypto:
    path: path/to/plugin_crypto
```

```dart
import 'package:plugin_crypto/plugin_crypto.dart';

void main() {
  final api = PluginCryptoAPI.instance;

  // ── Hash ────────────────────────────────────────────────
  final hash = api.sha256(utf8.encode('hello world'));
  print(hash); // 32 bytes

  // ── Random ──────────────────────────────────────────────
  final key = api.randomBytes(32);   // AES-256 key
  final iv  = api.randomBytes(12);   // GCM nonce

  // ── AES-256-GCM encrypt ─────────────────────────────────
  final result = api.aes256GcmEncrypt(key, iv, utf8.encode('secret message'));
  // result.ciphertext, result.tag (16 bytes)

  // ── AES-256-GCM decrypt ─────────────────────────────────
  final plain = api.aes256GcmDecrypt(key, iv, result.ciphertext, result.tag);
  print(utf8.decode(plain)); // 'secret message'

  // ── RSA key generation ──────────────────────────────────
  final rsa = api.generateRsaKeyPair(2048);
  print(rsa.publicKeyPem);  // -----BEGIN PUBLIC KEY-----

  // ── Sign & verify ───────────────────────────────────────
  final sig = api.sign(utf8.encode('data'), utf8.encode(rsa.privateKeyPem));
  final ok  = api.verify(utf8.encode('data'), utf8.encode(rsa.publicKeyPem), sig);
  print(ok); // true

  // ── EC key generation ───────────────────────────────────
  final ec = api.generateEcKeyPair('prime256v1'); // P-256
  // Also: secp384r1 (P-384), secp521r1 (P-521)

  // ── CMS sign & verify ───────────────────────────────────
  final cms = api.cmsSign(
    utf8.encode('payload'),
    utf8.encode(certPem),
    utf8.encode(keyPem),
  );
  final cmsOk = api.cmsVerify(cms);
  print(cmsOk); // true

  // ── X.509 certificate parsing ───────────────────────────
  final cert = api.parseX509Certificate(certBytes);
  print(cert.subjectCn);   // 'example.com'
  print(cert.notBefore);   // DateTime
  print(cert.notAfter);    // DateTime

  // ── OpenSSL errors ──────────────────────────────────────
  final err = api.getLastError();
  if (err != null) {
    print('OpenSSL error: $err');
    api.clearErrors();
  }
}
```

---

## API Overview

Every public method lives on the singleton `PluginCryptoAPI.instance`:

| Category | Methods | Description |
|----------|---------|-------------|
| **Info** | `getOpenSSLVersion()` | Returns the linked OpenSSL version string |
| **Hash** | `sha256`, `sha512`, `sha3_256`, `sha3_512` | One-shot cryptographic digest, returns `Uint8List` |
| **Random** | `randomBytes(length)` | CSPRNG bytes via `RAND_bytes` |
| **AES-CBC** | `aes128CbcEncrypt/Decrypt`, `aes256CbcEncrypt/Decrypt` | PKCS#7-padded CBC; key=16/32, iv=16 bytes |
| **AES-GCM** | `aes128GcmEncrypt/Decrypt`, `aes256GcmEncrypt/Decrypt` | AEAD with 16-byte auth tag and optional AAD; nonce=12 bytes |
| **RSA** | `generateRsaKeyPair(bits)`, `sign`, `verify`, `rsaEncrypt`, `rsaDecrypt` | OAEP with SHA-256; PKCS#1 v1.5 and PSS signatures |
| **ECDSA** | `generateEcKeyPair(curve)` | P-256, P-384, P-521; DER-encoded signatures |
| **ML-KEM** | `mlKemEncapsulate`, `mlKemDecapsulate` | FIPS 203 key encapsulation (Kyber) |
| **ML-DSA** | sign/verify (via `KeySpec`) | FIPS 204 post-quantum signatures |
| **X.509** | `parseX509Certificate`, `verifyX509Certificate` | PEM/DER parsing, subject/issuer fields, extensions |
| **CMS** | `cmsSign`, `cmsVerify`, `cmsEncrypt`, `cmsDecrypt`, `cmsSignCades` | PKCS#7 SignedData, EnvelopedData, CAdES-BES |
| **CRL** | `parseCrl`, `verifyCrlSignature`, `checkRevocation` | Returns `CryptoResult<T>` |
| **OCSP** | `buildOcspRequest`, `verifyOcspResponse` | Manual DER construction, nonce support |
| **CSR** | `generateCsr(CsrRequest)` | PKCS#10 with customizable DN and extensions |
| **Timestamp** | `createTimestampRequest`, `verifyTimestampResponse`, `verifyTimestamp` | RFC 3161 with optional nonce |
| **Error** | `getLastError()`, `clearErrors()` | OpenSSL error queue access |

### Error model

Throw-style (hash, AES, RSA, EC, CMS, X.509 parse):

```dart
try {
  api.aes128GcmDecrypt(key, iv, ct, wrongTag);
} on AesGcmAuthFailure catch (e) {
  print('Tag mismatch: ${e.reason}');
  print('OpenSSL: ${e.openSslError}');
}
```

Result-monad style (CRL, OCSP, CSR, Timestamp):

```dart
final result = api.checkRevocation(certBytes, crlBytes);
switch (result) {
  case CryptoSuccess(:final value):
    print('Revoked: ${value.isRevoked}');
  case CryptoFailure(:final error):
    print('CRL error: ${error.message}');
}
```

### Key types

```dart
// RSA
api.generateRsaKeyPair(bits);    // 1024-16384, multiples of 1024

// EC
api.generateEcKeyPair('prime256v1');   // P-256
api.generateEcKeyPair('secp384r1');    // P-384
api.generateEcKeyPair('secp521r1');    // P-521

// Post-quantum (via KeyCreator flow)
KeyCreatorFactory.create(MlKemKeySpec(MlKemParameterSet.mlKem768));
KeyCreatorFactory.create(MlDsaKeySpec(MlDsaParameterSet.mlDsa65));
```

---

## Platform Support

| Platform | Status | Architecture | Notes |
|----------|--------|-------------|-------|
| **Linux** | Full support | `x86_64` | `libcrypto.so.4` + `libssl.so.4`, 4 providers (default, fips, legacy, oqsprovider) |
| **Android** | Full support | `arm64-v8a`, `armeabi-v7a`, `x86_64` | 3 ABIs with prebuilt `.so` in `jniLibs/`, NDK 27.1 |
| **iOS** | **Help wanted** | `arm64` | Plugin scaffold exists (`ffiPlugin: true` in `pubspec.yaml`), OpenSSL `.xcframework` + `oqsprovider` need to be compiled and linked. See [Contributing](#contributing). |

The plugin uses Flutter's FFI plugin system (`ffiPlugin: true`). On Linux, shared libraries are loaded from `native/linux/x86_64/`. On Android, they ship inside the APK via `jniLibs/`. No method channels are used for cryptographic operations.

---

## Cryptographic Capabilities

### Symmetric encryption

| Algorithm | Mode | Key sizes | IV/Nonce | Auth tag | Padding |
|-----------|------|-----------|----------|----------|---------|
| AES-128 | CBC | 16 bytes | 16 bytes | — | PKCS#7 |
| AES-128 | GCM | 16 bytes | 12 bytes | 16 bytes | — |
| AES-256 | CBC | 32 bytes | 16 bytes | — | PKCS#7 |
| AES-256 | GCM | 32 bytes | 12 bytes | 16 bytes | — |

GCM supports optional Additional Authenticated Data (AAD) via the `aad:` named parameter.

### Asymmetric algorithms

| Algorithm | Operations | Key sizes / Curves | Padding / Encoding |
|-----------|-----------|-------------------|-------------------|
| RSA | Keygen, sign, verify, encrypt, decrypt | 1024–16384 bits | OAEP (SHA-256), PKCS#1 v1.5, PSS |
| ECDSA | Keygen, sign, verify | P-256, P-384, P-521 | DER signatures |
| ML-KEM | Encapsulate, decapsulate | 512, 768, 1024 | FIPS 203 (Kyber) |
| ML-DSA | Sign, verify | 44, 65, 87 | FIPS 204 |

### Hash algorithms

SHA-256 (32 bytes), SHA-512 (64 bytes), SHA3-256 (32 bytes), SHA3-512 (64 bytes).

### PKI operations

| Operation | Standard | Format |
|-----------|----------|--------|
| X.509 parsing | RFC 5280 | PEM and DER input |
| CMS SignedData | PKCS#7 / RFC 5652 | DER output |
| CMS EnvelopedData | PKCS#7 / RFC 5652 | DER output |
| CAdES-BES | ETSI TS 101 733 | CMS with signed attributes |
| CRL | RFC 5280 | PEM and DER input |
| OCSP | RFC 6960 | Manual DER construction |
| CSR | PKCS#10 / RFC 2986 | PEM output |
| Timestamp | RFC 3161 | DER request/response |

### OpenSSL providers

The plugin ships 4 OpenSSL providers:

| Provider | Algorithms |
|----------|-----------|
| `default` | AES, RSA, ECDSA, SHA-2, SHA-3, HKDF |
| `fips` | FIPS 140-3 validated subset |
| `legacy` | Older algorithms (CAST5, IDEA, SEED, etc.) |
| `oqsprovider` | ML-KEM (Kyber), ML-DSA (Dilithium) |

The `oqsprovider` is conditionally loaded from `native/linux/x86_64/providers/` (Linux) and embedded in the APK (`jniLibs/`) for Android.

---

## Installation

### Prerequisites

- Flutter SDK >= 3.3.0
- Dart SDK >= 3.11.5
- Linux: CMake, Ninja, Clang, GTK 3 development headers
- Android: NDK 27.1.12297006, Android SDK with API 36

### From this repository

```bash
git clone https://github.com/medalha01/tcc-plugin-crypto.git
cd tcc-plugin-crypto/plugin_crypto
flutter pub get
```

### Linux build

```bash
cd plugin_crypto/example
flutter build linux
```

The build automatically links `libcrypto.so.4`, `libssl.so.4`, and loads providers from `native/linux/x86_64/providers/`.

### Android build

```bash
cd tcc_test_app
flutter build apk --debug
```

Prebuilt `.so` files for 3 ABIs are included in `plugin_crypto/android/src/main/jniLibs/`. The Gradle build packages them into the APK automatically.

### OpenSSL shared libraries

Prebuilt `.so` files are committed in the repository:

```
plugin_crypto/
├── native/linux/x86_64/
│   ├── libcrypto.so.4       (~7.0 MB)
│   ├── libssl.so.4          (~1.3 MB)
│   └── providers/
│       ├── default.so
│       ├── fips.so
│       ├── legacy.so
│       └── oqsprovider.so
└── android/src/main/jniLibs/
    ├── arm64-v8a/
    │   ├── libcrypto.so     (~3.8 MB)
    │   └── libssl.so        (~0.9 MB)
    ├── armeabi-v7a/
    │   ├── libcrypto.so     (~2.7 MB)
    │   └── libssl.so        (~0.6 MB)
    └── x86_64/
        ├── libcrypto.so     (~4.2 MB)
        └── libssl.so        (~1.0 MB)
```

To rebuild these from source, run:

```bash
./tool/reproduce_all.sh
```

This script downloads verified OpenSSL 4.0.0 and `oqsprovider` tarballs, compiles for each target, and copies the outputs into place.

---

## Testing

The test suite has **41 test zones** with over 400 individual test cases.

### Run all tests (Linux)

```bash
cd plugin_crypto
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH flutter test
```

### Run a specific zone

```bash
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH \
  flutter test test/zone06_rsa_test.dart
```

### Run tests with tags

```bash
# Skip slow tests (default)
flutter test

# Include slow fuzzing tests
flutter test --tags slow

# Run everything, including stress and soak tests
flutter test --run-skipped
```

### Test taxonomy

| Zones | Focus | Count |
|-------|-------|-------|
| 01–03 | Native loader, hash, random | ~25 |
| 04–10 | AES-CBC, AES-GCM, RSA, ECDSA, X.509, CMS, error handling | ~130 |
| 11–18 | CMS encrypt/decrypt, error handling extended, edge cases (CBC, random, hash, RSA, ECDSA, X.509) | ~110 |
| 19–26 | Flows: key creation, certificate creation, file signing, chain validation, CRL, OCSP, CSR | ~35 |
| 27–30 | X.509 extensions, CAdES, ASN.1, property-based | ~55 |
| 31 | Randomized fuzzing (10,000 cases) | 5 |
| 32–35 | NIST SP 800-22, SP 800-90B, RSA timing, FIPS 186-4 | ~60 |
| 36–40 | Differential CLI, soak (4 × 5 min), interop matrix, combinatorial, public API ICP | ~65 |

### Test tags

| Tag | Behavior | Zones |
|-----|----------|-------|
| `slow` | Skipped by default; opt-in with `--tags slow` | 31, 37 |
| `stress` | Resource-intensive; may overlap with `slow` | 37 |
| `concurrent` | Safe for parallel execution | Most zones |
| `metrics` | Generates `tcc_metrics_report.json` | — |

---

## Documentation

Full technical documentation in Portuguese (Brazil) is available in `docs/`:

| File | Lines | Content |
|------|-------|---------|
| `ARQUITETURA.md` | 1,144 | 3-layer architecture (FFI → Core → Public API), ASCII diagrams, providers, thread safety, memory model, Linux vs Android comparison |
| `API.md` | 1,557 | Complete reference of all 43 methods with Dart signatures, parameter tables, C function call chains, error types, code examples |
| `MODULOS.md` | 1,134 | All 76 source files documented with OpenSSL function mapping, internal flow, line-count summary table |
| `FLUXOS.md` | 1,276 | 7 complete workflows with ASCII sequence diagrams, exact OpenSSL calls, resource management patterns |
| `GUIA_TESTES.md` | 1,820 | 41 test zones, tag system, CI/CD pipelines (GitHub Actions + GitLab CI), soak and fuzzing |
| `COMPILACAO.md` | 1,529 | Step-by-step builds for Linux (CMake, 5 phases) and Android (Gradle + NDK, 3 ABIs), provider compilation, troubleshooting (16 scenarios), profiling |

---

## Contributing

Contributions are welcome, especially in these areas:

### High priority

- **iOS support** — The plugin scaffold declares `ios: ffiPlugin: true` in `pubspec.yaml`. The missing piece is compiling OpenSSL 4.0.0 + `oqsprovider` as an `.xcframework` for `arm64` and placing it in `plugin_crypto/ios/`. The Dart FFI layer is platform-agnostic and will work unchanged.
- **macOS support** — Similar to iOS: needs OpenSSL `.dylib` files compiled for `arm64` and `x86_64`.
- **Windows support** — OpenSSL `.dll` files for `x64`, placed in the appropriate Flutter Windows plugin directory.

### General

- Additional NIST EC curves (Brainpool, Curve25519, Curve448)
- Hardware-backed key storage integration (Android Keystore, iOS Secure Enclave)
- PKCS#11 / hardware token support
- Streaming AEAD for large files
- TPM 2.0 integration
- Benchmarking tooling and performance regression tests
- Additional `.sublime-syntax` definitions for documentation highlighting

### Development workflow

```bash
# Clone
git clone https://github.com/medalha01/tcc-plugin-crypto.git
cd tcc-plugin-crypto

# Get dependencies
cd plugin_crypto && flutter pub get
cd ../tcc_test_app && flutter pub get

# Run all tests (Linux)
cd ../plugin_crypto
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH flutter test

# Build the test app APK
cd ../tcc_test_app
flutter build apk --debug

# Rebuild OpenSSL from source
cd ../tool
./reproduce_all.sh
```

---

## License

MIT — see the source files for details.
