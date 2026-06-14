library;

import 'dart:ffi';
import '../../ffi/openssl_bindings.dart';

/// Supported hash algorithms for signing.
enum HashAlgorithm {
  sha256,
  sha512,
  sha3_256,
  sha3_512;

  /// Resolves this hash algorithm to its OpenSSL [EVP_MD] pointer.
  Pointer<Void> evpMd(OpenSslBindings b) {
    return switch (this) {
      HashAlgorithm.sha256 => b.evpSha256(),
      HashAlgorithm.sha512 => b.evpSha512(),
      HashAlgorithm.sha3_256 => b.evpSha3_256(),
      HashAlgorithm.sha3_512 => b.evpSha3_512(),
    };
  }

  /// Returns the [HashAlgorithm] for the given string name, or `null`.
  static HashAlgorithm? fromName(String name) {
    return switch (name) {
      'sha256' => HashAlgorithm.sha256,
      'sha512' => HashAlgorithm.sha512,
      'sha3_256' => HashAlgorithm.sha3_256,
      'sha3_512' => HashAlgorithm.sha3_512,
      _ => null,
    };
  }
}

/// Supported key types for signing.
enum SigningKeyType {
  rsa,
  ec,

  /// ML-DSA (FIPS 204) — NIST-standardized post-quantum digital signature.
  ml_dsa,
}

class SigningAlgorithm {
  final HashAlgorithm hash;
  final SigningKeyType keyType;

  const SigningAlgorithm({required this.hash, required this.keyType});

  /// Returns the hash name string as used by the OpenSSL API.
  String get hashName => switch (hash) {
    HashAlgorithm.sha256 => 'sha256',
    HashAlgorithm.sha512 => 'sha512',
    HashAlgorithm.sha3_256 => 'sha3_256',
    HashAlgorithm.sha3_512 => 'sha3_512',
  };

  @override
  bool operator ==(Object other) =>
      other is SigningAlgorithm &&
      hash == other.hash &&
      keyType == other.keyType;

  @override
  int get hashCode => Object.hash(hash, keyType);

  @override
  String toString() => 'SigningAlgorithm(${hash.name}, ${keyType.name})';
}
