library;

/// Describes a key type and its parameters.
sealed class KeySpec {
  const KeySpec._();
}

class RsaKeySpec extends KeySpec {
  final int bits;

  RsaKeySpec(this.bits) : super._() {
    if (bits < 1024) {
      throw ArgumentError('RSA key bits must be >= 1024, got $bits');
    }
    if (bits > 16384) {
      throw ArgumentError('RSA key bits must be <= 16384, got $bits');
    }
    if (bits % 1024 != 0) {
      throw ArgumentError('RSA key bits must be a multiple of 1024, got $bits');
    }
  }
}

/// Supported NIST EC curves for key generation.
abstract class EcCurve {
  static const prime256v1 = 'prime256v1';
  static const secp384r1 = 'secp384r1';
  static const secp521r1 = 'secp521r1';

  static const _supported = {prime256v1, secp384r1, secp521r1};

  /// Returns `true` if [name] is a supported curve short name.
  static bool isSupported(String name) => _supported.contains(name);

  /// All supported curve names.
  static Set<String> get all => _supported;

  /// Validates that [name] is a supported curve name, throwing
  /// [ArgumentError] if not.
  static void validate(String name) {
    if (!isSupported(name)) {
      throw ArgumentError(
        'Unsupported EC curve: "$name". '
        'Supported curves: ${_supported.join(', ')}',
      );
    }
  }
}

class EcKeySpec extends KeySpec {
  final String curve;

  EcKeySpec(this.curve) : super._() {
    EcCurve.validate(curve);
  }
}


enum MlKemParameterSet {
  /// ML-KEM-512 — NIST security level 1 (128-bit, AES-128 equivalent).
  mlKem512,

  /// ML-KEM-768 — NIST security level 3 (192-bit, AES-192 equivalent).
  mlKem768,

  /// ML-KEM-1024 — NIST security level 5 (256-bit, AES-256 equivalent).
  mlKem1024,
}

enum MlDsaParameterSet {
  /// ML-DSA-44 — NIST security level 1 (128-bit, AES-128 equivalent).
  mlDsa44,

  /// ML-DSA-65 — NIST security level 3 (192-bit, AES-192 equivalent).
  mlDsa65,

  /// ML-DSA-87 — NIST security level 5 (256-bit, AES-256 equivalent).
  mlDsa87,
}

class MlKemKeySpec extends KeySpec {
  final MlKemParameterSet parameterSet;

  const MlKemKeySpec(this.parameterSet) : super._();
}

class MlDsaKeySpec extends KeySpec {
  final MlDsaParameterSet parameterSet;

  const MlDsaKeySpec(this.parameterSet) : super._();
}
