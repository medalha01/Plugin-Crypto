library;

import '../crypto_api.dart';

/// Extension methods on [KeyPair].
extension KeyPairExtensions on KeyPair {
  /// Returns `true` if the public key PEM header indicates an RSA key.
  bool get isRsa =>
      publicKeyPem.contains('BEGIN RSA PUBLIC KEY') ||
      (publicKeyPem.contains('BEGIN PUBLIC KEY') &&
          privateKeyPem.contains('BEGIN RSA PRIVATE KEY'));

  /// Returns `true` if the public key PEM header indicates an EC key.
  bool get isEc =>
      publicKeyPem.contains('BEGIN EC PUBLIC KEY') ||
      (publicKeyPem.contains('BEGIN PUBLIC KEY') &&
          privateKeyPem.contains('BEGIN EC PRIVATE KEY'));

  /// Returns a human-readable key type label.
  String get keyTypeLabel {
    if (isRsa) return 'RSA';
    if (isEc) return 'EC';
    return 'Unknown';
  }
}
