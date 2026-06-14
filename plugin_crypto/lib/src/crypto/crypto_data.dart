/// Data classes for cryptographic operations.
library;

import 'dart:typed_data';

import 'models/certificate_data.dart';


class AesGcmResult {
  final Uint8List ciphertext;
  final Uint8List tag;
  const AesGcmResult(this.ciphertext, this.tag);
}

class KeyPair {
  final String publicKeyPem;
  final String privateKeyPem;
  const KeyPair({required this.publicKeyPem, required this.privateKeyPem});
}

class X509Certificate {
  final String subject;
  final String issuer;
  final String serialNumber;
  final DateTime notBefore;
  final DateTime notAfter;
  final Uint8List rawDer;

  /// Parsed X.509 v3 extensions, or `null` if no extensions were found
  /// or parsing was not requested.
  final X509ParsedExtensions? extensions;

  const X509Certificate({
    required this.subject,
    required this.issuer,
    required this.serialNumber,
    required this.notBefore,
    required this.notAfter,
    required this.rawDer,
    this.extensions,
  });
}
