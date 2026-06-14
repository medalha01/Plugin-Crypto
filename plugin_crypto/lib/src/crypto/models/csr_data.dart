library;

import 'dart:typed_data';

import '../crypto_api.dart';
import 'distinguished_name.dart';

class CsrRequest {
  /// The subject Distinguished Name for the requested certificate.
  final DistinguishedName subject;

  /// The key pair for the subject (CSR is signed with the private key).
  final KeyPair subjectKeyPair;

  /// Optional list of DNS names for the Subject Alternative Name extension.
  final List<String>? dnsNames;

  const CsrRequest({
    required this.subject,
    required this.subjectKeyPair,
    this.dnsNames,
  });

  CsrRequest validate() {
    subject.validate();
    if (subjectKeyPair.privateKeyPem.isEmpty) {
      throw ArgumentError(
        'CsrRequest.subjectKeyPair.privateKeyPem must be non-empty',
      );
    }
    if (subjectKeyPair.publicKeyPem.isEmpty) {
      throw ArgumentError(
        'CsrRequest.subjectKeyPair.publicKeyPem must be non-empty',
      );
    }
    if (dnsNames != null) {
      for (final name in dnsNames!) {
        if (name.isEmpty) {
          throw ArgumentError(
            'CsrRequest.dnsNames must not contain empty '
            'strings',
          );
        }
      }
    }
    return this;
  }
}

/// Output DTO for CSR generation.
class CsrData {
  /// The CSR as raw DER bytes.
  final Uint8List derBytes;

  /// The CSR as a PEM string.
  final String pemString;

  /// Distinguished Name of the subject in oneline format.
  final String subjectDn;

  const CsrData({
    required this.derBytes,
    required this.pemString,
    required this.subjectDn,
  });
}
