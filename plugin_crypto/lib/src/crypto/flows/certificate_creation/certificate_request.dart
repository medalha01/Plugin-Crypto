library;

import '../../crypto_api.dart';
import '../../models/distinguished_name.dart';
import '../../models/signing_algorithm.dart';

/// A request to create an X.509 certificate.
class CertificateRequest {
  /// The subject Distinguished Name.
  final DistinguishedName subject;

  /// The issuer Distinguished Name (same as [subject] for self-signed certs).
  final DistinguishedName issuer;

  final KeyPair subjectPublicKey;

  final KeyPair issuerPrivateKey;

  /// Certificate validity start date.
  final DateTime notBefore;

  /// Certificate validity end date.
  final DateTime notAfter;

  /// X.509 v3 extensions to add.
  final List<String> extensions;

  /// The signing algorithm (hash + key type).
  final SigningAlgorithm signingAlgorithm;

  CertificateRequest({
    required this.subject,
    required this.issuer,
    required this.subjectPublicKey,
    required this.issuerPrivateKey,
    required this.notBefore,
    required this.notAfter,
    this.extensions = const [],
    this.signingAlgorithm = const SigningAlgorithm(
      hash: HashAlgorithm.sha256,
      keyType: SigningKeyType.rsa,
    ),
  }) {
    subject.validate();
    issuer.validate();

    if (notBefore.isAfter(notAfter) || notBefore.isAtSameMomentAs(notAfter)) {
      throw ArgumentError(
        'notBefore ($notBefore) must be strictly before notAfter ($notAfter)',
      );
    }

    if (notAfter.year > 9999) {
      throw ArgumentError(
        'notAfter year must not exceed 9999 (ASN.1 GENERALIZEDTIME limit), '
        'got ${notAfter.year}',
      );
    }

    final oneYearAgo = DateTime.now().subtract(const Duration(days: 366));
    if (notBefore.isBefore(oneYearAgo)) {
      throw ArgumentError(
        'notBefore ($notBefore) must not be more than 1 year in the past',
      );
    }
  }

  /// Returns `true` if this is a self-signed certificate request
  /// (subject key == issuer key).
  bool get isSelfSigned =>
      subjectPublicKey.publicKeyPem == issuerPrivateKey.publicKeyPem &&
      subject.commonName == issuer.commonName;
}
