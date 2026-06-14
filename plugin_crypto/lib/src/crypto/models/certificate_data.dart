library;

import 'dart:typed_data';

import '../crypto_api.dart';

/// The complete output of a certificate creation operation.
class CertificateData {
  /// The certificate as raw DER bytes.
  final Uint8List derBytes;

  /// The certificate as a PEM string.
  final String pemString;

  /// Parsed representation for field-level access (subject, issuer, dates, etc).
  final X509Certificate parsed;

  /// Distinguished Name of the subject as an oneline string.
  final String subjectDn;

  /// Distinguished Name of the issuer as an oneline string.
  final String issuerDn;

  /// Certificate validity start.
  final DateTime notBefore;

  /// Certificate validity end.
  final DateTime notAfter;

  const CertificateData({
    required this.derBytes,
    required this.pemString,
    required this.parsed,
    required this.subjectDn,
    required this.issuerDn,
    required this.notBefore,
    required this.notAfter,
  });
}

/// Describes an X.509 v3 extension.
class X509Extension {
  /// The extension OID as a dotted string (e.g. "2.5.29.19" for BasicConstraints).
  final String oid;

  /// The extension value in its native string representation.
  final String value;

  /// Whether the extension is marked critical.
  final bool critical;

  const X509Extension({
    required this.oid,
    required this.value,
    this.critical = false,
  });
}

/// Parsed BasicConstraints X.509 v3 extension.
class BasicConstraints {
  /// Whether the certificate is a CA.
  final bool isCa;

  final int? pathLen;

  const BasicConstraints({required this.isCa, this.pathLen});
}

class X509ParsedExtensions {
  /// Key Usage flags (e.g. "digitalSignature", "keyCertSign").
  final List<String>? keyUsage;

  /// Basic Constraints (CA flag + path length).
  final BasicConstraints? basicConstraints;

  /// Subject Alternative Names (DNS, IP, email, URI).
  final List<String>? subjectAltNames;

  /// CRL Distribution Point URLs extracted from the CRL Distribution Points
  /// extension (OID 2.5.29.31).
  final List<String>? crlDistributionPoints;

  /// OCSP Responder URLs extracted from the Authority Information Access
  /// extension (OID 1.3.6.1.5.5.7.1.1).
  final List<String>? ocspResponders;

  const X509ParsedExtensions({
    this.keyUsage,
    this.basicConstraints,
    this.subjectAltNames,
    this.crlDistributionPoints,
    this.ocspResponders,
  });
}
