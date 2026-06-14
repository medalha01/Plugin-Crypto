library;

/// A single entry in a Certificate Revocation List.
class RevokedEntry {
  /// The serial number of the revoked certificate as a hex string.
  final String serialNumber;

  /// The date and time when the certificate was revoked.
  final DateTime revocationDate;

  /// The CRL reason code (e.g. 0=unspecified, 1=keyCompromise), or `null`
  /// if no reason extension is present.
  final int? reason;

  const RevokedEntry({
    required this.serialNumber,
    required this.revocationDate,
    this.reason,
  });
}

/// Parsed information from a Certificate Revocation List (CRL).
class CrlInfo {
  /// The date this CRL was last updated (thisUpdate).
  final DateTime lastUpdate;

  /// The date this CRL will next be updated (nextUpdate).
  final DateTime nextUpdate;

  /// The Distinguished Name of the CRL issuer.
  final String issuer;

  /// The list of revoked certificate entries contained in this CRL.
  final List<RevokedEntry> revoked;

  const CrlInfo({
    required this.lastUpdate,
    required this.nextUpdate,
    required this.issuer,
    this.revoked = const [],
  });
}

/// The revocation status of a certificate as determined by CRL or OCSP check.
class CertificateRevocationStatus {
  /// Whether the certificate has been revoked.
  final bool isRevoked;

  /// The date of revocation (if revoked), otherwise null.
  final DateTime? revocationDate;

  /// The CRL reason code (if available), otherwise null.
  final int? reasonCode;

  const CertificateRevocationStatus({
    required this.isRevoked,
    this.revocationDate,
    this.reasonCode,
  });

  /// Convenience for a non-revoked status.
  static const notRevoked = CertificateRevocationStatus(isRevoked: false);
}
