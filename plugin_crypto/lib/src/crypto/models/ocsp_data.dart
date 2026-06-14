library;

/// Certificate revocation status as reported by an OCSP responder.
enum CertificateStatus {
  /// The certificate has not been revoked.
  good,

  /// The certificate has been revoked.
  revoked,

  /// The certificate status is unknown (responder doesn't have info).
  unknown,
}

/// Parsed OCSP response containing the certificate status and validity
/// timestamps.
class OcspResponse {
  /// Revocation status of the queried certificate.
  final CertificateStatus status;

  /// Time at which the OCSP response was produced.
  final DateTime? producedAt;

  /// Start of the validity period for this response.
  final DateTime? thisUpdate;

  /// End of the validity period for this response.
  final DateTime? nextUpdate;

  const OcspResponse({
    required this.status,
    this.producedAt,
    this.thisUpdate,
    this.nextUpdate,
  });
}
