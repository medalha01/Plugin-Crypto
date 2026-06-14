library;

import 'dart:typed_data';

/// The status of a timestamp response.
enum TimestampStatus {
  /// The timestamp token was granted.
  granted,

  /// The timestamp token was granted with modifications.
  grantedWithMods,

  /// The timestamp request was rejected.
  rejection,

  /// The TSA is waiting for additional input.
  waiting,

  /// The TSA has revoked its certificate.
  revocationWarning,

  /// The TSA has sent a revocation notification.
  revocationNotification,
}

/// Parsed RFC 3161 timestamp response (TimeStampResp).
class TimestampResponse {
  /// The PKI status of the response (granted, rejected, etc.).
  final TimestampStatus status;

  /// Human-readable status string (may be multi-line).
  final String? statusString;

  /// The timestamp token as DER-encoded CMS SignedData, if [status] is
  /// [TimestampStatus.granted] or [TimestampStatus.grantedWithMods].
  final Uint8List? tokenData;

  /// When the timestamp was generated (from the token's signing time).
  final DateTime? genTime;

  /// The serial number of the timestamp token.
  final String? serialNumber;

  /// The hash algorithm OID used for the message imprint.
  final String? hashAlgorithmOid;

  /// The message imprint (hash) that was timestamped (from the token TSTInfo).
  final Uint8List? messageImprint;

  /// The nonce from the request, echoed back in the response.
  final int? nonce;

  /// The TSA's policy OID under which the token was issued.
  final String? policyOid;

  /// The accuracy (seconds, millis, micros) of the timestamp.
  final TimestampAccuracy? accuracy;

  const TimestampResponse({
    required this.status,
    this.statusString,
    this.tokenData,
    this.genTime,
    this.serialNumber,
    this.hashAlgorithmOid,
    this.messageImprint,
    this.nonce,
    this.policyOid,
    this.accuracy,
  });

  /// Whether the timestamp was granted.
  bool get isGranted =>
      status == TimestampStatus.granted ||
      status == TimestampStatus.grantedWithMods;
}

/// TSA-specified accuracy for the timestamp.
class TimestampAccuracy {
  /// Accuracy in seconds.
  final int? seconds;

  /// Accuracy in milliseconds.
  final int? millis;

  /// Accuracy in microseconds.
  final int? micros;

  const TimestampAccuracy({this.seconds, this.millis, this.micros});
}

/// Hash algorithm identifiers for RFC 3161.
class TsHashAlgorithm {
  /// OID for SHA-256 (2.16.840.1.101.3.4.2.1).
  static const oidSha256 = '2.16.840.1.101.3.4.2.1';

  /// OID for SHA-512 (2.16.840.1.101.3.4.2.3).
  static const oidSha512 = '2.16.840.1.101.3.4.2.3';

  /// OID for SHA-384 (2.16.840.1.101.3.4.2.2).
  static const oidSha384 = '2.16.840.1.101.3.4.2.2';

  /// DER-encoded AlgorithmIdentifier for SHA-256.
  static final Uint8List derSha256 = Uint8List.fromList([
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
  ]);

  /// DER-encoded AlgorithmIdentifier for SHA-512.
  static final Uint8List derSha512 = Uint8List.fromList([
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
  ]);

  /// DER-encoded AlgorithmIdentifier for SHA-384.
  static final Uint8List derSha384 = Uint8List.fromList([
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
  ]);

  /// Returns the DER AlgorithmIdentifier for the given hash name.
  static Uint8List derForAlgorithm(String algorithm) {
    switch (algorithm) {
      case 'sha256':
        return derSha256;
      case 'sha512':
        return derSha512;
      case 'sha384':
        return derSha384;
      default:
        return derSha256;
    }
  }

  /// Returns the hash output length in bytes.
  static int hashLength(String algorithm) {
    switch (algorithm) {
      case 'sha256':
        return 32;
      case 'sha512':
        return 64;
      case 'sha384':
        return 48;
      default:
        return 32;
    }
  }
}
