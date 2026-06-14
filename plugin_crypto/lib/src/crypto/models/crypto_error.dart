library;

/// Top-level sealed error type for all crypto operations.
sealed class CryptoError {
  const CryptoError._();

  /// Human-readable error message suitable for logging or UI display.
  String get message;
}

class KeygenError extends CryptoError {
  final String keyType;
  final String reason;
  final String? openSslError;

  const KeygenError({
    required this.keyType,
    required this.reason,
    this.openSslError,
  }) : super._();

  @override
  String get message =>
      'Key generation failed ($keyType): $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class CertificateError extends CryptoError {
  final String reason;
  final String? openSslError;

  const CertificateError({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'Certificate creation failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class FileSigningError extends CryptoError {
  final String filePath;
  final String reason;
  final String? openSslError;

  const FileSigningError({
    required this.filePath,
    required this.reason,
    this.openSslError,
  }) : super._();

  @override
  String get message =>
      'File signing failed ($filePath): $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class ValidationError extends CryptoError {
  final String field;
  final String reason;

  const ValidationError({required this.field, required this.reason})
    : super._();

  @override
  String get message => 'Validation failed for "$field": $reason';
}

class ChainValidationError extends CryptoError {
  final String? chainDetail;
  final int? errorDepth;
  final String? openSslError;

  const ChainValidationError({
    this.chainDetail,
    this.errorDepth,
    this.openSslError,
  }) : super._();

  @override
  String get message =>
      'Chain validation failed'
      '${chainDetail != null ? ': $chainDetail' : ''}'
      '${errorDepth != null ? ' at depth $errorDepth' : ''}'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class CrlError extends CryptoError {
  final String reason;
  final String? openSslError;

  const CrlError({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'CRL operation failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class X509ExtensionError extends CryptoError {
  final String? oid;
  final String reason;
  final String? openSslError;

  const X509ExtensionError({this.oid, required this.reason, this.openSslError})
    : super._();

  @override
  String get message =>
      'X.509 extension parsing failed'
      '${oid != null ? ' ($oid)' : ''}: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

/// OCSP client operation failures.
class OcspError extends CryptoError {
  final String reason;
  final String? openSslError;

  const OcspError({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'OCSP operation failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

/// ASN.1 parsing failures.
class Asn1Error extends CryptoError {
  final String reason;
  final String? openSslError;

  const Asn1Error({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'ASN.1 parsing failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

class AesGcmAuthFailure extends CryptoError {
  final String reason;
  final String? openSslError;

  const AesGcmAuthFailure({required this.reason, this.openSslError})
      : super._();

  @override
  String get message =>
      'GCM authentication failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

/// CSR generation failures.
class CsrError extends CryptoError {
  final String reason;
  final String? openSslError;

  const CsrError({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'CSR generation failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

/// RFC 3161 Timestamping operation failures.
class TimestampError extends CryptoError {
  final String reason;
  final String? openSslError;

  const TimestampError({required this.reason, this.openSslError}) : super._();

  @override
  String get message =>
      'Timestamp operation failed: $reason'
      '${openSslError != null ? ' [$openSslError]' : ''}';
}

CryptoError mapExceptionToCryptoError(Object e, String operation) {
  if (e is ArgumentError) {
    return ValidationError(
      field: 'input',
      reason: (e.message as String?) ?? e.toString(),
    );
  }
  if (e is StateError) {
    return KeygenError(keyType: 'unknown', reason: e.message);
  }
  return KeygenError(keyType: 'unknown', reason: '$operation: ${e.toString()}');
}
