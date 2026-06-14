library;

import '../../models/crypto_result.dart';
import 'chain_verification_request.dart';

/// The result of a certificate chain verification.
class ChainValidationResult {
  /// Whether the chain is valid and trusted.
  final bool valid;

  /// Human-readable error reason when [valid] is `false`.
  final String? errorReason;

  final int? chainDepth;

  /// The instant at which validation was performed.
  final DateTime validatedAt;

  const ChainValidationResult({
    required this.valid,
    this.errorReason,
    this.chainDepth,
    required this.validatedAt,
  });
}

abstract interface class ChainVerifier {
  /// Verify the certificate chain described by [request].
  CryptoResult<ChainValidationResult> verify(ChainVerificationRequest request);
}
