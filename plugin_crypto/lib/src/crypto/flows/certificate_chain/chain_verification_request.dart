library;

import 'dart:typed_data';

/// A request to verify a certificate chain.
class ChainVerificationRequest {
  /// The leaf (end-entity) certificate in DER or PEM format.
  final Uint8List leafCert;

  final Uint8List? trustedRoot;

  final List<Uint8List> intermediates;

  final DateTime? verificationTime;

  ChainVerificationRequest({
    required this.leafCert,
    this.trustedRoot,
    this.intermediates = const [],
    this.verificationTime,
  }) {
    validate();
  }

  void validate() {
    if (leafCert.isEmpty) {
      throw ArgumentError('leafCert must not be empty');
    }
    for (var i = 0; i < intermediates.length; i++) {
      if (intermediates[i].isEmpty) {
        throw ArgumentError('intermediates[$i] must not be empty');
      }
    }
    if (trustedRoot != null && trustedRoot!.isEmpty) {
      throw ArgumentError('trustedRoot must not be empty when provided');
    }
    if (verificationTime != null && verificationTime!.isAfter(DateTime.now())) {
      throw ArgumentError('verificationTime must not be in the future');
    }
  }
}
