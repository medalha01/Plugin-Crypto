library;

import 'dart:typed_data';

import 'models/crypto_result.dart';
import 'models/ocsp_data.dart';
import 'flows/revocation/ocsp_verifier.dart';
import 'flows/revocation/revocation_verifier.dart';
import 'crypto_context.dart';

class OcspOperations {
  final OcspVerifier _verifier;

  /// Creates [OcspOperations] using the given [CryptoContext].
  OcspOperations(CryptoContext ctx) : _verifier = OpenSslOcspVerifier(ctx);

  CryptoResult<Uint8List> buildOcspRequest(
    Uint8List cert,
    Uint8List issuerCert,
  ) => _verifier.buildOcspRequest(cert, issuerCert);

  CryptoResult<OcspResponse> verifyOcspResponse(
    Uint8List ocspRespBytes,
    Uint8List issuerCert,
  ) => _verifier.verifyOcspResponse(ocspRespBytes, issuerCert);
}
