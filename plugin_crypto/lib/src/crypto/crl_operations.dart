library;

import 'dart:typed_data';

import 'models/crl_data.dart';
import 'models/crypto_result.dart';
import 'flows/revocation/crl_verifier.dart';
import 'flows/revocation/revocation_verifier.dart';
import 'crypto_context.dart';

class CrlOperations {
  final CrlVerifier _verifier;

  /// Creates [CrlOperations] using the given [CryptoContext].
  CrlOperations(CryptoContext ctx) : _verifier = OpenSslCrlVerifier(ctx);

  CryptoResult<CrlInfo> parseCrl(Uint8List crlData) =>
      _verifier.parseCrl(crlData);

  CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert) =>
      _verifier.verifyCrlSignature(crlData, caCert);

  CryptoResult<CertificateRevocationStatus> checkRevocation(
    Uint8List certData,
    Uint8List crlData,
  ) => _verifier.checkRevocation(certData, crlData);
}
