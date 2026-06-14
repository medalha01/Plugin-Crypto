library;

import 'dart:typed_data';

import '../../models/crl_data.dart';
import '../../models/crypto_result.dart';
import '../../models/ocsp_data.dart';

abstract interface class CrlVerifier {
  /// Parses a DER-encoded CRL and returns metadata.
  CryptoResult<CrlInfo> parseCrl(Uint8List crlData);

  /// Verifica se [crlData] está criptograficamente assinado por [caCert].
  CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert);

  /// Verifica se [certData] aparece na lista de revogados de [crlData].
  CryptoResult<CertificateRevocationStatus> checkRevocation(
    Uint8List certData,
    Uint8List crlData,
  );
}

/// Builds OCSP requests and verifies OCSP responses.
abstract interface class OcspVerifier {
  /// Constrói uma requisição OCSP codificada em DER para [cert] emitido por [issuerCert].
  CryptoResult<Uint8List> buildOcspRequest(
    Uint8List cert,
    Uint8List issuerCert,
  );

  /// Verifica uma resposta OCSP contra o [issuerCert] que a assinou.
  CryptoResult<OcspResponse> verifyOcspResponse(
    Uint8List ocspRespBytes,
    Uint8List issuerCert,
  );
}
