library;

import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/native_loader.dart';
import '../ffi/openssl_bindings.dart';
import 'aes_operations.dart';
import 'asymmetric_operations.dart';
import 'cms_operations.dart';
import 'crl_operations.dart';
import 'csr_operations.dart';
import 'crypto_data.dart';
import 'crypto_operations.dart';
import 'models/crl_data.dart';
import 'models/crypto_result.dart';
import 'models/csr_data.dart';
import 'models/ocsp_data.dart';
import 'models/ts_data.dart';
import 'ocsp_operations.dart';
import 'plugin_crypto_context.dart';
import 'timestamp_operations.dart';
import 'utils/openssl_error.dart';
import 'x509_operations.dart';

export 'crypto_data.dart';
export 'models/crl_data.dart';
export 'models/crypto_result.dart';
export 'models/csr_data.dart';
export 'models/ocsp_data.dart';
export 'models/ts_data.dart';

class PluginCryptoAPI {
  static PluginCryptoAPI? _instance;
  late final OpenSslBindings _b;
  late final CryptoOperations _crypto;
  late final AesOperations _aes;
  late final AsymmetricOperations _asymmetric;
  late final X509Operations _x509;
  late final CmsOperations _cms;
  late final CrlOperations _crl;
  late final OcspOperations _ocsp;
  late final CsrOperations _csr;
  late final TimestampOperations _timestamp;

  PluginCryptoAPI._() {
    _b = OpenSslBindings.create(loadCrypto(), loadSsl());
    final version = _b.openSSLVersion(0).toDartString();
    if (!version.startsWith('OpenSSL 4.')) {
      throw StateError(
        'PluginCrypto requires OpenSSL 4.x, but loaded: $version',
      );
    }
    final ctx = PluginCryptoContext(_b);
    _crypto = CryptoOperations(_b);
    _aes = AesOperations(_b);
    _asymmetric = AsymmetricOperations(_b);
    _x509 = X509Operations(_b);
    _cms = CmsOperations(_b);
    _crl = CrlOperations(ctx);
    _ocsp = OcspOperations(ctx);
    _csr = CsrOperations(ctx);
    _timestamp = TimestampOperations(ctx);
  }

  /// Acessor singleton. Inicializa as bindings FFI na primeira chamada.
  static PluginCryptoAPI get instance {
    _instance ??= PluginCryptoAPI._();
    return _instance!;
  }


  /// Retorna a string de versão do OpenSSL.
  String getOpenSSLVersion() {
    return _b.openSSLVersion(0).toDartString();
  }


  /// Gera [length] bytes aleatórios criptograficamente seguros.
  Uint8List randomBytes(int length) => _crypto.randomBytes(length);


  Uint8List sha256(Uint8List data) => _crypto.sha256(data);
  Uint8List sha512(Uint8List data) => _crypto.sha512(data);
  Uint8List sha3_256(Uint8List data) => _crypto.sha3_256(data);
  Uint8List sha3_512(Uint8List data) => _crypto.sha3_512(data);


  /// Criptografa AES-128-CBC. [key] deve ter 16 bytes, [iv] deve ter 16 bytes.
  Uint8List aes128CbcEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext,
  ) => _aes.aes128CbcEncrypt(key, iv, plaintext);

  /// Descriptografa AES-128-CBC.
  Uint8List aes128CbcDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
  ) => _aes.aes128CbcDecrypt(key, iv, ciphertext);

  /// Criptografa AES-256-CBC. [key] deve ter 32 bytes, [iv] deve ter 16 bytes.
  Uint8List aes256CbcEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext,
  ) => _aes.aes256CbcEncrypt(key, iv, plaintext);

  /// Descriptografa AES-256-CBC.
  Uint8List aes256CbcDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
  ) => _aes.aes256CbcDecrypt(key, iv, ciphertext);

  /// Criptografa AES-128-GCM. Retorna [AesGcmResult] com texto cifrado e tag de 16 bytes.
  AesGcmResult aes128GcmEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext, {
    Uint8List? aad,
  }) => _aes.aes128GcmEncrypt(key, iv, plaintext, aad: aad);

  /// Descriptografa AES-128-GCM. [tag] deve ter 16 bytes.
  Uint8List aes128GcmDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List tag, {
    Uint8List? aad,
  }) => _aes.aes128GcmDecrypt(key, iv, ciphertext, tag, aad: aad);

  /// Criptografa AES-256-GCM.
  AesGcmResult aes256GcmEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext, {
    Uint8List? aad,
  }) => _aes.aes256GcmEncrypt(key, iv, plaintext, aad: aad);

  /// Descriptografa AES-256-GCM.
  Uint8List aes256GcmDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List tag, {
    Uint8List? aad,
  }) => _aes.aes256GcmDecrypt(key, iv, ciphertext, tag, aad: aad);


  /// Gera um par de chaves RSA de tamanho [bits] (ex.: 2048, 4096).
  KeyPair generateRsaKeyPair(int bits) => _asymmetric.generateRsaKeyPair(bits);


  /// Gera um par de chaves EC para [curveName] (ex.: "prime256v1", "secp384r1").
  KeyPair generateEcKeyPair(String curveName) =>
      _asymmetric.generateEcKeyPair(curveName);


  /// Assina [data] usando uma chave privada (PEM ou DER).
  Uint8List sign(
    Uint8List data,
    Uint8List privateKeyPem, {
    String hashAlgorithm = 'sha256',
  }) => _asymmetric.sign(data, privateKeyPem, hashAlgorithm: hashAlgorithm);

  /// Verifica [signature] de [data] usando uma chave pública (PEM ou DER).
  bool verify(
    Uint8List data,
    Uint8List publicKeyPem,
    Uint8List signature, {
    String hashAlgorithm = 'sha256',
  }) => _asymmetric.verify(
    data,
    publicKeyPem,
    signature,
    hashAlgorithm: hashAlgorithm,
  );


  /// Criptografa RSA-OAEP com SHA-256.
  Uint8List rsaEncrypt(Uint8List publicKeyPem, Uint8List plaintext) =>
      _asymmetric.rsaEncrypt(publicKeyPem, plaintext);

  /// Descriptografa RSA-OAEP com SHA-256.
  Uint8List rsaDecrypt(Uint8List privateKeyPem, Uint8List ciphertext) =>
      _asymmetric.rsaDecrypt(privateKeyPem, ciphertext);


  ({Uint8List ciphertext, Uint8List sharedSecret}) mlKemEncapsulate(
    Uint8List publicKeyPem,
  ) {
    return _asymmetric.mlKemEncapsulate(publicKeyPem);
  }

  Uint8List mlKemDecapsulate(
    Uint8List privateKeyPem,
    Uint8List ciphertext,
  ) {
    return _asymmetric.mlKemDecapsulate(privateKeyPem, ciphertext);
  }


  /// Analisa um certificado X.509 a partir de PEM ou DER.
  X509Certificate parseX509Certificate(Uint8List certData) =>
      _x509.parseX509Certificate(certData);

  /// Valida uma cadeia de certificados.
  bool verifyX509Certificate(Uint8List cert, Uint8List caCert) =>
      _x509.verifyX509Certificate(cert, caCert);


  /// Assina dados usando um certificado e chave privada, retornando CMS/PKCS#7
  /// dados assinados em DER.
  Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem) =>
      _cms.cmsSign(data, certPem, keyPem);

  /// Verifica dados assinados CMS/PKCS#7 contra certificados confiáveis.
  bool cmsVerifySignature(Uint8List signedData) =>
      _cms.cmsVerifySignature(signedData);

  bool cmsVerifyTrusted(
    Uint8List signedData, {
    required Uint8List trustAnchor,
    List<Uint8List> intermediates = const [],
  }) => _cms.cmsVerifyTrusted(
    signedData,
    trustAnchor: trustAnchor,
    intermediates: intermediates,
  );

  @Deprecated(
    'Use cmsVerifySignature or cmsVerifyTrusted to make trust semantics explicit.',
  )
  bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert}) =>
      _cms.cmsVerify(signedData, trustedCert: trustedCert);

  /// Criptografa dados para o(s) destinatário(s) identificado(s) por [certPem].
  /// Retorna CMS/PKCS#7 EnvelopedData em formato DER.
  Uint8List cmsEncrypt(Uint8List data, Uint8List certPem) =>
      _cms.cmsEncrypt(data, certPem);

  /// Descriptografa CMS/PKCS#7 EnvelopedData usando o certificado e
  /// chave privada do destinatário.
  Uint8List cmsDecrypt(
    Uint8List encryptedData,
    Uint8List certPem,
    Uint8List keyPem,
  ) => _cms.cmsDecrypt(encryptedData, certPem, keyPem);


  @Deprecated('Use cmsSignCadesBes; CAdES-BES attributes are mandatory.')
  Uint8List cmsSignCades(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
    bool addSigningTime = true,
    bool addMessageDigest = true,
  }) => _cms.cmsSignCades(
    data,
    certPem,
    keyPem,
    caCertPem: caCertPem,
    intermediates: intermediates,
    addSigningTime: addSigningTime,
    addMessageDigest: addMessageDigest,
  );

  Uint8List cmsSignCadesBes(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
  }) => _cms.cmsSignCadesBes(
    data,
    certPem,
    keyPem,
    caCertPem: caCertPem,
    intermediates: intermediates,
  );


  CryptoResult<CrlInfo> parseCrl(Uint8List crlData) =>
      _crl.parseCrl(crlData);

  /// Verifica se [crlData] está criptograficamente assinado por [caCert].
  CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert) =>
      _crl.verifyCrlSignature(crlData, caCert);

  /// Verifica se [certData] aparece na lista de revogados de [crlData].
  CryptoResult<CertificateRevocationStatus> checkRevocation(
    Uint8List certData,
    Uint8List crlData,
  ) => _crl.checkRevocation(certData, crlData);


  CryptoResult<Uint8List> buildOcspRequest(
    Uint8List cert,
    Uint8List issuerCert,
  ) => _ocsp.buildOcspRequest(cert, issuerCert);

  CryptoResult<OcspResponse> verifyOcspResponse(
    Uint8List ocspRespBytes,
    Uint8List issuerCert,
  ) => _ocsp.verifyOcspResponse(ocspRespBytes, issuerCert);


  CryptoResult<CsrData> generateCsr(CsrRequest request) =>
      _csr.generate(request);


  CryptoResult<Uint8List> createTimestampRequest(
    Uint8List data, {
    String hashAlgorithm = 'sha256',
    Uint8List? nonce,
  }) => _timestamp.createRequest(data,
      hashAlgorithm: hashAlgorithm, nonce: nonce);

  CryptoResult<TimestampResponse> verifyTimestampResponse(
    Uint8List responseData, {
    Uint8List? cert,
  }) => _timestamp.verifyResponse(responseData, cert: cert);

  CryptoResult<bool> verifyTimestamp(
    Uint8List tokenData,
    Uint8List data,
  ) => _timestamp.verify(tokenData, data);


  /// Retorna a última string de erro do OpenSSL, ou null se não houver erro.
  String? getLastError() => getOpenSslError(_b);

  /// Limpa a fila de erros do OpenSSL.
  void clearErrors() => _b.errClearError();
}
