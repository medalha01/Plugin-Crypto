library;

import 'dart:typed_data';

import '../ffi/openssl_bindings.dart';
import 'crypto_data.dart';
import 'models/certificate_data.dart';

/// Unified context providing access to both raw FFI bindings and
/// high-level cryptographic operations.
abstract interface class CryptoContext {
  /// Raw OpenSSL FFI bindings for low-level operations.
  OpenSslBindings get bindings;

  /// High-level cryptographic operations.
  CryptographicOperations get operations;
}

/// High-level cryptographic operations exposed through [CryptoContext].
abstract interface class CryptographicOperations {
  KeyPair generateRsaKeyPair(int bits);
  KeyPair generateEcKeyPair(String curve);

  Uint8List sha256(Uint8List data);
  Uint8List sha384(Uint8List data);
  Uint8List sha512(Uint8List data);

  Uint8List sign(
    Uint8List data,
    Uint8List privateKeyPem, {
    String hashAlgorithm = 'sha256',
  });
  bool verify(
    Uint8List data,
    Uint8List publicKeyPem,
    Uint8List signature, {
    String hashAlgorithm = 'sha256',
  });

  Uint8List parseX509ToDer(Uint8List certBytes);
  CertificateData parseX509Certificate(Uint8List certBytes);

  Uint8List cmsSign(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    List<Uint8List>? caCerts,
    bool detached = false,
  });
  @Deprecated(
    'Use cmsVerifySignature or cmsVerifyTrusted to make trust semantics explicit.',
  )
  bool cmsVerify(
    Uint8List signedData, {
    Uint8List? content,
    Uint8List? caCert,
    bool noSignerCertVerify = false,
  });
  bool cmsVerifySignature(Uint8List signedData);
  bool cmsVerifyTrusted(
    Uint8List signedData, {
    required Uint8List trustAnchor,
    List<Uint8List> intermediates = const [],
  });
  Uint8List cmsEncrypt(Uint8List data, List<Uint8List> recipientCerts);
  Uint8List cmsDecrypt(
    Uint8List encryptedData,
    Uint8List recipientKeyPem,
    Uint8List recipientCertPem,
  );
}
