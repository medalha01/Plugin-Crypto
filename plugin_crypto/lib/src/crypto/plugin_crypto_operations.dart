/// Concrete implementation of [CryptographicOperations] that delegates to
/// [PluginCryptoAPI] for all operations.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'crypto_api.dart';
import 'crypto_context.dart';
import 'crypto_data.dart';
import 'models/certificate_data.dart';
import 'utils/bio_utils.dart';
import 'utils/openssl_error.dart';

class PluginCryptoOperations implements CryptographicOperations {
  final OpenSslBindings _b;

  PluginCryptoOperations(this._b);

  PluginCryptoAPI get _api => PluginCryptoAPI.instance;


  @override
  KeyPair generateRsaKeyPair(int bits) {
    if (bits < 1024 || bits > 16384 || bits % 1024 != 0) {
      throw ArgumentError(
        'RSA bits must be >= 1024, <= 16384, and multiple of 1024',
      );
    }
    return _api.generateRsaKeyPair(bits);
  }

  @override
  KeyPair generateEcKeyPair(String curve) {
    if (curve.isEmpty) throw ArgumentError('curve must be non-empty');
    return _api.generateEcKeyPair(curve);
  }


  @override
  Uint8List sha256(Uint8List data) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    return _api.sha256(data);
  }

  @override
  Uint8List sha384(Uint8List data) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    return _digest(data, _b.evpSha384(), 48);
  }

  @override
  Uint8List sha512(Uint8List data) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    return _api.sha512(data);
  }


  @override
  Uint8List sign(
    Uint8List data,
    Uint8List privateKeyPem, {
    String hashAlgorithm = 'sha256',
  }) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    if (privateKeyPem.isEmpty)
      throw ArgumentError('privateKeyPem must be non-empty');
    return _api.sign(data, privateKeyPem, hashAlgorithm: hashAlgorithm);
  }

  @override
  bool verify(
    Uint8List data,
    Uint8List publicKeyPem,
    Uint8List signature, {
    String hashAlgorithm = 'sha256',
  }) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    if (publicKeyPem.isEmpty)
      throw ArgumentError('publicKeyPem must be non-empty');
    if (signature.isEmpty) throw ArgumentError('signature must be non-empty');
    return _api.verify(
      data,
      publicKeyPem,
      signature,
      hashAlgorithm: hashAlgorithm,
    );
  }


  @override
  Uint8List parseX509ToDer(Uint8List certBytes) {
    if (certBytes.isEmpty) throw ArgumentError('certBytes must be non-empty');
    if (certBytes[0] == 0x30) return certBytes;
    final bio = bioFromData(_b, certBytes);
    if (bio == nullptr)
      throw StateError('Failed to create BIO for parseX509ToDer');
    try {
      final x509 = _b.pemReadBioX509(bio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) {
        final err = getOpenSslError(_b);
        _b.errClearError();
        throw StateError(
          'Failed to parse PEM certificate${err != null ? ': $err' : ''}',
        );
      }
      try {
        final derBio = _b.bioNew(_b.bioSMem());
        if (derBio == nullptr) throw StateError('Failed to create DER BIO');
        try {
          _check1(_b.i2dX509Bio(derBio, x509), 'i2d_X509_bio');
          return bioToBytes(_b, derBio);
        } finally {
          _b.bioFree(derBio);
        }
      } finally {
        _b.x509Free(x509);
      }
    } finally {
      _b.bioFree(bio);
    }
  }

  @override
  CertificateData parseX509Certificate(Uint8List certBytes) {
    if (certBytes.isEmpty) throw ArgumentError('certBytes must be non-empty');
    final parsed = _api.parseX509Certificate(certBytes);

    final der = parseX509ToDer(certBytes);

    final pemBio = _b.bioNew(_b.bioSMem());
    if (pemBio == nullptr) throw StateError('Failed to create PEM BIO');
    try {
      final derBio = bioFromData(_b, der);
      if (derBio == nullptr) throw StateError('Failed to create DER BIO');
      try {
        final x509 = _b.d2iX509Bio(derBio, nullptr);
        if (x509 == nullptr)
          throw StateError('Failed to parse DER certificate');
        try {
          _check1(_b.pemWriteBioX509(pemBio, x509), 'PEM_write_bio_X509');
          final pemString = bioToString(_b, pemBio);
          return CertificateData(
            derBytes: der,
            pemString: pemString,
            parsed: parsed,
            subjectDn: parsed.subject,
            issuerDn: parsed.issuer,
            notBefore: parsed.notBefore,
            notAfter: parsed.notAfter,
          );
        } finally {
          _b.x509Free(x509);
        }
      } finally {
        _b.bioFree(derBio);
      }
    } finally {
      _b.bioFree(pemBio);
    }
  }


  @override
  Uint8List cmsSign(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    List<Uint8List>? caCerts,
    bool detached = false,
  }) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    if (certPem.isEmpty) throw ArgumentError('certPem must be non-empty');
    if (keyPem.isEmpty) throw ArgumentError('keyPem must be non-empty');
    if (caCerts == null || caCerts.isEmpty) {
      return _api.cmsSign(data, certPem, keyPem);
    }
    return _api.cmsSign(data, certPem, keyPem);
  }

  @override
  @Deprecated(
    'Use cmsVerifySignature or cmsVerifyTrusted to make trust semantics explicit.',
  )
  bool cmsVerify(
    Uint8List signedData, {
    Uint8List? content,
    Uint8List? caCert,
    bool noSignerCertVerify = false,
  }) {
    if (signedData.isEmpty) throw ArgumentError('signedData must be non-empty');
    return _api.cmsVerify(signedData, trustedCert: caCert);
  }

  @override
  bool cmsVerifySignature(Uint8List signedData) {
    if (signedData.isEmpty) throw ArgumentError('signedData must be non-empty');
    return _api.cmsVerifySignature(signedData);
  }

  @override
  bool cmsVerifyTrusted(
    Uint8List signedData, {
    required Uint8List trustAnchor,
    List<Uint8List> intermediates = const [],
  }) {
    if (signedData.isEmpty) throw ArgumentError('signedData must be non-empty');
    if (trustAnchor.isEmpty) throw ArgumentError('trustAnchor must be non-empty');
    return _api.cmsVerifyTrusted(
      signedData,
      trustAnchor: trustAnchor,
      intermediates: intermediates,
    );
  }

  @override
  Uint8List cmsEncrypt(Uint8List data, List<Uint8List> recipientCerts) {
    if (data.isEmpty) throw ArgumentError('data must be non-empty');
    if (recipientCerts.isEmpty)
      throw ArgumentError('recipientCerts must be non-empty');
    return _api.cmsEncrypt(data, recipientCerts.first);
  }

  @override
  Uint8List cmsDecrypt(
    Uint8List encryptedData,
    Uint8List recipientKeyPem,
    Uint8List recipientCertPem,
  ) {
    if (encryptedData.isEmpty)
      throw ArgumentError('encryptedData must be non-empty');
    if (recipientKeyPem.isEmpty)
      throw ArgumentError('recipientKeyPem must be non-empty');
    if (recipientCertPem.isEmpty)
      throw ArgumentError('recipientCertPem must be non-empty');
    return _api.cmsDecrypt(encryptedData, recipientCertPem, recipientKeyPem);
  }


  Uint8List _digest(Uint8List data, Pointer<Void> md, int digestLen) {
    final ctx = _b.evpMdCtxNew();
    if (ctx == nullptr) throw StateError('EVP_MD_CTX_new failed');
    try {
      _check1(_b.evpDigestInitEx(ctx, md, nullptr), 'EVP_DigestInit_ex');
      final dp = calloc<Uint8>(data.length);
      try {
        dp.asTypedList(data.length).setAll(0, data);
        _check1(
          _b.evpDigestUpdate(ctx, dp.cast(), data.length),
          'EVP_DigestUpdate',
        );
      } finally {
        calloc.free(dp);
      }
      final mdBuf = calloc<Uint8>(digestLen);
      final mdLen = calloc<Uint32>();
      try {
        _check1(_b.evpDigestFinalEx(ctx, mdBuf, mdLen), 'EVP_DigestFinal_ex');
        return Uint8List.fromList(mdBuf.asTypedList(digestLen));
      } finally {
        calloc.free(mdBuf);
        calloc.free(mdLen);
      }
    } finally {
      _b.evpMdCtxFree(ctx);
    }
  }

  void _check1(int result, String op) {
    if (result != 1) {
      final err = getOpenSslError(_b);
      _b.errClearError();
      throw StateError('$op failed${err != null ? ': $err' : ''}');
    }
  }
}
