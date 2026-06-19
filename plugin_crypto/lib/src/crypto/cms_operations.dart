library;

import 'dart:ffi';
import 'dart:typed_data';

import '../ffi/openssl_bindings.dart';
import 'utils/bio_utils.dart';
import 'utils/openssl_error.dart';
import 'utils/secret_memory.dart';

/// CMS/PKCS#7 cryptographic message operations.
class CmsOperations {
  final OpenSslBindings _b;

  CmsOperations(this._b);


  /// CMS/PKCS#7 flags.
  static const int _cmsNoSignerCertVerify = 0x20;
  static const int _cmsBinary = 0x80;
  static const int _cmsCades = 0x100000;

  /// Assina dados usando um certificado e chave privada, retornando CMS/PKCS#7
  /// dados assinados em DER.
  Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem) {
    final x509 = _loadCertificate(certPem, 'CMS signer certificate');
    try {
      final pkey = _loadPrivateKey(keyPem);
      try {
        final inBio = bioFromData(_b, data);
        if (inBio == nullptr) _fail('BIO_new(cmsSign data)');
        try {
          final cms = _b.cmsSign(x509, pkey, nullptr, inBio, _cmsBinary);
          if (cms == nullptr) _fail('CMS_sign');
          try {
            return _cmsToDer(cms);
          } finally {
            _b.cmsContentInfoFree(cms);
          }
        } finally {
          _b.bioFree(inBio);
        }
      } finally {
        _b.evpPkeyFree(pkey);
      }
    } finally {
      _b.x509Free(x509);
    }
  }

  /// Verifica dados assinados CMS/PKCS#7 contra certificados confiáveis.
  bool cmsVerifySignature(Uint8List signedData) {
    return _verifyCms(
      signedData,
      flags: _cmsNoSignerCertVerify,
    );
  }

  bool cmsVerifyTrusted(
    Uint8List signedData, {
    required Uint8List trustAnchor,
    List<Uint8List> intermediates = const [],
  }) {
    final store = _b.x509StoreNew();
    if (store == nullptr) _fail('X509_STORE_new');
    try {
      final anchor = _loadCertificate(trustAnchor, 'CMS trust anchor');
      try {
        _check1(_b.x509StoreAddCert(store, anchor), 'X509_STORE_add_cert');
        return _withCertificateStack(
          intermediates,
          (stack) => _verifyCms(
            signedData,
            store: store,
            untrustedCertificates: stack,
            flags: 0,
          ),
        );
      } finally {
        _b.x509Free(anchor);
      }
    } finally {
      _b.x509StoreFree(store);
    }
  }

  @Deprecated(
    'Use cmsVerifySignature or cmsVerifyTrusted to make trust semantics explicit.',
  )
  bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert}) {
    if (trustedCert == null) return cmsVerifySignature(signedData);
    return cmsVerifyTrusted(signedData, trustAnchor: trustedCert);
  }

  Uint8List cmsEncrypt(Uint8List data, Uint8List certPem) {
    final x509 = _loadCertificate(certPem, 'CMS recipient certificate');
    try {
      final certs = _b.osslSkNewNull();
      if (certs == nullptr) _fail('OPENSSL_sk_new_null');
      try {
        _check1(_b.osslSkPush(certs, x509), 'OPENSSL_sk_push');
        final inBio = bioFromData(_b, data);
        if (inBio == nullptr) _fail('BIO_new(cmsEncrypt data)');
        try {
          final cms = _b.cmsEncrypt(certs, inBio, _b.evpAes256Cbc(), 0);
          if (cms == nullptr) _fail('CMS_encrypt');
          try {
            return _cmsToDer(cms);
          } finally {
            _b.cmsContentInfoFree(cms);
          }
        } finally {
          _b.bioFree(inBio);
        }
      } finally {
        _b.osslSkFree(certs);
      }
    } finally {
      _b.x509Free(x509);
    }
  }

  Uint8List cmsDecrypt(
    Uint8List encryptedData,
    Uint8List certPem,
    Uint8List keyPem,
  ) {
    final cms = _loadCms(encryptedData);
    try {
        final pkey = _loadPrivateKey(keyPem);
        try {
          final x509 = _loadCertificate(certPem, 'CMS recipient certificate');
          try {
            final outBio = _b.bioNew(_b.bioSMem());
            if (outBio == nullptr) _fail('BIO_new(cmsDecrypt)');
            try {
              _check1(
                _b.cmsDecrypt(cms, pkey, x509, nullptr, outBio, 0),
                'CMS_decrypt',
              );
              return bioToBytes(_b, outBio);
            } finally {
              _b.bioFree(outBio);
            }
          } finally {
            _b.x509Free(x509);
          }
        } finally {
          _b.evpPkeyFree(pkey);
        }
    } finally {
      _b.cmsContentInfoFree(cms);
    }
  }

  @Deprecated('Use cmsSignCadesBes; CAdES-BES attributes are mandatory.')
  Uint8List cmsSignCades(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
    bool addSigningTime = true,
    bool addMessageDigest = true,
  }) {
    if (!addSigningTime || !addMessageDigest) {
      throw ArgumentError(
        'CAdES-BES requires signingTime and messageDigest; disabling either '
        'attribute is not supported.',
      );
    }
    return cmsSignCadesBes(
      data,
      certPem,
      keyPem,
      caCertPem: caCertPem,
      intermediates: intermediates,
    );
  }

  Uint8List cmsSignCadesBes(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
  }) {
    if (data.isEmpty) {
      throw ArgumentError('data must be non-empty');
    }
    if (certPem.isEmpty || keyPem.isEmpty) {
      throw ArgumentError('certPem and keyPem must be non-empty');
    }

    final x509 = _loadCertificate(certPem, 'CAdES signer certificate');
    try {
      final pkey = _loadPrivateKey(keyPem);
      try {
        final inBio = bioFromData(_b, data);
        if (inBio == nullptr) _fail('BIO_new(cmsSignCades data)');
        try {
          final chain = <Uint8List>[
            if (caCertPem != null && caCertPem.isNotEmpty) caCertPem,
            ...?intermediates,
          ];
          return _withCertificateStack(chain, (certs) {
            final cms = _b.cmsSign(
              x509,
              pkey,
              certs,
              inBio,
              _cmsBinary | _cmsCades,
            );
            if (cms == nullptr) _fail('CMS_sign(CAdES)');
            try {
              return _cmsToDer(cms);
            } finally {
              _b.cmsContentInfoFree(cms);
            }
          });
        } finally {
          _b.bioFree(inBio);
        }
      } finally {
        _b.evpPkeyFree(pkey);
      }
    } finally {
      _b.x509Free(x509);
    }
  }


  Uint8List _cmsToDer(CMS_ContentInfo cms) {
    final bio = _b.bioNew(_b.bioSMem());
    if (bio == nullptr) _fail('BIO_new(CMS DER)');
    try {
      _check1(_b.i2dCmsBio(bio, cms), 'i2d_CMS_bio');
      return bioToBytes(_b, bio);
    } finally {
      _b.bioFree(bio);
    }
  }

  EVP_PKEY _loadPrivateKey(Uint8List data) {
    return withSecretBytes(_b, data, (pointer) {
      final bio = _b.bioNewMemBuf(pointer.cast(), data.length);
      if (bio == nullptr) _fail('BIO_new_mem_buf(_loadPrivateKey)');
      try {
        final pkey = _b.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
        if (pkey == nullptr) {
          _fail('PEM_read_bio_PrivateKey');
        }
        return pkey;
      } finally {
        _b.bioFree(bio);
      }
    });
  }

  void _check1(int result, String op) {
    if (result != 1) {
      final err = getOpenSslError(_b);
      _b.errClearError();
      throw StateError('$op failed${err != null ? ': $err' : ''}');
    }
  }

  Never _fail(String op) {
    final err = getOpenSslError(_b);
    _b.errClearError();
    throw StateError('$op failed${err != null ? ': $err' : ''}');
  }


  T _withCertificateStack<T>(
    List<Uint8List> certificates,
    T Function(Pointer<Void> stack) action,
  ) {
    if (certificates.isEmpty) return action(nullptr);
    final stack = _b.osslSkNewNull();
    if (stack == nullptr) _fail('OPENSSL_sk_new_null(certs)');
    final loaded = <X509>[];
    try {
      for (final encoded in certificates) {
        final x509 = _loadCertificate(encoded, 'CMS certificate chain');
        loaded.add(x509);
        _check1(_b.osslSkPush(stack, x509.cast()), 'OPENSSL_sk_push(cert)');
      }
      return action(stack);
    } finally {
      for (final x509 in loaded) {
        _b.x509Free(x509);
      }
      _b.osslSkFree(stack);
    }
  }

  X509 _loadCertificate(Uint8List encoded, String operation) {
    final bio = bioFromData(_b, encoded);
    if (bio == nullptr) _fail('BIO_new($operation)');
    try {
      final cert = _b.d2iX509Bio(bio, nullptr);
      if (cert != nullptr) return cert;
      _b.errClearError();
    } finally {
      _b.bioFree(bio);
    }
    final pemBio = bioFromData(_b, encoded);
    if (pemBio == nullptr) _fail('BIO_new($operation PEM)');
    try {
      final cert = _b.pemReadBioX509(pemBio, nullptr, nullptr, nullptr);
      if (cert == nullptr) _fail('$operation is neither DER nor PEM X.509');
      return cert;
    } finally {
      _b.bioFree(pemBio);
    }
  }

  CMS_ContentInfo _loadCms(Uint8List encoded) {
    final derBio = bioFromData(_b, encoded);
    if (derBio == nullptr) _fail('BIO_new(CMS DER)');
    try {
      final cms = _b.d2iCmsBio(derBio, nullptr);
      if (cms != nullptr) return cms;
      _b.errClearError();
    } finally {
      _b.bioFree(derBio);
    }
    final pemBio = bioFromData(_b, encoded);
    if (pemBio == nullptr) _fail('BIO_new(CMS PEM)');
    try {
      final cms = _b.pemReadBioCms(pemBio, nullptr, nullptr, nullptr);
      if (cms == nullptr) _fail('CMS input is neither DER nor PEM');
      return cms;
    } finally {
      _b.bioFree(pemBio);
    }
  }

  bool _verifyCms(
    Uint8List signedData, {
    X509_STORE? store,
    Pointer<Void>? untrustedCertificates,
    required int flags,
  }) {
    final cms = _loadCms(signedData);
    try {
      final result = _b.cmsVerify(
        cms,
        untrustedCertificates ?? nullptr,
        store ?? nullptr,
        nullptr,
        nullptr,
        flags,
      );
      if (result == 1) return true;
      _b.errClearError();
      return false;
    } finally {
      _b.cmsContentInfoFree(cms);
    }
  }

}
