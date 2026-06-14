library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'utils/bio_utils.dart';
import 'utils/openssl_error.dart';

/// CMS/PKCS#7 cryptographic message operations.
class CmsOperations {
  final OpenSslBindings _b;

  CmsOperations(this._b);


  /// CMS/PKCS#7 flags.
  static const int _cmsBinary = 0x80;
  static const int _cmsNoSignerCertVerify = 0x200;
  static const int _cmsCades = 0x800;

  /// Assina dados usando um certificado e chave privada, retornando CMS/PKCS#7
  /// dados assinados em DER.
  Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem) {
    final certBio = bioFromData(_b, certPem);
    if (certBio == nullptr) _fail('BIO_new(cmsSign cert)');
    try {
      final x509 = _b.pemReadBioX509(certBio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) _fail('PEM_read_bio_X509(cms)');
      try {
        final pkey = _loadPrivateKey(keyPem);
        try {
          final inBio = bioFromData(_b, data);
          if (inBio == nullptr) _fail('BIO_new(cmsSign data)');
          try {
            final cms = _b.cmsSign(x509, pkey, nullptr, inBio, 0);
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
    } finally {
      _b.bioFree(certBio);
    }
  }

  /// Verifica dados assinados CMS/PKCS#7 contra certificados confiáveis.
  bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert}) {
    final store = _b.x509StoreNew();
    if (store == nullptr) _fail('X509_STORE_new');
    try {
      if (trustedCert != null) {
        final caBio = bioFromData(_b, trustedCert);
        if (caBio == nullptr) _fail('BIO_new(cmsVerify CA)');
        try {
          final ca = _b.pemReadBioX509(caBio, nullptr, nullptr, nullptr);
          if (ca != nullptr) {
            _b.x509StoreAddCert(store, ca);
            _b.x509Free(ca);
          }
        } finally {
          _b.bioFree(caBio);
        }
      }
      final cmsBio = bioFromData(_b, signedData);
      if (cmsBio == nullptr) _fail('BIO_new(cmsVerify data)');
      try {
        final cms = _b.pemReadBioCms(cmsBio, nullptr, nullptr, nullptr);
        if (cms == nullptr) _fail('PEM_read_bio_CMS(cmsVerify)');
        try {
          final result = _b.cmsVerify(
            cms,
            nullptr,
            store,
            nullptr,
            nullptr,
            _cmsNoSignerCertVerify,
          );
          return result == 1;
        } finally {
          _b.cmsContentInfoFree(cms);
        }
      } finally {
        _b.bioFree(cmsBio);
      }
    } finally {
      _b.x509StoreFree(store);
    }
  }

  Uint8List cmsEncrypt(Uint8List data, Uint8List certPem) {
    final certBio = bioFromData(_b, certPem);
    if (certBio == nullptr) _fail('BIO_new(cmsEncrypt cert)');
    try {
      final x509 = _b.pemReadBioX509(certBio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) _fail('PEM_read_bio_X509(cmsEncrypt)');
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
    } finally {
      _b.bioFree(certBio);
    }
  }

  Uint8List cmsDecrypt(
    Uint8List encryptedData,
    Uint8List certPem,
    Uint8List keyPem,
  ) {
    final cmsBio = bioFromData(_b, encryptedData);
    if (cmsBio == nullptr) _fail('BIO_new(cmsDecrypt data)');
    try {
      final cms = _b.pemReadBioCms(cmsBio, nullptr, nullptr, nullptr);
      if (cms == nullptr) _fail('PEM_read_bio_CMS(cmsDecrypt)');
      try {
        final pkey = _loadPrivateKey(keyPem);
        try {
          final certBio = bioFromData(_b, certPem);
          if (certBio == nullptr) _fail('BIO_new(cmsDecrypt cert)');
          try {
            final x509 = _b.pemReadBioX509(certBio, nullptr, nullptr, nullptr);
            if (x509 == nullptr) _fail('PEM_read_bio_X509(cmsDecrypt)');
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
            _b.bioFree(certBio);
          }
        } finally {
          _b.evpPkeyFree(pkey);
        }
      } finally {
        _b.cmsContentInfoFree(cms);
      }
    } finally {
      _b.bioFree(cmsBio);
    }
  }

  Uint8List cmsSignCades(
    Uint8List data,
    Uint8List certPem,
    Uint8List keyPem, {
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
    bool addSigningTime = true,
    bool addMessageDigest = true,
  }) {
    if (data.isEmpty) {
      throw ArgumentError('data must be non-empty');
    }
    if (certPem.isEmpty || keyPem.isEmpty) {
      throw ArgumentError('certPem and keyPem must be non-empty');
    }

    final certBio = bioFromData(_b, certPem);
    if (certBio == nullptr) _fail('BIO_new(cmsSignCades cert)');
    try {
      final x509 = _b.pemReadBioX509(certBio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) _fail('PEM_read_bio_X509(cmsSignCades)');
      try {
        final pkey = _loadPrivateKey(keyPem);
        try {
          final inBio = bioFromData(_b, data);
          if (inBio == nullptr) _fail('BIO_new(cmsSignCades data)');
          try {
            final certs = _buildCertStack(
              caCertPem: caCertPem,
              intermediates: intermediates,
            );
            try {
              var flags = _cmsBinary;
              if (addSigningTime) {
                flags |= _cmsCades;
              }

              final cms = _b.cmsSign(x509, pkey, certs, inBio, flags);
              if (cms == nullptr) _fail('CMS_sign(CAdES)');
              try {
                if (addMessageDigest && !addSigningTime) {
                  _addSignedAttr(cms, 'messageDigest');
                }
                return _cmsToDer(cms);
              } finally {
                _b.cmsContentInfoFree(cms);
              }
            } finally {
              if (certs != nullptr) {
                _b.osslSkFree(certs);
              }
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
    } finally {
      _b.bioFree(certBio);
    }
  }


  Uint8List _cmsToDer(CMS_ContentInfo cms) {
    final bio = _b.bioNew(_b.bioSMem());
    try {
      _check1(_b.pemWriteBioCms(bio, cms), 'PEM_write_bio_CMS');
      return bioToBytes(_b, bio);
    } finally {
      _b.bioFree(bio);
    }
  }

  EVP_PKEY _loadPrivateKey(Uint8List data) {
    final bio = bioFromData(_b, data);
    if (bio == nullptr) _fail('BIO_new(_loadPrivateKey)');
    try {
      final pkey = _b.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
      if (pkey == nullptr) {
        _fail('PEM_read_bio_PrivateKey');
      }
      return pkey;
    } finally {
      _b.bioFree(bio);
    }
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


  /// Builds a STACK_OF(X509) from optional CA and intermediate certs.
  /// Builds a STACK_OF(X509) for the certificates chain.
  Pointer<Void> _buildCertStack({
    Uint8List? caCertPem,
    List<Uint8List>? intermediates,
  }) {
    final certs = <Uint8List>[];
    if (caCertPem != null && caCertPem.isNotEmpty) certs.add(caCertPem);
    if (intermediates != null) certs.addAll(intermediates);
    if (certs.isEmpty) return nullptr;

    final stack = _b.osslSkNewNull();
    if (stack == nullptr) _fail('OPENSSL_sk_new_null(certs)');

    for (final pem in certs) {
      final bio = bioFromData(_b, pem);
      if (bio == nullptr) _fail('BIO_new(certs stack)');
      try {
        final x509 = _b.pemReadBioX509(bio, nullptr, nullptr, nullptr);
        if (x509 == nullptr) _fail('PEM_read_bio_X509(certs stack)');
        _check1(_b.osslSkPush(stack, x509.cast()), 'OPENSSL_sk_push(cert)');
      } finally {
        _b.bioFree(bio);
      }
    }

    return stack;
  }

  /// Adds a signed attribute to the first signer in the CMS.
  void _addSignedAttr(CMS_ContentInfo cms, String attrName) {
    final signers = _b.cmsGet0Signers(cms);
    if (signers == nullptr) return;
    try {
      final si = _osslSkValue(signers, 0);
      if (si == nullptr) return;
      final name = attrName.toNativeUtf8();
      try {
        _check1(
          _b.cmsSignedAdd1AttrByTxt(si.cast(), name, 0, nullptr, 0),
          'CMS_signed_add1_attr_by_txt($attrName)',
        );
      } finally {
        calloc.free(name);
      }
    } finally {
      _b.osslSkFree(signers);
    }
  }

  /// Gets the value at index from an OPENSSL stack.
  Pointer<Void> _osslSkValue(Pointer<Void> st, int idx) {
    return _b.osslSkValue(st, idx);
  }
}
