library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'crypto_data.dart';
import 'models/certificate_data.dart';
import 'utils/asn1_time.dart';
import 'utils/bio_utils.dart';
import 'utils/openssl_error.dart';
import 'utils/x509_ext_parser.dart';

/// X.509 certificate parsing and chain verification operations.
class X509Operations {
  final OpenSslBindings _b;

  X509Operations(this._b);


  /// Analisa um certificado X.509 a partir de PEM ou DER.
  X509Certificate parseX509Certificate(Uint8List certData) {
    final bio = bioFromData(_b, certData);
    if (bio == nullptr) _fail('BIO_new(parseX509Certificate)');
    try {
      var x509 = _b.pemReadBioX509(bio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) {
        _b.errClearError();
        final bio2 = bioFromData(_b, certData);
        if (bio2 != nullptr) {
          x509 = _b.d2iX509Bio(bio2, nullptr);
          _b.bioFree(bio2);
        }
      }
      if (x509 == nullptr) _fail('PEM_read_bio_X509 / d2i_X509_bio');
      try {
        return _parseX509(x509, certData);
      } finally {
        _b.x509Free(x509);
      }
    } finally {
      _b.bioFree(bio);
    }
  }

  /// Valida uma cadeia de certificados.
  /// [cert] is the leaf certificate, [caCert] is the trusted CA.
  bool verifyX509Certificate(Uint8List cert, Uint8List caCert) {
    final store = _b.x509StoreNew();
    if (store == nullptr) _fail('X509_STORE_new');
    try {
      final caBio = bioFromData(_b, caCert);
      if (caBio == nullptr) _fail('BIO_new(verifyX509)');
      try {
        final ca = _b.pemReadBioX509(caBio, nullptr, nullptr, nullptr);
        if (ca == nullptr) _fail('PEM_read_bio_X509(CA cert)');
        try {
          _check1(_b.x509StoreAddCert(store, ca), 'X509_STORE_add_cert');
        } finally {
          _b.x509Free(ca);
        }
      } finally {
        _b.bioFree(caBio);
      }

      final certBio = bioFromData(_b, cert);
      if (certBio == nullptr) _fail('BIO_new(verifyX509 cert)');
      try {
        final x509 = _b.pemReadBioX509(certBio, nullptr, nullptr, nullptr);
        if (x509 == nullptr) _fail('PEM_read_bio_X509(verify)');
        try {
          final vfyCtx = _b.x509StoreCtxNew();
          if (vfyCtx == nullptr) _fail('X509_STORE_CTX_new');
          try {
            _check1(
              _b.x509StoreCtxInit(vfyCtx, store, x509, nullptr),
              'X509_STORE_CTX_init',
            );
            return _b.x509VerifyCert(vfyCtx) == 1;
          } finally {
            _b.x509StoreCtxFree(vfyCtx);
          }
        } finally {
          _b.x509Free(x509);
        }
      } finally {
        _b.bioFree(certBio);
      }
    } finally {
      _b.x509StoreFree(store);
    }
  }


  X509Certificate _parseX509(X509 x509, Uint8List raw) {
    final subj = _b.x509GetSubjectName(x509);
    final iss = _b.x509GetIssuerName(x509);
    String nameOneLine(Pointer<Void> name) {
      if (name == nullptr) return '(unknown)';
      final ptr = _b.x509NameOneline(name, nullptr, 0);
      if (ptr == nullptr) return '(unknown)';
      try {
        return ptr.toDartString();
      } finally {
        _b.cryptoFree(ptr.cast(), nullptr, 0);
      }
    }

    final subjStr = nameOneLine(subj);
    final issStr = nameOneLine(iss);

    final sn = _b.x509GetSerialNumber(x509);
    final snStr = sn != nullptr ? 'present' : '(unavailable)';

    DateTime notBefore = DateTime(1970);
    DateTime notAfter = DateTime(1970);

    final nb = _b.x509GetNotBefore(x509);
    if (nb != nullptr) {
      notBefore = parseAsn1Time(_b, nb) ?? DateTime(1970);
    }

    final na = _b.x509GetNotAfter(x509);
    if (na != nullptr) {
      notAfter = parseAsn1Time(_b, na) ?? DateTime(1970);
    }

    return X509Certificate(
      subject: subjStr,
      issuer: issStr,
      serialNumber: snStr,
      notBefore: notBefore,
      notAfter: notAfter,
      rawDer: raw,
      extensions: _parseExt(x509),
    );
  }

  X509ParsedExtensions? _parseExt(X509 x509) {
    try {
      final parser = X509ExtensionParser(_b);
      final extensions = parser.parseExtensions(x509.cast());
      if (extensions.keyUsage == null &&
          extensions.basicConstraints == null &&
          extensions.subjectAltNames == null &&
          extensions.crlDistributionPoints == null &&
          extensions.ocspResponders == null) {
        return null;
      }
      return extensions;
    } catch (_) {
      return null;
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
}
