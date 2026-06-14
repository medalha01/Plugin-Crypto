library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/csr_data.dart';
import '../../models/distinguished_name.dart';
import '../../utils/bio_utils.dart';
import '../../utils/openssl_error.dart';
import '../../constants.dart';
import '../../utils/x509_name_builder.dart';
import '../../crypto_context.dart';
import '../../../ffi/openssl_bindings.dart' show EVP_PKEY, X509_REQ, X509_NAME;
import 'csr_generator.dart';

class OpenSslCsrGenerator implements CsrGenerator {
  final CryptoContext _ctx;

  /// Creates an [OpenSslCsrGenerator] with the given [CryptoContext].
  const OpenSslCsrGenerator(this._ctx);

  @override
  CryptoResult<CsrData> generate(CsrRequest request) {
    try {
      request.validate();
    } catch (e) {
      return CryptoFailure(CsrError(reason: e.toString()));
    }

    final pkey = _loadPkey(request.subjectKeyPair.privateKeyPem);
    if (pkey == null) {
      return CryptoFailure(CsrError(reason: 'Failed to load private key'));
    }

    try {
      return _doGenerate(request, pkey);
    } finally {
      _ctx.bindings.evpPkeyFree(pkey);
    }
  }

  CryptoResult<CsrData> _doGenerate(CsrRequest request, EVP_PKEY pkey) {
    final req = _ctx.bindings.x509ReqNew();
    if (req == nullptr) {
      return _fail<CsrData>(
        CsrError(
          reason: 'X509_REQ_new',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }
    try {
      return _buildReq(req, request, pkey);
    } finally {
      _ctx.bindings.x509ReqFree(req);
    }
  }

  CryptoResult<CsrData> _buildReq(
    X509_REQ req,
    CsrRequest request,
    EVP_PKEY pkey,
  ) {
    if (_ctx.bindings.x509ReqSetVersion(req, 0) != 1) {
      return _fail<CsrData>(
        CsrError(
          reason: 'X509_REQ_set_version',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }

    final subjectName = _dnToX509Name(request.subject);
    try {
      if (_ctx.bindings.x509ReqSetSubjectName(req, subjectName) != 1) {
        return _fail<CsrData>(
          CsrError(
            reason: 'X509_REQ_set_subject_name',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }

      if (_ctx.bindings.x509ReqSetPubkey(req, pkey) != 1) {
        return _fail<CsrData>(
          CsrError(
            reason: 'X509_REQ_set_pubkey',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }

      if (request.dnsNames != null && request.dnsNames!.isNotEmpty) {
        final result = _addSanExtension(req, request.dnsNames!);
        if (result != null) return result;
      }

      final md = _ctx.bindings.evpSha256();
      if (_ctx.bindings.x509ReqSign(req, pkey, md) <= 0) {
        return _fail<CsrData>(
          CsrError(
            reason: 'X509_REQ_sign',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }

      final derResult = _extractDer(req);
      switch (derResult) {
        case CryptoFailure(:final error):
          return CryptoFailure(error);
        case CryptoSuccess(:final value):
          final derBytes = value;
          final pemResult = _extractPem(req);
          switch (pemResult) {
            case CryptoFailure(:final error):
              return CryptoFailure(error);
            case CryptoSuccess(:final value):
              final pemString = value;
              final subjectDn = _getSubjectDn(req);

              return CryptoSuccess(
                CsrData(
                  derBytes: derBytes,
                  pemString: pemString,
                  subjectDn: subjectDn,
                ),
              );
          }
      }
    } finally {
      _ctx.bindings.x509NameFree(subjectName);
    }
  }

  /// Creates an X509_NAME from a [DistinguishedName].
  X509_NAME _dnToX509Name(DistinguishedName dn) {
    return X509NameBuilder(_ctx.bindings).build(dn);
  }

  /// Adds the Subject Alternative Name extension to the CSR.
  CryptoResult<CsrData>? _addSanExtension(X509_REQ req, List<String> dnsNames) {
    final sanValue = dnsNames.map((n) => 'DNS:$n').join(',');
    final sanStr = sanValue.toNativeUtf8();
    try {
      const nidSan = nidSubjectAltName;

      final ctx = calloc<Int8>(1024);
      _ctx.bindings.x509V3SetCtx(
        ctx.cast(),
        nullptr,
        nullptr,
        req.cast(),
        nullptr,
        0,
      );

      final ext = _ctx.bindings.x509V3ExtConfNid(
        nullptr,
        ctx.cast(),
        nidSan,
        sanStr,
      );
      calloc.free(ctx);

      if (ext == nullptr) {
        return _fail<CsrData>(
          CsrError(
            reason: 'X509V3_EXT_conf_nid(SAN)',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }

      final extStack = _ctx.bindings.osslSkNewNull();
      if (extStack == nullptr) {
        _ctx.bindings.x509ExtensionFree(ext);
        return _fail<CsrData>(
          CsrError(
            reason: 'OPENSSL_sk_new_null(SAN)',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }
      try {
        _ctx.bindings.osslSkPush(extStack, ext.cast());
        if (_ctx.bindings.x509ReqAddExtensions(req, extStack) != 1) {
          return _fail<CsrData>(
            CsrError(
              reason: 'X509_REQ_add_extensions(SAN)',
              openSslError: getOpenSslError(_ctx.bindings),
            ),
          );
        }
      } finally {
        _ctx.bindings.osslSkFree(extStack);
      }
    } finally {
      calloc.free(sanStr);
    }
    return null;
  }

  /// Extracts the CSR as DER bytes.
  CryptoResult<Uint8List> _extractDer(X509_REQ req) {
    final bio = _ctx.bindings.bioNew(_ctx.bindings.bioSMem());
    if (bio == nullptr) {
      return _fail<Uint8List>(CsrError(reason: 'BIO_new(DER) failed'));
    }
    try {
      if (_ctx.bindings.i2dX509ReqBio(bio, req) != 1) {
        return _fail<Uint8List>(CsrError(reason: 'i2d_X509_REQ_bio failed'));
      }
      return CryptoSuccess(bioToBytes(_ctx.bindings, bio));
    } finally {
      _ctx.bindings.bioFree(bio);
    }
  }

  /// Extracts the CSR as a PEM string.
  CryptoResult<String> _extractPem(X509_REQ req) {
    final bio = _ctx.bindings.bioNew(_ctx.bindings.bioSMem());
    if (bio == nullptr) {
      return _fail<String>(CsrError(reason: 'BIO_new(PEM) failed'));
    }
    try {
      if (_ctx.bindings.pemWriteBioX509Req(bio, req) != 1) {
        return _fail<String>(CsrError(reason: 'PEM_write_bio_X509_REQ failed'));
      }
      return CryptoSuccess(bioToString(_ctx.bindings, bio));
    } finally {
      _ctx.bindings.bioFree(bio);
    }
  }

  /// Gets the subject DN oneline from the CSR.
  String _getSubjectDn(X509_REQ req) {
    final name = _ctx.bindings.x509ReqGetSubjectName(req);
    if (name == nullptr) return '';
    final p = _ctx.bindings.x509NameOneline(name, nullptr, 0);
    if (p == nullptr) return '';
    try {
      return p.cast<Utf8>().toDartString();
    } finally {
      _ctx.bindings.cryptoFree(p.cast(), nullptr, 0);
    }
  }

  /// Loads a private key from PEM data.
  EVP_PKEY? _loadPkey(String pemData) {
    final bio = bioFromString(_ctx.bindings, pemData);
    if (bio == nullptr) return null;
    try {
      final pkey = _ctx.bindings.pemReadBioPrivateKey(
        bio,
        nullptr,
        nullptr,
        nullptr,
      );
      return pkey;
    } finally {
      _ctx.bindings.bioFree(bio);
    }
  }

  CryptoFailure<T> _fail<T>(CryptoError error) {
    _ctx.bindings.errClearError();
    return CryptoFailure<T>(error);
  }
}
