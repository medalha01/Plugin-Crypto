library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/ocsp_data.dart';
import '../../utils/asn1_time.dart';
import '../../utils/openssl_error.dart';
import '../../utils/x509_loader.dart';
import '../../crypto_context.dart';
import '../../../ffi/openssl_bindings.dart'
    show
        X509,
        OCSP_REQUEST,
        OCSP_RESPONSE,
        OCSP_BASICRESP,
        ASN1_GENERALIZEDTIME;
import 'revocation_verifier.dart';

class OpenSslOcspVerifier implements OcspVerifier {
  final CryptoContext _ctx;

  /// Creates an [OpenSslOcspVerifier] with the given [CryptoContext].
  const OpenSslOcspVerifier(this._ctx);

  /// OCSP response status: successful.
  static const int _ocspRespStatusSuccessful = 0;

  /// OCSP cert status constants.
  static const int _certStatusGood = 0;
  static const int _certStatusRevoked = 1;

  @override
  CryptoResult<Uint8List> buildOcspRequest(
    Uint8List cert,
    Uint8List issuerCert,
  ) {
    if (cert.isEmpty) {
      return CryptoFailure(OcspError(reason: 'cert must be non-empty'));
    }
    if (issuerCert.isEmpty) {
      return CryptoFailure(OcspError(reason: 'issuerCert must be non-empty'));
    }

    final leafResult = _parseCert(cert);
    switch (leafResult) {
      case CryptoFailure(:final error):
        return CryptoFailure(error);
      case CryptoSuccess(:final value):
        final leafX509 = value;
        try {
          final issuerResult = _parseCert(issuerCert);
          switch (issuerResult) {
            case CryptoFailure(:final error):
              return CryptoFailure(error);
            case CryptoSuccess(:final value):
              final issuerX509 = value;
              try {
                return _doBuildRequest(leafX509, issuerX509);
              } finally {
                _ctx.bindings.x509Free(issuerX509);
              }
          }
        } finally {
          _ctx.bindings.x509Free(leafX509);
        }
    }
  }

  CryptoResult<Uint8List> _doBuildRequest(X509 leaf, X509 issuer) {
    final issuerName = _ctx.bindings.x509GetSubjectName(issuer);
    final issuerKey = _ctx.bindings.x509Get0PubkeyBitstr(issuer);
    final serialNumber = _ctx.bindings.x509GetSerialNumber(leaf);

    final digest = _ctx.bindings.evpSha256();
    final certId = _ctx.bindings.ocspCertIdNew(
      digest,
      issuerName,
      issuerKey,
      serialNumber.cast(),
    );
    if (certId == nullptr) {
      return _fail<Uint8List>(OcspError(reason: 'OCSP_cert_id_new'));
    }

    final request = _ctx.bindings.ocspRequestNew();
    if (request == nullptr) {
      _ctx.bindings.ocspCertidFree(certId);
      return _fail<Uint8List>(OcspError(reason: 'OCSP_REQUEST_new'));
    }
    try {
      final added = _ctx.bindings.ocspRequestAdd0Id(request, certId);
      if (added == nullptr) {
        _ctx.bindings.ocspCertidFree(certId);
        return _fail<Uint8List>(OcspError(reason: 'OCSP_request_add0_id'));
      }
      return _requestToDer(request);
    } finally {
      _ctx.bindings.ocspRequestFree(request);
    }
  }

  @override
  CryptoResult<OcspResponse> verifyOcspResponse(
    Uint8List ocspRespBytes,
    Uint8List issuerCert,
  ) {
    if (ocspRespBytes.isEmpty) {
      return CryptoFailure(
        OcspError(reason: 'ocspRespBytes must be non-empty'),
      );
    }
    if (issuerCert.isEmpty) {
      return CryptoFailure(OcspError(reason: 'issuerCert must be non-empty'));
    }

    return _doVerifyResponse(ocspRespBytes, issuerCert);
  }

  CryptoResult<OcspResponse> _doVerifyResponse(
    Uint8List respBytes,
    Uint8List issuerData,
  ) {
    final pp = calloc<Pointer<Uint8>>();
    final data = calloc<Uint8>(respBytes.length);
    try {
      data.asTypedList(respBytes.length).setAll(0, respBytes);
      pp.value = data;
      final resp = _ctx.bindings.d2iOcspResponse(nullptr, pp, respBytes.length);
      if (resp == nullptr) {
        return _fail<OcspResponse>(
          OcspError(
            reason: 'd2i_OCSP_RESPONSE',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }
      try {
        return _processOcspResponse(resp, issuerData);
      } finally {
        _ctx.bindings.ocspResponseFree(resp);
      }
    } finally {
      calloc.free(data);
      calloc.free(pp);
    }
  }

  CryptoResult<OcspResponse> _processOcspResponse(
    OCSP_RESPONSE resp,
    Uint8List issuerData,
  ) {
    final respStatus = _ctx.bindings.ocspResponseStatus(resp);
    if (respStatus != _ocspRespStatusSuccessful) {
      return _fail<OcspResponse>(
        OcspError(
          reason: 'OCSP_response_status: $respStatus',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }

    final bs = _ctx.bindings.ocspResponseGetBasic(resp);
    if (bs == nullptr) {
      return _fail<OcspResponse>(
        OcspError(
          reason: 'OCSP_response_get1_basic',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }
    try {
      return _processBasicResponse(bs, issuerData);
    } finally {
      _ctx.bindings.ocspBasicrespFree(bs);
    }
  }

  CryptoResult<OcspResponse> _processBasicResponse(
    OCSP_BASICRESP bs,
    Uint8List issuerData,
  ) {
    final issuerResult = _parseCert(issuerData);
    switch (issuerResult) {
      case CryptoFailure(:final error):
        return CryptoFailure(error);
      case CryptoSuccess(:final value):
        final issuerX509 = value;
        try {
          final store = _ctx.bindings.x509StoreNew();
          if (store == nullptr) {
            return _fail<OcspResponse>(
              OcspError(
                reason: 'X509_STORE_new',
                openSslError: getOpenSslError(_ctx.bindings),
              ),
            );
          }
          try {
            final addCertResult = _ctx.bindings.x509StoreAddCert(
              store,
              issuerX509,
            );
            if (addCertResult != 1) {
              final err = getOpenSslError(_ctx.bindings);
              _ctx.bindings.errClearError();
              return CryptoFailure(
                OcspError(
                  reason:
                      'X509_STORE_add_cert failed'
                      '${err != null ? ': $err' : ''}',
                ),
              );
            }

            final verifyResult = _ctx.bindings.ocspBasicVerify(
              bs,
              nullptr,
              store,
              0,
            );
            if (verifyResult != 1) {
              final err = getOpenSslError(_ctx.bindings);
              _ctx.bindings.errClearError();
              return CryptoFailure(
                OcspError(
                  reason: 'OCSP_basic_verify failed',
                  openSslError: err,
                ),
              );
            }
          } finally {
            _ctx.bindings.x509StoreFree(store);
          }
        } finally {
          _ctx.bindings.x509Free(issuerX509);
        }

        return _extractResponseStatus(bs);
    }
  }

  CryptoResult<OcspResponse> _extractResponseStatus(OCSP_BASICRESP bs) {
    final count = _ctx.bindings.ocspRespCount(bs);
    if (count <= 0) {
      return CryptoSuccess(OcspResponse(status: CertificateStatus.unknown));
    }

    final single = _ctx.bindings.ocspRespGet0(bs, 0);
    if (single == nullptr) {
      return CryptoSuccess(OcspResponse(status: CertificateStatus.unknown));
    }

    final pReason = calloc<Int>();
    final pRevtime = calloc<ASN1_GENERALIZEDTIME>();
    final pThisupd = calloc<ASN1_GENERALIZEDTIME>();
    final pNextupd = calloc<ASN1_GENERALIZEDTIME>();
    try {
      final status = _ctx.bindings.ocspSingleGet0Status(
        single,
        pReason,
        pRevtime,
        pThisupd,
        pNextupd,
      );

      final certStatus = _mapStatus(status);

      final producedAt = _parseAsn1Time(
        _ctx.bindings.ocspRespGet0ProducedAt(bs),
      );
      final thisUpdate = _parseAsn1Time(pThisupd.value);
      final nextUpdate = _parseAsn1Time(pNextupd.value);

      if (pThisupd.value != nullptr && pNextupd.value != nullptr) {
        final validResult = _ctx.bindings.ocspCheckValidity(
          pThisupd.value,
          pNextupd.value,
          300,
          -1,
        );
        if (validResult != 1) {
          final err = getOpenSslError(_ctx.bindings);
          _ctx.bindings.errClearError();
          return CryptoFailure(
            OcspError(reason: 'OCSP_check_validity failed', openSslError: err),
          );
        }
      }

      return CryptoSuccess(
        OcspResponse(
          status: certStatus,
          producedAt: producedAt,
          thisUpdate: thisUpdate,
          nextUpdate: nextUpdate,
        ),
      );
    } finally {
      calloc.free(pReason);
      calloc.free(pRevtime);
      calloc.free(pThisupd);
      calloc.free(pNextupd);
    }
  }


  /// Parses a PEM/DER certificate into an X509*.
  CryptoResult<X509> _parseCert(Uint8List data) {
    final x509 = loadX509(_ctx.bindings, data);
    if (x509 == nullptr) {
      return _fail<X509>(OcspError(reason: 'Failed to parse certificate'));
    }
    return CryptoSuccess(x509);
  }

  /// Serializes an OCSP_REQUEST to DER bytes using i2d_OCSP_REQUEST.
  CryptoResult<Uint8List> _requestToDer(OCSP_REQUEST request) {
    final size = _ctx.bindings.i2dOcspRequest(request, nullptr);
    if (size <= 0) {
      return _fail<Uint8List>(OcspError(reason: 'i2d_OCSP_REQUEST(size)'));
    }

    final buf = calloc<Uint8>(size);
    final pp = calloc<Pointer<Uint8>>()..value = buf;
    try {
      final written = _ctx.bindings.i2dOcspRequest(request, pp);
      if (written <= 0) {
        return _fail<Uint8List>(OcspError(reason: 'i2d_OCSP_REQUEST'));
      }
      return CryptoSuccess(
        Uint8List.fromList(buf.asTypedList(size).sublist(0, written)),
      );
    } finally {
      calloc.free(pp);
      calloc.free(buf);
    }
  }

  /// Parses an ASN1_GENERALIZEDTIME to [DateTime] using the shared
  /// [parseAsn1Time] utility.
  DateTime? _parseAsn1Time(ASN1_GENERALIZEDTIME tm) {
    if (tm == nullptr) return null;
    return parseAsn1Time(_ctx.bindings, tm.cast<Void>());
  }

  CertificateStatus _mapStatus(int status) {
    switch (status) {
      case _certStatusGood:
        return CertificateStatus.good;
      case _certStatusRevoked:
        return CertificateStatus.revoked;
      default:
        return CertificateStatus.unknown;
    }
  }

  CryptoFailure<T> _fail<T>(CryptoError error) {
    _ctx.bindings.errClearError();
    return CryptoFailure<T>(error);
  }
}
