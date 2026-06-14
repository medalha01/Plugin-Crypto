library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../utils/openssl_error.dart';
import '../../utils/x509_loader.dart';
import '../../crypto_context.dart';
import '../../../ffi/openssl_bindings.dart' show X509, X509_STORE;
import 'chain_verifier.dart';
import 'chain_verification_request.dart';

class OpensslChainVerifier implements ChainVerifier {
  final CryptoContext _ctx;

  /// Creates a verifier backed by the given [CryptoContext].
  OpensslChainVerifier(this._ctx);

  @override
  CryptoResult<ChainValidationResult> verify(ChainVerificationRequest request) {
    _ctx.bindings.errClearError();

    try {
      request.validate();
    } on ArgumentError catch (e) {
      return CryptoFailure(
        ValidationError(field: 'request', reason: e.message.toString()),
      );
    }

    final store = _ctx.bindings.x509StoreNew();
    if (store == nullptr) {
      return _fail<ChainValidationResult>(
        ChainValidationError(
          chainDetail: 'X509_STORE_new returned null',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }

    try {
      if (request.trustedRoot != null) {
        final res = _loadCertIntoStore(store, request.trustedRoot!);
        if (res != null) return CryptoFailure(res);
      }

      final untrusted = _ctx.bindings.osslSkNewNull();
      if (untrusted == nullptr) {
        return _fail<ChainValidationResult>(
          ChainValidationError(
            chainDetail: 'OPENSSL_sk_new_null failed',
            openSslError: getOpenSslError(_ctx.bindings),
          ),
        );
      }

      try {
        for (final inter in request.intermediates) {
          final x509 = _loadX509(inter);
          if (x509 == nullptr) {
            return _fail<ChainValidationResult>(
              ChainValidationError(
                chainDetail: 'Failed to parse intermediate certificate',
                openSslError: getOpenSslError(_ctx.bindings),
              ),
            );
          }
          _ctx.bindings.osslSkPush(untrusted, x509.cast());
        }

        final leaf = _loadX509(request.leafCert);
        if (leaf == nullptr) {
          return _fail<ChainValidationResult>(
            ChainValidationError(
              chainDetail: 'Failed to parse leaf certificate',
              openSslError: getOpenSslError(_ctx.bindings),
            ),
          );
        }
        try {
          final vfyCtx = _ctx.bindings.x509StoreCtxNew();
          if (vfyCtx == nullptr) {
            return _fail<ChainValidationResult>(
              ChainValidationError(
                chainDetail: 'X509_STORE_CTX_new failed',
                openSslError: getOpenSslError(_ctx.bindings),
              ),
            );
          }
          try {
            final initResult = _ctx.bindings.x509StoreCtxInit(
              vfyCtx,
              store,
              leaf,
              untrusted,
            );
            if (initResult != 1) {
              return _fail<ChainValidationResult>(
                ChainValidationError(
                  chainDetail: 'X509_STORE_CTX_init failed',
                  openSslError: getOpenSslError(_ctx.bindings),
                ),
              );
            }

            if (request.verificationTime != null) {
              final param = _ctx.bindings.x509StoreCtxGet0Param(vfyCtx);
              if (param != nullptr) {
                final unixTime =
                    request.verificationTime!.millisecondsSinceEpoch ~/ 1000;
                _ctx.bindings.x509VerifyParamSetTime(param, unixTime);
              }
            }

            final verifyResult = _ctx.bindings.x509VerifyCert(vfyCtx);
            if (verifyResult == 1) {
              return CryptoSuccess(
                ChainValidationResult(valid: true, validatedAt: DateTime.now()),
              );
            }

            final errorCode = _ctx.bindings.x509StoreCtxGetError(vfyCtx);
            final errorDepth = _ctx.bindings.x509StoreCtxGetErrorDepth(vfyCtx);
            final errStrPtr = _ctx.bindings.x509VerifyCertErrorString(
              errorCode,
            );
            final errStr = errStrPtr != nullptr
                ? errStrPtr.toDartString()
                : 'Unknown error (code $errorCode)';
            return CryptoSuccess(
              ChainValidationResult(
                valid: false,
                errorReason: errStr,
                chainDepth: errorDepth,
                validatedAt: DateTime.now(),
              ),
            );
          } finally {
            _ctx.bindings.x509StoreCtxFree(vfyCtx);
          }
        } finally {
          _ctx.bindings.x509Free(leaf);
        }
      } finally {
        _ctx.bindings.osslSkFree(untrusted);
      }
    } finally {
      _ctx.bindings.x509StoreFree(store);
    }
  }


  ChainValidationError? _loadCertIntoStore(X509_STORE store, Uint8List data) {
    final x509 = _loadX509(data);
    if (x509 == nullptr) {
      _ctx.bindings.errClearError();
      return ChainValidationError(
        chainDetail: 'Failed to parse trusted root certificate',
        openSslError: getOpenSslError(_ctx.bindings),
      );
    }
    try {
      final addResult = _ctx.bindings.x509StoreAddCert(store, x509);
      if (addResult != 1) {
        _ctx.bindings.errClearError();
        return ChainValidationError(
          chainDetail: 'X509_STORE_add_cert failed for trusted root',
          openSslError: getOpenSslError(_ctx.bindings),
        );
      }
      return null; // success
    } finally {
      _ctx.bindings.x509Free(x509);
    }
  }

  /// Loads a single X.509 certificate from [data] (PEM or DER).
  X509 _loadX509(Uint8List data) {
    return loadX509(_ctx.bindings, data);
  }

  CryptoFailure<T> _fail<T>(CryptoError error) {
    _ctx.bindings.errClearError();
    return CryptoFailure<T>(error);
  }
}
