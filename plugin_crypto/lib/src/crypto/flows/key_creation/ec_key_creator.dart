library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../../../ffi/openssl_bindings.dart';
import '../../crypto_api.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/key_types.dart';
import 'key_creator.dart';
import '../../utils/key_pair_serializer.dart';
import '../../constants.dart';
import '../../utils/openssl_error.dart';

class EcKeyCreator implements KeyCreator {
  final OpenSslBindings _b;

  /// Creates an [EcKeyCreator] with the given FFI bindings.
  const EcKeyCreator(this._b);

  @override
  List<KeySpec> get supportedSpecs => [
    EcKeySpec('prime256v1'),
    EcKeySpec('secp384r1'),
    EcKeySpec('secp521r1'),
  ];

  @override
  CryptoResult<KeyPair> create(KeySpec spec) {
    if (spec is! EcKeySpec) {
      return CryptoFailure(
        ValidationError(
          field: 'KeySpec',
          reason:
              'EcKeyCreator only accepts EcKeySpec, got ${spec.runtimeType}',
        ),
      );
    }

    final curve = spec.curve;

    if (!EcCurve.isSupported(curve)) {
      return CryptoFailure(
        ValidationError(
          field: 'EcKeySpec.curve',
          reason:
              'Unsupported curve "$curve". '
              'Supported: ${EcCurve.all.join(', ')}',
        ),
      );
    }

    final curveUtf8 = curve.toNativeUtf8();
    final nid = _b.objSn2nid(curveUtf8.cast());
    calloc.free(curveUtf8);

    if (nid == 0) {
      return _fail<KeyPair>(
        KeygenError(
          keyType: 'EC',
          reason: 'OBJ_sn2nid("$curve") returned 0',
          openSslError: getOpenSslError(_b),
        ),
      );
    }

    final ctx = _b.evpPkeyCtxNewId(nidEc, nullptr); // EVP_PKEY_EC = 408
    if (ctx == nullptr) {
      return _fail<KeyPair>(
        KeygenError(keyType: 'EC', reason: 'EVP_PKEY_CTX_new_id returned null'),
      );
    }

    try {
      final initResult = _b.evpPkeyKeygenInit(ctx);
      if (initResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'EC',
            reason: 'EVP_PKEY_keygen_init',
            openSslError: getOpenSslError(_b),
          ),
        );
      }

      final curveResult = _b.evpPkeyCtxSetEcKeygenCurveNid(ctx, nid);
      if (curveResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'EC',
            reason: 'EVP_PKEY_CTX_set_ec_paramgen_curve_nid($curve)',
            openSslError: getOpenSslError(_b),
          ),
        );
      }

      final ppkey = calloc<EVP_PKEY>();
      try {
        final genResult = _b.evpPkeyKeygen(ctx, ppkey);
        if (genResult != 1) {
          return _fail<KeyPair>(
            KeygenError(
              keyType: 'EC',
              reason: 'EVP_PKEY_keygen',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        return KeyPairSerializer(_b).extract(ppkey.value, 'EC');
      } finally {
        calloc.free(ppkey);
      }
    } finally {
      _b.evpPkeyCtxFree(ctx);
    }
  }


  /// Creates a [KeygenError] after optionally capturing the OpenSSL error queue.
  CryptoFailure<T> _fail<T>(CryptoError error) => CryptoFailure<T>(error);
}
