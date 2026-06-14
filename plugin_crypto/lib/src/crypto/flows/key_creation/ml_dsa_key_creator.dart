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

class MlDsaKeyCreator implements KeyCreator {
  final OpenSslBindings _b;

  /// Creates an [MlDsaKeyCreator] with the given FFI bindings.
  const MlDsaKeyCreator(this._b);

  @override
  List<KeySpec> get supportedSpecs => [
    const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
    const MlDsaKeySpec(MlDsaParameterSet.mlDsa65),
    const MlDsaKeySpec(MlDsaParameterSet.mlDsa87),
  ];

  @override
  CryptoResult<KeyPair> create(KeySpec spec) {
    if (spec is! MlDsaKeySpec) {
      return CryptoFailure(
        ValidationError(
          field: 'KeySpec',
          reason:
              'MlDsaKeyCreator only accepts MlDsaKeySpec, got ${spec.runtimeType}',
        ),
      );
    }

    final nid = switch (spec.parameterSet) {
      MlDsaParameterSet.mlDsa44 => nidMlDsa44,
      MlDsaParameterSet.mlDsa65 => nidMlDsa65,
      MlDsaParameterSet.mlDsa87 => nidMlDsa87,
    };

    final ctx = _b.evpPkeyCtxNewId(nid, nullptr);
    if (ctx == nullptr) {
      return _fail<KeyPair>(
        KeygenError(
          keyType: 'ML-DSA',
          reason: 'EVP_PKEY_CTX_new_id returned null (NID $nid)',
        ),
      );
    }

    try {
      final initResult = _b.evpPkeyKeygenInit(ctx);
      if (initResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'ML-DSA',
            reason: 'EVP_PKEY_keygen_init',
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
              keyType: 'ML-DSA',
              reason: 'EVP_PKEY_keygen',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        return KeyPairSerializer(_b).extract(ppkey.value, 'ML-DSA');
      } finally {
        calloc.free(ppkey);
      }
    } finally {
      _b.evpPkeyCtxFree(ctx);
    }
  }


  /// Creates a [KeygenError] after optionally capturing the OpenSSL error
  /// queue.
  CryptoFailure<T> _fail<T>(CryptoError error) => CryptoFailure<T>(error);
}
