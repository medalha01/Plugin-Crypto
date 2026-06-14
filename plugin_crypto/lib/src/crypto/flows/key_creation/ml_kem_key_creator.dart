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

class MlKemKeyCreator implements KeyCreator {
  final OpenSslBindings _b;

  /// Creates an [MlKemKeyCreator] with the given FFI bindings.
  const MlKemKeyCreator(this._b);

  @override
  List<KeySpec> get supportedSpecs => [
    const MlKemKeySpec(MlKemParameterSet.mlKem512),
    const MlKemKeySpec(MlKemParameterSet.mlKem768),
    const MlKemKeySpec(MlKemParameterSet.mlKem1024),
  ];

  @override
  CryptoResult<KeyPair> create(KeySpec spec) {
    if (spec is! MlKemKeySpec) {
      return CryptoFailure(
        ValidationError(
          field: 'KeySpec',
          reason:
              'MlKemKeyCreator only accepts MlKemKeySpec, got ${spec.runtimeType}',
        ),
      );
    }

    final nid = switch (spec.parameterSet) {
      MlKemParameterSet.mlKem512 => nidMlKem512,
      MlKemParameterSet.mlKem768 => nidMlKem768,
      MlKemParameterSet.mlKem1024 => nidMlKem1024,
    };

    final ctx = _b.evpPkeyCtxNewId(nid, nullptr);
    if (ctx == nullptr) {
      return _fail<KeyPair>(
        KeygenError(
          keyType: 'ML-KEM',
          reason: 'EVP_PKEY_CTX_new_id returned null (NID $nid)',
        ),
      );
    }

    try {
      final initResult = _b.evpPkeyKeygenInit(ctx);
      if (initResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'ML-KEM',
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
              keyType: 'ML-KEM',
              reason: 'EVP_PKEY_keygen',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        return KeyPairSerializer(_b).extract(ppkey.value, 'ML-KEM');
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
