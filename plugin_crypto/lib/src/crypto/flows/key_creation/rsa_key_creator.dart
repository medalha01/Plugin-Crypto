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

class RsaKeyCreator implements KeyCreator {
  final OpenSslBindings _b;

  /// Creates an [RsaKeyCreator] with the given FFI bindings.
  const RsaKeyCreator(this._b);

  @override
  List<KeySpec> get supportedSpecs => [
    RsaKeySpec(2048),
    RsaKeySpec(3072),
    RsaKeySpec(4096),
    RsaKeySpec(8192),
  ];

  @override
  CryptoResult<KeyPair> create(KeySpec spec) {
    if (spec is! RsaKeySpec) {
      return CryptoFailure(
        ValidationError(
          field: 'KeySpec',
          reason:
              'RsaKeyCreator only accepts RsaKeySpec, got ${spec.runtimeType}',
        ),
      );
    }

    final bits = spec.bits;

    if (bits < 1024 || bits > 16384 || bits % 1024 != 0) {
      return CryptoFailure(
        ValidationError(
          field: 'RsaKeySpec.bits',
          reason:
              'bits must be >= 1024, <= 16384, and a multiple of 1024, '
              'got $bits',
        ),
      );
    }

    final ctx = _b.evpPkeyCtxNewId(nidRsa, nullptr); // EVP_PKEY_RSA = 6
    if (ctx == nullptr) {
      return _fail<KeyPair>(
        KeygenError(
          keyType: 'RSA',
          reason: 'EVP_PKEY_CTX_new_id returned null',
        ),
      );
    }

    try {
      final initResult = _b.evpPkeyKeygenInit(ctx);
      if (initResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'RSA',
            reason: 'EVP_PKEY_keygen_init',
            openSslError: getOpenSslError(_b),
          ),
        );
      }

      final bitsResult = _b.evpPkeyCtxSetRsaKeygenBits(ctx, bits);
      if (bitsResult != 1) {
        return _fail<KeyPair>(
          KeygenError(
            keyType: 'RSA',
            reason: 'EVP_PKEY_CTX_set_rsa_keygen_bits($bits)',
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
              keyType: 'RSA',
              reason: 'EVP_PKEY_keygen',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        return KeyPairSerializer(_b).extract(ppkey.value, 'RSA');
      } finally {
        calloc.free(ppkey);
      }
    } finally {
      _b.evpPkeyCtxFree(ctx);
    }
  }


  /// Creates a [KeygenError] after capturing the OpenSSL error queue.
  CryptoFailure<T> _fail<T>(CryptoError error) => CryptoFailure<T>(error);
}
