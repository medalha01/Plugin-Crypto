library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'utils/openssl_error.dart';

/// Stateless hashing and random-byte operations using OpenSSL.
class CryptoOperations {
  final OpenSslBindings _b;

  CryptoOperations(this._b);


  /// Gera [length] bytes aleatórios criptograficamente seguros.
  Uint8List randomBytes(int length) {
    final buf = calloc<Uint8>(length);
    try {
      _check1(_b.randBytes(buf, length), 'RAND_bytes');
      return Uint8List.fromList(buf.asTypedList(length));
    } finally {
      calloc.free(buf);
    }
  }


  Uint8List sha256(Uint8List data) => _digest(data, _b.evpSha256(), 32);
  Uint8List sha512(Uint8List data) => _digest(data, _b.evpSha512(), 64);
  Uint8List sha3_256(Uint8List data) => _digest(data, _b.evpSha3_256(), 32);
  Uint8List sha3_512(Uint8List data) => _digest(data, _b.evpSha3_512(), 64);

  Uint8List _digest(Uint8List data, Pointer<Void> md, int digestLen) {
    final ctx = _b.evpMdCtxNew();
    if (ctx == nullptr) _fail('EVP_MD_CTX_new');
    try {
      _check1(_b.evpDigestInitEx(ctx, md, nullptr), 'EVP_DigestInit_ex');
      final dp = calloc<Uint8>(data.length);
      try {
        dp.asTypedList(data.length).setAll(0, data);
        _check1(
          _b.evpDigestUpdate(ctx, dp.cast(), data.length),
          'EVP_DigestUpdate',
        );
      } finally {
        calloc.free(dp);
      }
      final mdBuf = calloc<Uint8>(digestLen);
      final mdLen = calloc<Uint32>();
      try {
        _check1(_b.evpDigestFinalEx(ctx, mdBuf, mdLen), 'EVP_DigestFinal_ex');
        return Uint8List.fromList(mdBuf.asTypedList(digestLen));
      } finally {
        calloc.free(mdBuf);
        calloc.free(mdLen);
      }
    } finally {
      _b.evpMdCtxFree(ctx);
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
