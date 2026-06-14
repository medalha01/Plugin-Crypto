/// OpenSSL error queue utilities.
library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../../ffi/openssl_bindings.dart';
import '../models/crypto_error.dart';
import '../models/crypto_result.dart';

/// Returns the last OpenSSL error string, or `null` if the error queue
/// is empty.
String? getOpenSslError(OpenSslBindings b) {
  final err = b.errGetError();
  if (err == 0) return null;
  final buf = calloc<Uint8>(256);
  try {
    b.errErrorStringN(err, buf.cast(), 256);
    return buf.cast<Utf8>().toDartString();
  } finally {
    calloc.free(buf);
  }
}

/// Wraps a [CryptoError] in a [CryptoFailure].
CryptoFailure<T> cryptoFailure<T>(CryptoError error) {
  return CryptoFailure<T>(error);
}
