library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../ffi/openssl_bindings.dart';

/// Test hook invoked after a native secret buffer has been cleansed and before
/// it is released. Production code should leave this set to `null`.
abstract interface class SecretMemoryObserver {
  void afterCleanse(Pointer<Uint8> pointer, int length);
}

SecretMemoryObserver? secretMemoryObserver;

/// Copies [bytes] into native memory for the duration of [action], then wipes
/// the plugin-owned copy with `OPENSSL_cleanse` before freeing it.
T withSecretBytes<T>(
  OpenSslBindings bindings,
  Uint8List bytes,
  T Function(Pointer<Uint8> pointer) action,
) {
  // calloc(0) is implementation-defined. Allocate one byte while still passing
  // the real length to OpenSSL and to OPENSSL_cleanse.
  final pointer = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
  if (bytes.isNotEmpty) {
    pointer.asTypedList(bytes.length).setAll(0, bytes);
  }
  try {
    return action(pointer);
  } finally {
    bindings.opensslCleanse(pointer.cast(), bytes.length);
    secretMemoryObserver?.afterCleanse(pointer, bytes.length);
    calloc.free(pointer);
  }
}
