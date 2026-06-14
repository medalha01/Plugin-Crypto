library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../ffi/openssl_bindings.dart';

/// Creates a read/write memory BIO containing [data].
BIO bioFromData(OpenSslBindings b, Uint8List data) {
  final bio = b.bioNew(b.bioSMem());
  if (bio == nullptr) return nullptr;
  if (data.isNotEmpty) {
    final dp = calloc<Uint8>(data.length);
    try {
      dp.asTypedList(data.length).setAll(0, data);
      b.bioWrite(bio, dp.cast(), data.length);
    } finally {
      calloc.free(dp);
    }
  }
  return bio;
}

/// Creates a read/write memory BIO containing the bytes of [s].
BIO bioFromString(OpenSslBindings b, String s) {
  final bio = b.bioNew(b.bioSMem());
  if (bio == nullptr) return nullptr;
  if (s.isNotEmpty) {
    final bytes = s.codeUnits;
    final dp = calloc<Uint8>(bytes.length);
    try {
      dp.asTypedList(bytes.length).setAll(0, bytes);
      b.bioWrite(bio, dp.cast(), bytes.length);
    } finally {
      calloc.free(dp);
    }
  }
  return bio;
}

/// Reads all data from a memory [BIO] into a [Uint8List].
Uint8List bioToBytes(OpenSslBindings b, BIO bio) {
  final buffer = BytesBuilder(copy: false);
  final chunk = calloc<Uint8>(4096);
  try {
    while (true) {
      final n = b.bioRead(bio, chunk.cast(), 4096);
      if (n <= 0) break;
      buffer.add(Uint8List.fromList(chunk.asTypedList(n)));
    }
    return buffer.takeBytes();
  } finally {
    calloc.free(chunk);
  }
}

/// Reads all data from a memory [BIO] and returns it as a Dart [String].
String bioToString(OpenSslBindings b, BIO bio) {
  final bytes = bioToBytes(b, bio);
  if (bytes.isEmpty) return '';
  return String.fromCharCodes(bytes);
}
