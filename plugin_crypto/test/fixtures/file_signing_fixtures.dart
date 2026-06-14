library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:plugin_crypto/plugin_crypto.dart';


/// Creates a temporary file with known content and returns its path.
String tempSmallFile() {
  final file = File('/tmp/plugin_crypto_test_small.bin');
  file.writeAsStringSync(
    'Hello, PluginCrypto! This is test content for file signing.\n',
  );
  return file.path;
}

String tempLargeFile(int sizeBytes) {
  final file = File('/tmp/plugin_crypto_test_large.bin');
  final random = Random(42); // deterministic for reproducibility
  final chunk = Uint8List(65536);
  final sink = file.openWrite();

  var remaining = sizeBytes;
  while (remaining > 0) {
    final n = min(remaining, chunk.length);
    for (var i = 0; i < n; i++) {
      chunk[i] = random.nextInt(256);
    }
    sink.add(chunk.sublist(0, n));
    remaining -= n;
  }

  sink.close();
  return file.path;
}

/// Deletes a temporary file by path, ignoring errors.
void deleteTempFile(String path) {
  try {
    File(path).deleteSync();
  } catch (_) {
  }
}


/// Returns a cached RSA 2048-bit key pair.
KeyPair rsaKeyPair() {
  final api = PluginCryptoAPI.instance;
  return api.generateRsaKeyPair(2048);
}

/// Returns a cached EC prime256v1 key pair.
KeyPair ecKeyPair() {
  final api = PluginCryptoAPI.instance;
  return api.generateEcKeyPair('prime256v1');
}
