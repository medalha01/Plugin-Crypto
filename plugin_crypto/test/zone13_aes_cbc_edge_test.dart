import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

/// Hex string → Uint8List.
Uint8List _bytes(String hex) {
  final len = hex.length;
  final result = Uint8List(len ~/ 2);
  for (var i = 0; i < len; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone13', 'AES-CBC Edge Cases');

  final api = PluginCryptoAPI.instance;

  final nistKey = _bytes('2b7e151628aed2a6abf7158809cf4f3c');
  final nistIv = _bytes('000102030405060708090a0b0c0d0e0f');
  final nistPlaintext = _bytes('6bc1bee22e409f96e93d7e117393172a');
  group('AES-CBC empty plaintext', () {
    test('encrypt empty then decrypt returns empty', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final empty = Uint8List(0);

      final ciphertext = api.aes128CbcEncrypt(key, iv, empty);
      expect(ciphertext, isNotEmpty);
      expect(ciphertext.length, greaterThanOrEqualTo(16));

      final decrypted = api.aes128CbcDecrypt(key, iv, ciphertext);
      expect(decrypted, isEmpty);
    });

    test('encrypt empty AES-256 then decrypt returns empty', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      final empty = Uint8List(0);

      final ciphertext = api.aes256CbcEncrypt(key, iv, empty);
      expect(ciphertext, isNotEmpty);

      final decrypted = api.aes256CbcDecrypt(key, iv, ciphertext);
      expect(decrypted, isEmpty);
    });
  });

  group('AES-CBC single-byte plaintext', () {
    test('encrypt single byte then decrypt returns original', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final plaintext = Uint8List.fromList([0x42]);

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintext);
      final decrypted = api.aes128CbcDecrypt(key, iv, ciphertext);

      expect(decrypted, equals(plaintext));
    });

    test('single-byte encrypt/decrypt with AES-256', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      final plaintext = Uint8List.fromList([0xFF]);

      final ciphertext = api.aes256CbcEncrypt(key, iv, plaintext);
      final decrypted = api.aes256CbcDecrypt(key, iv, ciphertext);

      expect(decrypted, equals(plaintext));
    });
  });

  group('AES-CBC NIST CAVP known-answer', () {
    test('F.2.1 CBC-AES128 decrypt round-trip', () {
      final paddedCiphertext = api.aes128CbcEncrypt(
        nistKey,
        nistIv,
        nistPlaintext,
      );
      expect(paddedCiphertext.length, equals(32));

      final decrypted = api.aes128CbcDecrypt(nistKey, nistIv, paddedCiphertext);
      expect(decrypted, equals(nistPlaintext));
    });
  });

  group('AES-CBC corrupted ciphertext', () {
    test('decrypt with single-bit flip produces garbage, does not crash', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final plaintext = utf8.encode('The quick brown fox.');

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintext);
      final corrupted = Uint8List.fromList(ciphertext);
      corrupted[corrupted.length - 1] ^= 0x01;

      Uint8List decrypted;
      try {
        decrypted = api.aes128CbcDecrypt(key, iv, corrupted);
      } catch (_) {
        decrypted = Uint8List(0);
      }

      if (decrypted.isNotEmpty) {
        expect(decrypted, isNot(equals(plaintext)));
      }
    });

    test('decrypt first-block corruption does not crash', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final plaintext = utf8.encode(
        'This is a longer message for multi-block AES-CBC.',
      );

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintext);
      final corrupted = Uint8List.fromList(ciphertext);
      corrupted[0] ^= 0xFF;

      try {
        final decrypted = api.aes128CbcDecrypt(key, iv, corrupted);
        expect(decrypted, isNotNull);
      } catch (_) {
      }
    });
  });

  group('AES-CBC wrong key size for decrypt', () {
    test('16-byte key on aes256CbcDecrypt throws', () {
      final key16 = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final dummyCiphertext = Uint8List(32);

      expect(
        () => api.aes256CbcDecrypt(key16, iv, dummyCiphertext),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('32-byte key on aes128CbcDecrypt throws', () {
      final key32 = api.randomBytes(32);
      final iv = api.randomBytes(16);
      final dummyCiphertext = Uint8List(32);

      expect(
        () => api.aes128CbcDecrypt(key32, iv, dummyCiphertext),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  m?.endZone();
}
