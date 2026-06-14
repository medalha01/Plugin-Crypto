import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone04', 'Random');

  final api = PluginCryptoAPI.instance;

  group('AES-128-CBC', () {
    test('encrypt then decrypt returns original plaintext', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-128-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintextBytes);
      final decrypted = api.aes128CbcDecrypt(key, iv, ciphertext);

      expect(utf8.decode(decrypted), equals(plaintext));
    });

    test('encrypt produces different ciphertext than plaintext', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-128-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintextBytes);

      expect(ciphertext, isNot(equals(plaintextBytes)));
    });

    test('decrypt with wrong IV produces wrong result', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final wrongIv = api.randomBytes(16);
      const plaintext = 'Hello AES-128-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes128CbcEncrypt(key, iv, plaintextBytes);
      final decrypted = api.aes128CbcDecrypt(key, wrongIv, ciphertext);

      expect(decrypted, isNot(equals(plaintextBytes)));
    });
  });

  group('AES-256-CBC', () {
    test('encrypt then decrypt returns original plaintext', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-256-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes256CbcEncrypt(key, iv, plaintextBytes);
      final decrypted = api.aes256CbcDecrypt(key, iv, ciphertext);

      expect(utf8.decode(decrypted), equals(plaintext));
    });

    test('encrypt produces different ciphertext than plaintext', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-256-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes256CbcEncrypt(key, iv, plaintextBytes);

      expect(ciphertext, isNot(equals(plaintextBytes)));
    });

    test('decrypt with wrong IV produces wrong result', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      final wrongIv = api.randomBytes(16);
      const plaintext = 'Hello AES-256-CBC!';
      final plaintextBytes = utf8.encode(plaintext);

      final ciphertext = api.aes256CbcEncrypt(key, iv, plaintextBytes);
      final decrypted = api.aes256CbcDecrypt(key, wrongIv, ciphertext);

      expect(decrypted, isNot(equals(plaintextBytes)));
    });
  });

  group('key size validation', () {
    test('AES-128 with 32-byte key throws', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      const plaintext = 'test';
      final plaintextBytes = utf8.encode(plaintext);

      expect(
        () => api.aes128CbcEncrypt(key, iv, plaintextBytes),
        throwsA(anything),
      );
    });

    test('AES-256 with 16-byte key throws', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      const plaintext = 'test';
      final plaintextBytes = utf8.encode(plaintext);

      expect(
        () => api.aes256CbcEncrypt(key, iv, plaintextBytes),
        throwsA(anything),
      );
    });
  });

  group('IV size validation', () {
    test('encrypt with 12-byte IV throws', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12);
      const plaintext = 'test';
      final plaintextBytes = utf8.encode(plaintext);

      expect(
        () => api.aes128CbcEncrypt(key, iv, plaintextBytes),
        throwsA(anything),
      );
    });
  });

  m?.endZone();
}
