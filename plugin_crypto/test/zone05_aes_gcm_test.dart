import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone05', 'AES-GCM');

  final api = PluginCryptoAPI.instance;

  final aes128Key = Uint8List.fromList(List.filled(16, 0x2B));
  final aes256Key = Uint8List.fromList(List.filled(32, 0x4E));
  final iv12 = Uint8List.fromList(List.filled(12, 0xA1));
  final plaintext = utf8.encode('The quick brown fox jumps over the lazy dog.');


  group('AES-128-GCM', () {
    test('encrypt returns AesGcmResult with ciphertext and 16-byte tag', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext);
      expect(result.ciphertext, isNotNull);
      expect(result.ciphertext, isNotEmpty);
      expect(result.tag.length, equals(16));
    });

    test('encrypt then decrypt returns original plaintext', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext);
      final decrypted = api.aes128GcmDecrypt(
        aes128Key,
        iv12,
        result.ciphertext,
        result.tag,
      );
      expect(decrypted, equals(plaintext));
    });

    test('decrypt with wrong tag throws or fails', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext);
      final wrongTag = Uint8List.fromList(List.filled(16, 0x00));
      expect(
        () =>
            api.aes128GcmDecrypt(aes128Key, iv12, result.ciphertext, wrongTag),
        throwsA(isA<AesGcmAuthFailure>()),
      );
    });

    test('decrypt with modified ciphertext fails', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext);
      final modified = Uint8List.fromList(result.ciphertext);
      modified[0] ^= 0xFF;
      expect(
        () => api.aes128GcmDecrypt(aes128Key, iv12, modified, result.tag),
        throwsA(isA<AesGcmAuthFailure>()),
      );
    });
  });


  group('AES-256-GCM', () {
    test('encrypt returns AesGcmResult with ciphertext and 16-byte tag', () {
      final result = api.aes256GcmEncrypt(aes256Key, iv12, plaintext);
      expect(result.ciphertext, isNotNull);
      expect(result.ciphertext, isNotEmpty);
      expect(result.tag.length, equals(16));
    });

    test('encrypt then decrypt returns original plaintext', () {
      final result = api.aes256GcmEncrypt(aes256Key, iv12, plaintext);
      final decrypted = api.aes256GcmDecrypt(
        aes256Key,
        iv12,
        result.ciphertext,
        result.tag,
      );
      expect(decrypted, equals(plaintext));
    });

    test('decrypt with wrong tag throws or fails', () {
      final result = api.aes256GcmEncrypt(aes256Key, iv12, plaintext);
      final wrongTag = Uint8List.fromList(List.filled(16, 0x00));
      expect(
        () =>
            api.aes256GcmDecrypt(aes256Key, iv12, result.ciphertext, wrongTag),
        throwsA(isA<AesGcmAuthFailure>()),
      );
    });

    test('decrypt with modified ciphertext fails', () {
      final result = api.aes256GcmEncrypt(aes256Key, iv12, plaintext);
      final modified = Uint8List.fromList(result.ciphertext);
      modified[0] ^= 0xFF;
      expect(
        () => api.aes256GcmDecrypt(aes256Key, iv12, modified, result.tag),
        throwsA(isA<AesGcmAuthFailure>()),
      );
    });
  });


  group('AES-GCM with AAD', () {
    final aad = utf8.encode('additional data');
    final wrongAad = utf8.encode('wrong data');

    test('encrypt with AAD then decrypt with same AAD succeeds', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext, aad: aad);
      final decrypted = api.aes128GcmDecrypt(
        aes128Key,
        iv12,
        result.ciphertext,
        result.tag,
        aad: aad,
      );
      expect(decrypted, equals(plaintext));
    });

    test('decrypt with wrong AAD fails', () {
      final result = api.aes128GcmEncrypt(aes128Key, iv12, plaintext, aad: aad);
      expect(
        () => api.aes128GcmDecrypt(
          aes128Key,
          iv12,
          result.ciphertext,
          result.tag,
          aad: wrongAad,
        ),
        throwsA(isA<AesGcmAuthFailure>()),
      );
    });
  });


  group('key validation', () {
    test('AES-128-GCM with 32-byte key throws', () {
      expect(
        () => api.aes128GcmEncrypt(aes256Key, iv12, plaintext),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('AES-256-GCM with 16-byte key throws', () {
      expect(
        () => api.aes256GcmEncrypt(aes128Key, iv12, plaintext),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  m?.endZone();
}
