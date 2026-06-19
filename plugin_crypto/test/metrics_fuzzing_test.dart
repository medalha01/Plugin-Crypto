@Tags(['metrics'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

import 'fixtures/helpers.dart' as helpers;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();
  final key16 = Uint8List.fromList(List<int>.filled(16, 0x01));
  final iv16 = Uint8List.fromList(List<int>.filled(16, 0x02));
  final iv12 = Uint8List.fromList(List<int>.filled(12, 0x02));
  var zeroLengthPassed = 0;
  var malformedPassed = 0;
  var massivePassed = 0;

  group('Zero-length inputs', () {
    test('hashes and symmetric ciphers handle empty plaintext', () {
      expect(api.sha256(Uint8List(0)).length, 32);
      expect(api.sha512(Uint8List(0)).length, 64);
      expect(api.aes128CbcEncrypt(key16, iv16, Uint8List(0)).length, 16);
      final gcm = api.aes128GcmEncrypt(key16, iv12, Uint8List(0));
      expect(gcm.ciphertext, isEmpty);
      expect(gcm.tag.length, 16);
      zeroLengthPassed = 4;
    });
  });

  group('Malformed inputs', () {
    test('AES-CBC rejects invalid key and IV lengths', () {
      expect(
        () => api.aes128CbcEncrypt(Uint8List(15), iv16, Uint8List(16)),
        throwsArgumentError,
      );
      expect(
        () => api.aes128CbcEncrypt(key16, Uint8List(8), Uint8List(16)),
        throwsArgumentError,
      );
      malformedPassed += 2;
    });

    test('AES-GCM rejects a bad authentication tag', () {
      final encrypted = api.aes128GcmEncrypt(key16, iv12, Uint8List(16));
      expect(
        () => api.aes128GcmDecrypt(
          key16,
          iv12,
          encrypted.ciphertext,
          Uint8List.fromList(List<int>.filled(16, 0xFF)),
        ),
        throwsA(isA<AesGcmAuthFailure>()),
      );
      malformedPassed++;
    });

    test('invalid EC curve fails with a documented state error', () {
      expect(
        () => api.generateEcKeyPair('imaginary-curve-9999'),
        throwsA(isA<StateError>()),
      );
      malformedPassed++;
    });
  });

  group('Large payloads', () {
    test('5 MiB SHA-256 succeeds', () {
      expect(api.sha256(Uint8List(5 * 1024 * 1024)).length, 32);
      massivePassed++;
    });

    test('1 MiB AES-CBC round-trips', () {
      final data = Uint8List(1024 * 1024);
      final ciphertext = api.aes128CbcEncrypt(key16, iv16, data);
      expect(api.aes128CbcDecrypt(key16, iv16, ciphertext), data);
      massivePassed++;
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  tearDownAll(() {
    const zeroLengthTested = 4;
    const malformedTested = 4;
    const massiveTested = 2;
    final passed = zeroLengthPassed + malformedPassed + massivePassed;
    const total = zeroLengthTested + malformedTested + massiveTested;
    _collector.setFuzzingMetrics(
      FuzzingMetrics(
        malformedPayloadsTested: malformedTested,
        malformedPayloadsSafelyRejected: malformedPassed,
        zeroLengthInputsTested: zeroLengthTested,
        zeroLengthInputsSafelyHandled: zeroLengthPassed,
        massivePayloadsTested: massiveTested,
        massivePayloadsSafelyHandled: massivePassed,
        nullPointerTests: 0,
        nullPointerSafelyHandled: 0,
        totalEdgeCases: total,
        safelyRejected: passed,
        rejectionRate: passed / total,
        summary: '$passed/$total edge cases behaved as specified',
      ),
    );
  });
}
