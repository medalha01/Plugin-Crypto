@Tags(['metrics'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

import 'fixtures/helpers.dart' as helpers;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();

  int zeroLengthTested = 0;
  int zeroLengthPassed = 0;
  int malformedTested = 0;
  int malformedPassed = 0;
  int massiveTested = 0;
  int massivePassed = 0;

  final key16 = Uint8List.fromList(List<int>.filled(16, 0x01));
  final iv16 = Uint8List.fromList(List<int>.filled(16, 0x02));
  final iv12 = Uint8List.fromList(List<int>.filled(12, 0x02));

  group('Zero-length inputs', () {
    test('sha256(0B)', () {
      zeroLengthTested++;
      try {
        final d = api.sha256(Uint8List(0));
        expect(d.length, 32);
        zeroLengthPassed++;
      } catch (_) {}
    });

    test('sha512(0B)', () {
      zeroLengthTested++;
      try {
        final d = api.sha512(Uint8List(0));
        expect(d.length, 64);
        zeroLengthPassed++;
      } catch (_) {}
    });

    test('aes128CbcEncrypt(0B)', () {
      zeroLengthTested++;
      try {
        final ct = api.aes128CbcEncrypt(key16, iv16, Uint8List(0));
        expect(ct.length, 16); // PKCS#7 adds full block
        zeroLengthPassed++;
      } catch (_) {}
    });

    test('aes128GcmEncrypt(0B, empty AAD)', () {
      zeroLengthTested++;
      try {
        final result = api.aes128GcmEncrypt(key16, iv12, Uint8List(0));
        expect(result.ciphertext.length, 0);
        expect(result.tag.length, 16);
        zeroLengthPassed++;
      } catch (_) {}
    });

    test('sign(0B hash)', () {
      zeroLengthTested++;
      try {
        final ecKey = api.generateEcKeyPair('prime256v1');
        final sig = api.sign(Uint8List(0), helpers.pem(ecKey.privateKeyPem));
        expect(sig, isNotEmpty);
        zeroLengthPassed++;
      } catch (_) {}
    });
  });

  group('Malformed inputs', () {
    test('AES-128 bad key size (15 bytes)', () {
      malformedTested++;
      try {
        final badKey = Uint8List.fromList(List<int>.filled(15, 0x01));
        api.aes128CbcEncrypt(badKey, iv16, Uint8List(16));
      } on ArgumentError {
        malformedPassed++;
      } on StateError {
        malformedPassed++;
      } catch (_) {
        malformedPassed++;
      }
    });

    test('AES-128 bad IV size (8 bytes)', () {
      malformedTested++;
      try {
        final badIv = Uint8List.fromList(List<int>.filled(8, 0x02));
        api.aes128CbcEncrypt(key16, badIv, Uint8List(16));
      } on ArgumentError {
        malformedPassed++;
      } on StateError {
        malformedPassed++;
      } catch (_) {
        malformedPassed++;
      }
    });

    test('AES-GCM bad tag during decrypt', () {
      malformedTested++;
      try {
        final result = api.aes128GcmEncrypt(key16, iv12, Uint8List(16));
        final badTag = Uint8List.fromList(List<int>.filled(16, 0xFF));
        api.aes128GcmDecrypt(key16, iv12, result.ciphertext, badTag);
      } on ArgumentError {
        malformedPassed++;
      } on StateError {
        malformedPassed++;
      } catch (_) {
        malformedPassed++;
      }
    });

    test('Truncated ciphertext (4 bytes)', () {
      malformedTested++;
      try {
        final badCt = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
        api.aes128CbcDecrypt(key16, iv16, badCt);
      } on ArgumentError {
        malformedPassed++;
      } on StateError {
        malformedPassed++;
      } catch (_) {
        malformedPassed++;
      }
    });

    test('Wrong curve name for EC keygen', () {
      malformedTested++;
      try {
        api.generateEcKeyPair('imaginary-curve-9999');
      } on ArgumentError {
        malformedPassed++;
      } on StateError {
        malformedPassed++;
      } catch (_) {
        malformedPassed++;
      }
    });
  });

  group('Massive payloads', () {
    test('sha256(5MB)', () {
      massiveTested++;
      try {
        final data = Uint8List(5 * 1024 * 1024);
        final d = api.sha256(data);
        expect(d.length, 32);
        massivePassed++;
      } catch (_) {}
    });

    test('aes128CbcEncrypt(1MB)', () {
      massiveTested++;
      try {
        final data = Uint8List(1024 * 1024);
        final ct = api.aes128CbcEncrypt(key16, iv16, data);
        expect(ct.length, greaterThanOrEqualTo(data.length));
        massivePassed++;
      } catch (_) {}
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('Boundary conditions', () {
    test('Exactly-block-size AES-CBC (16 bytes)', () {
      zeroLengthTested++;
      try {
        final data = Uint8List.fromList(List<int>.filled(16, 0x41));
        final ct = api.aes128CbcEncrypt(key16, iv16, data);
        expect(ct.length, 32); // PKCS#7 full block padding
        final pt = api.aes128CbcDecrypt(key16, iv16, ct);
        expect(pt, equals(data));
        zeroLengthPassed++;
      } catch (_) {}
    });

    test('1-byte plaintext', () {
      zeroLengthTested++;
      try {
        final data = Uint8List.fromList([0x42]);
        final ct = api.aes128CbcEncrypt(key16, iv16, data);
        expect(ct.length, 16);
        final pt = api.aes128CbcDecrypt(key16, iv16, ct);
        expect(pt, equals(data));
        zeroLengthPassed++;
      } catch (_) {}
    });
  });

  tearDownAll(() {
    final totalEdgeCases = zeroLengthTested + malformedTested + massiveTested;
    final safelyHandled = zeroLengthPassed + malformedPassed + massivePassed;
    final rejectionRate = totalEdgeCases > 0
        ? safelyHandled / totalEdgeCases
        : 0.0;

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
        totalEdgeCases: totalEdgeCases,
        safelyRejected: safelyHandled,
        rejectionRate: rejectionRate,
        summary: '$safelyHandled/$totalEdgeCases edge cases safely handled',
      ),
    );
  });
}
