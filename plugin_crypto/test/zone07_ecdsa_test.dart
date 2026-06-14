import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone07', 'ECDSA');

  late PluginCryptoAPI crypto;

  setUp(() {
    crypto = PluginCryptoAPI.instance;
  });

  group('ECDSA prime256v1', () {
    test('generateEcKeyPair returns KeyPair with expected PEM headers', () {
      final kp = crypto.generateEcKeyPair('prime256v1');

      expect(kp, isA<KeyPair>());
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
    });

    test('sign returns non-empty signature', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('ECDSA prime256v1 signing'));

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );

      expect(sig, isNotNull);
      expect(sig.isNotEmpty, isTrue);
    });

    test('verify returns true for valid signature', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('ECDSA prime256v1 verify'));

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final ok = crypto.verify(
        data,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        sig,
      );

      expect(ok, isTrue);
    });

    test('verify with modified data returns false', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('original data'));
      final modified = Uint8List.fromList(utf8.encode('modified data'));

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final ok = crypto.verify(
        modified,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        sig,
      );

      expect(ok, isFalse);
    });

    test('verify with wrong signature returns false', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('payload for sig test'));

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final badSig = Uint8List.fromList(sig);
      badSig[badSig.length ~/ 2] ^= 0xFF;

      final ok = crypto.verify(
        data,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        badSig,
      );

      expect(ok, isFalse);
    });
  });

  group('ECDSA secp384r1', () {
    test('generateEcKeyPair and sign/verify round-trip passes', () {
      final kp = crypto.generateEcKeyPair('secp384r1');
      final data = Uint8List.fromList(
        utf8.encode('ECDSA secp384r1 round-trip'),
      );

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final ok = crypto.verify(
        data,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        sig,
      );

      expect(ok, isTrue);
    });

    test('verify tampered data returns false', () {
      final kp = crypto.generateEcKeyPair('secp384r1');
      final data = Uint8List.fromList(utf8.encode('original secp384r1 data'));
      final tampered = Uint8List.fromList(
        utf8.encode('tampered secp384r1 data'),
      );

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final ok = crypto.verify(
        tampered,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        sig,
      );

      expect(ok, isFalse);
    });
  });

  group('ECDSA secp521r1', () {
    test('generateEcKeyPair and sign/verify round-trip passes', () {
      final kp = crypto.generateEcKeyPair('secp521r1');
      final data = Uint8List.fromList(
        utf8.encode('ECDSA secp521r1 round-trip'),
      );

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kp.privateKeyPem)),
      );
      final ok = crypto.verify(
        data,
        Uint8List.fromList(utf8.encode(kp.publicKeyPem)),
        sig,
      );

      expect(ok, isTrue);
    });
  });

  group('Cross-key validation', () {
    test('sign with key A verify with key B returns false', () {
      final kpA = crypto.generateEcKeyPair('prime256v1');
      final kpB = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('cross-key validation data'));

      final sig = crypto.sign(
        data,
        Uint8List.fromList(utf8.encode(kpA.privateKeyPem)),
      );
      final ok = crypto.verify(
        data,
        Uint8List.fromList(utf8.encode(kpB.publicKeyPem)),
        sig,
      );

      expect(ok, isFalse);
    });
  });

  m?.endZone();
}
