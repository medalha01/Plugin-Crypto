import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone17', 'ECDSA Edge Cases');

  late PluginCryptoAPI crypto;

  setUp(() {
    crypto = PluginCryptoAPI.instance;
  });


  group('Invalid curve name', () {
    test('generateEcKeyPair with invalid_curve throws StateError', () {
      expect(
        () => crypto.generateEcKeyPair('invalid_curve'),
        throwsA(isA<StateError>()),
      );
    });
  });


  group('Curve name case sensitivity', () {
    test('prime256v1 works, PRIME256V1 throws', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      expect(kp, isA<KeyPair>());
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));

      expect(() => crypto.generateEcKeyPair('PRIME256V1'), throwsA(anything));
    });
  });


  group('EC keygen minimum viable curve', () {
    test('secp224r1 keygen does not crash', () {
      try {
        final kp = crypto.generateEcKeyPair('secp224r1');
        expect(kp, isA<KeyPair>());
        expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
        expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
      } on StateError {
      }
    });
  });


  group('Sign+Verify SHA-512 with EC key', () {
    test('sign and verify round-trip with sha512 hashAlgorithm', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('EC sha512 round-trip'));

      final sig = crypto.sign(
        data,
        _pem(kp.privateKeyPem),
        hashAlgorithm: 'sha512',
      );
      final ok = crypto.verify(
        data,
        _pem(kp.publicKeyPem),
        sig,
        hashAlgorithm: 'sha512',
      );

      expect(ok, isTrue);
    });
  });


  group('Sign+Verify SHA3-256 with EC key', () {
    test('sign and verify round-trip with sha3_256 hashAlgorithm', () {
      final kp = crypto.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('EC sha3_256 round-trip'));

      final sig = crypto.sign(
        data,
        _pem(kp.privateKeyPem),
        hashAlgorithm: 'sha3_256',
      );
      final ok = crypto.verify(
        data,
        _pem(kp.publicKeyPem),
        sig,
        hashAlgorithm: 'sha3_256',
      );

      expect(ok, isTrue);
    });
  });

  m?.endZone();
}
