import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone16', 'RSA Edge Cases');

  late PluginCryptoAPI crypto;

  setUp(() {
    crypto = PluginCryptoAPI.instance;
  });


  group('RSA key gen edge cases', () {
    test('generateRsaKeyPair(1024) returns valid KeyPair', () {
      final kp = crypto.generateRsaKeyPair(1024);

      expect(kp, isA<KeyPair>());
      expect(kp.publicKeyPem, isNotEmpty);
      expect(kp.privateKeyPem, isNotEmpty);
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('RSA-1024 sign/verify round-trip passes', () {
      final kp = crypto.generateRsaKeyPair(1024);
      final data = Uint8List.fromList(utf8.encode('RSA-1024 round-trip'));

      final sig = crypto.sign(data, _pem(kp.privateKeyPem));
      final ok = crypto.verify(data, _pem(kp.publicKeyPem), sig);

      expect(ok, isTrue);
    });

    test('generateRsaKeyPair(3072) returns valid KeyPair', () {
      final kp = crypto.generateRsaKeyPair(3072);

      expect(kp, isA<KeyPair>());
      expect(kp.publicKeyPem, isNotEmpty);
      expect(kp.privateKeyPem, isNotEmpty);
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('RSA-3072 sign/verify round-trip passes', () {
      final kp = crypto.generateRsaKeyPair(3072);
      final data = Uint8List.fromList(utf8.encode('RSA-3072 round-trip'));

      final sig = crypto.sign(data, _pem(kp.privateKeyPem));
      final ok = crypto.verify(data, _pem(kp.publicKeyPem), sig);

      expect(ok, isTrue);
    });
  });


  group('RSA PKCS#1 v1.5 max plaintext boundary', () {
    late KeyPair rsaKeyPair;

    setUpAll(() {
      rsaKeyPair = crypto.generateRsaKeyPair(2048);
    });

    test('245 bytes encrypt succeeds with RSA-2048 PKCS#1 v1.5', () {
      final plaintext = crypto.randomBytes(245);
      final pubKeyBytes = _pem(rsaKeyPair.publicKeyPem);
      final privKeyBytes = _pem(rsaKeyPair.privateKeyPem);

      final ciphertext = crypto.rsaEncrypt(pubKeyBytes, plaintext);

      expect(ciphertext, isNotEmpty);
      expect(ciphertext, isNot(equals(plaintext)));

      final decrypted = crypto.rsaDecrypt(privKeyBytes, ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('246 bytes encrypt throws with RSA-2048 PKCS#1 v1.5', () {
      final plaintext = crypto.randomBytes(246);
      final pubKeyBytes = _pem(rsaKeyPair.publicKeyPem);

      expect(
        () => crypto.rsaEncrypt(pubKeyBytes, plaintext),
        throwsA(anything),
      );
    });
  });


  group('RSA sign with unsupported hash algorithm', () {
    late KeyPair rsaKeyPair;
    late Uint8List data;

    setUpAll(() {
      rsaKeyPair = crypto.generateRsaKeyPair(2048);
      data = Uint8List.fromList(utf8.encode('Unsupported hash test'));
    });

    test('hashAlgorithm: md5 throws ArgumentError', () {
      expect(
        () => crypto.sign(
          data,
          _pem(rsaKeyPair.privateKeyPem),
          hashAlgorithm: 'md5',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('sign+verify with sha384 hashAlgorithm works correctly', () {
      final privKeyBytes = _pem(rsaKeyPair.privateKeyPem);

      final signature = crypto.sign(data, privKeyBytes, hashAlgorithm: 'sha384');
      expect(signature, isNotEmpty,
          reason: 'RSA sign with sha384 must produce a non-empty signature');

      final verified = crypto.verify(
        data,
        _pem(rsaKeyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha384',
      );
      expect(verified, isTrue,
          reason: 'RSA sha384 signature must verify with correct key');
    });
  });

  m?.endZone();
}
