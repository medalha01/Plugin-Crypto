import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

late String rsaPubKey;
late String rsaPrivKey;

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone06', 'RSA');

  setUpAll(() {
    final api = PluginCryptoAPI.instance;
    final keyPair = api.generateRsaKeyPair(2048);
    rsaPubKey = keyPair.publicKeyPem;
    rsaPrivKey = keyPair.privateKeyPem;
  });

  group('RSA Key Gen', () {
    test('generateRsaKeyPair(2048) returns KeyPair with non-empty PEMs', () {
      final api = PluginCryptoAPI.instance;
      final kp = api.generateRsaKeyPair(2048);

      expect(kp.publicKeyPem, isNotEmpty);
      expect(kp.privateKeyPem, isNotEmpty);
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });
  });

  group('RSA Sign & Verify', () {
    test('sign and verify returns true', () {
      final api = PluginCryptoAPI.instance;
      final data = utf8.encode('Hello, RSA!');
      final privKeyBytes = Uint8List.fromList(utf8.encode(rsaPrivKey));
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));

      final signature = api.sign(Uint8List.fromList(data), privKeyBytes);
      final result = api.verify(
        Uint8List.fromList(data),
        pubKeyBytes,
        signature,
      );

      expect(result, isTrue);
    });

    test('verify with modified data returns false', () {
      final api = PluginCryptoAPI.instance;
      final data = utf8.encode('Hello, RSA!');
      final privKeyBytes = Uint8List.fromList(utf8.encode(rsaPrivKey));
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));

      final signature = api.sign(Uint8List.fromList(data), privKeyBytes);
      final modifiedData = utf8.encode('Hello, RSA?');
      final result = api.verify(
        Uint8List.fromList(modifiedData),
        pubKeyBytes,
        signature,
      );

      expect(result, isFalse);
    });

    test('verify with wrong signature returns false', () {
      final api = PluginCryptoAPI.instance;
      final data = utf8.encode('Hello, RSA!');
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));

      final wrongSignature = Uint8List(256);
      final result = api.verify(
        Uint8List.fromList(data),
        pubKeyBytes,
        wrongSignature,
      );

      expect(result, isFalse);
    });

    test('sign with sha512 and sha3_256 hashAlgorithm param', () {
      final api = PluginCryptoAPI.instance;
      final data = utf8.encode('Hash algorithm test');
      final privKeyBytes = Uint8List.fromList(utf8.encode(rsaPrivKey));
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));

      final sig512 = api.sign(
        Uint8List.fromList(data),
        privKeyBytes,
        hashAlgorithm: 'sha512',
      );
      expect(
        api.verify(
          Uint8List.fromList(data),
          pubKeyBytes,
          sig512,
          hashAlgorithm: 'sha512',
        ),
        isTrue,
      );

      final sig3 = api.sign(
        Uint8List.fromList(data),
        privKeyBytes,
        hashAlgorithm: 'sha3_256',
      );
      expect(
        api.verify(
          Uint8List.fromList(data),
          pubKeyBytes,
          sig3,
          hashAlgorithm: 'sha3_256',
        ),
        isTrue,
      );
    });
  });

  group('RSA Encrypt & Decrypt', () {
    test('encrypt returns different ciphertext', () {
      final api = PluginCryptoAPI.instance;
      final plaintext = Uint8List.fromList(utf8.encode('Secret message'));
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));

      final ciphertext = api.rsaEncrypt(pubKeyBytes, plaintext);

      expect(ciphertext, isNot(equals(plaintext)));
    });

    test('decrypt returns original', () {
      final api = PluginCryptoAPI.instance;
      final plaintext = Uint8List.fromList(utf8.encode('Secret message'));
      final pubKeyBytes = Uint8List.fromList(utf8.encode(rsaPubKey));
      final privKeyBytes = Uint8List.fromList(utf8.encode(rsaPrivKey));

      final ciphertext = api.rsaEncrypt(pubKeyBytes, plaintext);
      final decrypted = api.rsaDecrypt(privKeyBytes, ciphertext);

      expect(decrypted, equals(plaintext));
    });

    test('encrypt with private key throws', () {
      final api = PluginCryptoAPI.instance;
      final plaintext = Uint8List.fromList(utf8.encode('Secret message'));
      final privKeyBytes = Uint8List.fromList(utf8.encode(rsaPrivKey));

      expect(() => api.rsaEncrypt(privKeyBytes, plaintext), throwsA(anything));
    });
  });

  m?.endZone();
}
