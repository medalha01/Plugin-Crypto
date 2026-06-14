@TestOn('linux')
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/rsa_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ec_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/key_creator_factory.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/key_creation_fixtures.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone19', 'Key Creation Flow');

  late OpenSslBindings bindings;
  late RsaKeyCreator rsaCreator;
  late EcKeyCreator ecCreator;
  late KeyCreatorFactory factory;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    rsaCreator = RsaKeyCreator(bindings);
    ecCreator = EcKeyCreator(bindings);
    factory = KeyCreatorFactory(bindings);
  });

  group('RsaKeyCreator', () {
    test('creates 2048-bit RSA key pair with valid PEM', () {
      final result = rsaCreator.create(validRsa2048Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
      expect(pair.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(pair.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('creates 4096-bit RSA key pair with valid PEM', () {
      final result = rsaCreator.create(validRsa4096Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    }, tags: ['keygen', 'slow']);

    test('creates 3072-bit RSA key pair with valid PEM', () {
      final result = rsaCreator.create(validRsa3072Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('PEM headers indicate RSA key type', () {
      final result = rsaCreator.create(validRsa2048Spec);
      final pair = (result as CryptoSuccess<KeyPair>).value;

      expect(
        pair.publicKeyPem.contains('BEGIN') &&
            pair.publicKeyPem.contains('KEY'),
        isTrue,
      );
      expect(
        pair.privateKeyPem.contains('BEGIN') &&
            pair.privateKeyPem.contains('KEY'),
        isTrue,
      );
    });

    test('returns CryptoFailure for invalid spec type (EcKeySpec)', () {
      final result = rsaCreator.create(validEcP256Spec);

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });
  });

  group('EcKeyCreator', () {
    test('creates prime256v1 EC key pair with valid PEM', () {
      final result = ecCreator.create(validEcP256Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
      expect(pair.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(pair.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('creates secp384r1 EC key pair with valid PEM', () {
      final result = ecCreator.create(validEcP384Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('creates secp521r1 EC key pair with valid PEM', () {
      final result = ecCreator.create(validEcP521Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('PEM headers indicate EC key type', () {
      final result = ecCreator.create(validEcP256Spec);
      final pair = (result as CryptoSuccess<KeyPair>).value;

      expect(
        pair.publicKeyPem.contains('BEGIN') &&
            pair.publicKeyPem.contains('KEY'),
        isTrue,
      );
      expect(
        pair.privateKeyPem.contains('BEGIN') &&
            pair.privateKeyPem.contains('KEY'),
        isTrue,
      );
    });

    test('returns CryptoFailure for invalid spec type (RsaKeySpec)', () {
      final result = ecCreator.create(validRsa2048Spec);

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });
  });

  group('KeyCreatorFactory', () {
    test('dispatches to RsaKeyCreator for RsaKeySpec', () {
      final creator = factory.create(validRsa2048Spec);
      expect(creator, isA<RsaKeyCreator>());
      expect(creator, isNot(isA<EcKeyCreator>()));
    });

    test('dispatches to EcKeyCreator for EcKeySpec', () {
      final creator = factory.create(validEcP256Spec);
      expect(creator, isA<EcKeyCreator>());
      expect(creator, isNot(isA<RsaKeyCreator>()));
    });

    test('each creator from factory can generate keys', () {
      final rsaC = factory.create(validRsa2048Spec)!;
      final result = rsaC.create(validRsa2048Spec);
      expect(result, isA<CryptoSuccess<KeyPair>>());

      final ecC = factory.create(validEcP256Spec)!;
      final ecResult = ecC.create(validEcP256Spec);
      expect(ecResult, isA<CryptoSuccess<KeyPair>>());
    });
  });

  group('KeySpec validation', () {
    test('RsaKeySpec validation rejects bits < 1024', () {
      expect(() => RsaKeySpec(512), throwsA(isA<ArgumentError>()));
    });

    test('RsaKeySpec validation rejects non-multiple-of-1024 bits', () {
      expect(() => RsaKeySpec(1536), throwsA(isA<ArgumentError>()));
    });

    test('RsaKeySpec validation rejects bits > 16384', () {
      expect(() => RsaKeySpec(32768), throwsA(isA<ArgumentError>()));
    });

    test('EcKeySpec validation rejects unknown curve name', () {
      expect(() => EcKeySpec('brainpoolP256r1'), throwsA(isA<ArgumentError>()));
    });

    test('EcKeySpec validation accepts all supported curves', () {
      for (final curve in EcCurve.all) {
        expect(() => EcKeySpec(curve), returnsNormally);
      }
    });
  });

  group('Key uniqueness', () {
    test('generated RSA keys are distinct across 10 calls', () {
      final keys = <String>{};
      for (var i = 0; i < 10; i++) {
        final result = rsaCreator.create(validRsa2048Spec);
        final pair = (result as CryptoSuccess<KeyPair>).value;
        keys.add(pair.privateKeyPem);
      }
      expect(
        keys.length,
        equals(10),
        reason: 'All 10 generated keys should be unique',
      );
    });

    test('generated EC keys are distinct across 10 calls', () {
      final keys = <String>{};
      for (var i = 0; i < 10; i++) {
        final result = ecCreator.create(validEcP256Spec);
        final pair = (result as CryptoSuccess<KeyPair>).value;
        keys.add(pair.privateKeyPem);
      }
      expect(
        keys.length,
        equals(10),
        reason: 'All 10 generated EC keys should be unique',
      );
    });
  });

  m?.endZone();
}
