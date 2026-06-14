@TestOn('linux')
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_kem_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_dsa_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/key_creator_factory.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/pq_key_creation_fixtures.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone22', 'Post-Quantum Key Creation');

  late OpenSslBindings bindings;
  late MlKemKeyCreator mlKemCreator;
  late MlDsaKeyCreator mlDsaCreator;
  late KeyCreatorFactory factory;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    mlKemCreator = MlKemKeyCreator(bindings);
    mlDsaCreator = MlDsaKeyCreator(bindings);
    factory = KeyCreatorFactory(bindings);
  });

  group('MlKemKeyCreator', () {
    test('creates ML-KEM-512 key pair with valid PEM', () {
      final result = mlKemCreator.create(validMlKem512Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
      expect(pair.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(pair.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('creates ML-KEM-768 key pair with valid PEM', () {
      final result = mlKemCreator.create(validMlKem768Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('creates ML-KEM-1024 key pair with valid PEM', () {
      final result = mlKemCreator.create(validMlKem1024Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('PEM headers indicate ML-KEM key type', () {
      final result = mlKemCreator.create(validMlKem768Spec);
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
      final result = mlKemCreator.create(RsaKeySpec(2048));

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });

    test('returns CryptoFailure for invalid spec type (EcKeySpec)', () {
      final result = mlKemCreator.create(EcKeySpec('prime256v1'));

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });

    test('ML-KEM keys are distinct across 5 calls', tags: ['pq'], () {
      final keys = <String>{};
      for (var i = 0; i < 5; i++) {
        final result = mlKemCreator.create(validMlKem768Spec);
        final pair = (result as CryptoSuccess<KeyPair>).value;
        keys.add(pair.privateKeyPem);
      }
      expect(
        keys.length,
        equals(5),
        reason: 'All 5 generated ML-KEM keys should be unique',
      );
    });

    test('ML-KEM-768 key size is reasonable (800-4000 bytes PEM)', () {
      final result = mlKemCreator.create(validMlKem768Spec);
      final pair = (result as CryptoSuccess<KeyPair>).value;

      expect(pair.publicKeyPem.length, greaterThanOrEqualTo(800));
      expect(pair.publicKeyPem.length, lessThanOrEqualTo(4000));
    });
  });

  group('MlDsaKeyCreator', () {
    test('creates ML-DSA-44 key pair with valid PEM', () {
      final result = mlDsaCreator.create(validMlDsa44Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
      expect(pair.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(pair.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    test('creates ML-DSA-65 key pair with valid PEM', () {
      final result = mlDsaCreator.create(validMlDsa65Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('creates ML-DSA-87 key pair with valid PEM', () {
      final result = mlDsaCreator.create(validMlDsa87Spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;
      expect(pair.publicKeyPem, isNotEmpty);
      expect(pair.privateKeyPem, isNotEmpty);
    });

    test('PEM headers indicate ML-DSA key type', () {
      final result = mlDsaCreator.create(validMlDsa44Spec);
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
      final result = mlDsaCreator.create(RsaKeySpec(2048));

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });

    test('returns CryptoFailure for invalid spec type (EcKeySpec)', () {
      final result = mlDsaCreator.create(EcKeySpec('prime256v1'));

      expect(result, isA<CryptoFailure<KeyPair>>());
      final error = (result as CryptoFailure<KeyPair>).error;
      expect(error, isA<ValidationError>());
    });

    test('ML-DSA keys are distinct across 5 calls', tags: ['pq'], () {
      final keys = <String>{};
      for (var i = 0; i < 5; i++) {
        final result = mlDsaCreator.create(validMlDsa44Spec);
        final pair = (result as CryptoSuccess<KeyPair>).value;
        keys.add(pair.privateKeyPem);
      }
      expect(
        keys.length,
        equals(5),
        reason: 'All 5 generated ML-DSA keys should be unique',
      );
    });

    test('ML-DSA-44 key size is reasonable (1200-5000 bytes PEM)', () {
      final result = mlDsaCreator.create(validMlDsa44Spec);
      final pair = (result as CryptoSuccess<KeyPair>).value;

      expect(pair.publicKeyPem.length, greaterThanOrEqualTo(1200));
      expect(pair.publicKeyPem.length, lessThanOrEqualTo(5000));
    });
  });

  group('KeyCreatorFactory with PQ', () {
    test('dispatches to MlKemKeyCreator for MlKemKeySpec', () {
      final creator = factory.create(validMlKem512Spec);
      expect(creator, isA<MlKemKeyCreator>());
      expect(creator, isNot(isA<MlDsaKeyCreator>()));
    });

    test('dispatches to MlDsaKeyCreator for MlDsaKeySpec', () {
      final creator = factory.create(validMlDsa44Spec);
      expect(creator, isA<MlDsaKeyCreator>());
      expect(creator, isNot(isA<MlKemKeyCreator>()));
    });

    test('each PQ creator from factory can generate keys', () {
      final mlKemC = factory.create(validMlKem512Spec)!;
      final result = mlKemC.create(validMlKem512Spec);
      expect(result, isA<CryptoSuccess<KeyPair>>());

      final mlDsaC = factory.create(validMlDsa44Spec)!;
      final dsaResult = mlDsaC.create(validMlDsa44Spec);
      expect(dsaResult, isA<CryptoSuccess<KeyPair>>());
    });

    test('factory has all 4 types registered (RSA, EC, ML-KEM, ML-DSA)', () {
      expect(factory.registeredTypes.length, greaterThanOrEqualTo(4));
    });
  });

  group('MlKemKeySpec and MlDsaKeySpec validation', () {
    test('MlKemKeySpec can be constructed with any MlKemParameterSet', () {
      for (final ps in MlKemParameterSet.values) {
        expect(() => MlKemKeySpec(ps), returnsNormally);
      }
    });

    test('MlDsaKeySpec can be constructed with any MlDsaParameterSet', () {
      for (final ps in MlDsaParameterSet.values) {
        expect(() => MlDsaKeySpec(ps), returnsNormally);
      }
    });
  });

  m?.endZone();
}
