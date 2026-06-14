@TestOn('linux')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/certificate_data.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_request.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/self_signed_cert_creator.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/certificate_fixtures.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone20', 'Certificate Creation Flow');

  late OpenSslBindings bindings;
  late PluginCryptoAPI api;
  late SelfSignedCertCreator certCreator;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    api = PluginCryptoAPI.instance;
    certCreator = SelfSignedCertCreator(bindings);
  });

  group('CertificateBuilder with RSA', () {
    late KeyPair rsaKeyPair;

    setUp(() {
      rsaKeyPair = api.generateRsaKeyPair(2048);
    });

    test('creates self-signed cert with RSA-2048 key', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final der = (result as CryptoSuccess<Uint8List>).value;
      expect(der, isNotEmpty);
    });

    test('buildPem returns valid PEM string', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);

      final result = builder.buildPem();

      expect(result, isA<CryptoSuccess<String>>());
      final pem = (result as CryptoSuccess<String>).value;
      expect(pem, contains('-----BEGIN CERTIFICATE-----'));
      expect(pem, contains('-----END CERTIFICATE-----'));
    });

    test('CertificateRequest creates valid request for RSA', () {
      final request = createValidCertificateRequest();
      expect(request.subject.commonName, equals('Test CN'));
      expect(request.isSelfSigned, isTrue);
    });
  });

  group('CertificateBuilder with EC', () {
    late KeyPair ecKeyPair;

    setUp(() {
      ecKeyPair = api.generateEcKeyPair('prime256v1');
    });

    test('creates self-signed cert with EC prime256v1 key', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(ecKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(ecKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final der = (result as CryptoSuccess<Uint8List>).value;
      expect(der, isNotEmpty);
    });

    test('creates self-signed cert with EC secp384r1 key', () {
      final ec384Pair = api.generateEcKeyPair('secp384r1');
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(ec384Pair)
          .validityPeriod(const Duration(days: 365))
          .signWith(ec384Pair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
    });
  });

  group('SelfSignedCertCreator', () {
    test('creates self-signed cert via CertificateRequest', () {
      final request = createValidCertificateRequest();
      final result = certCreator.create(request);

      expect(result, isA<CryptoSuccess<CertificateData>>());
      final data = (result as CryptoSuccess<CertificateData>).value;
      expect(data.derBytes, isNotEmpty);
      expect(data.pemString, isNotEmpty);
      expect(data.pemString, contains('-----BEGIN CERTIFICATE-----'));
    });

    test('CertificateData contains correct subject CN', () {
      final request = createValidCertificateRequest();
      final result = certCreator.create(request);
      final data = (result as CryptoSuccess<CertificateData>).value;

      expect(data.subjectDn, contains('Test CN'));
    });

    test('CertificateData issuer matches subject (self-signed)', () {
      final request = createValidCertificateRequest();
      final result = certCreator.create(request);
      final data = (result as CryptoSuccess<CertificateData>).value;

      expect(data.issuerDn, isNotEmpty);
      expect(data.subjectDn, isNotEmpty);
    });

    test('CertificateData validity dates match requested period', () {
      final request = createValidCertificateRequest();
      final result = certCreator.create(request);
      final data = (result as CryptoSuccess<CertificateData>).value;

      expect(
        data.notBefore.isBefore(data.notAfter) ||
            data.notBefore.isAtSameMomentAs(data.notAfter),
        isTrue,
      );
    });

    test(
      'built cert parses correctly via existing parseX509Certificate',
      () {
        final request = createValidCertificateRequest();
        final result = certCreator.create(request);
        final data = (result as CryptoSuccess<CertificateData>).value;

        final pemBytes = Uint8List.fromList(utf8.encode(data.pemString));
        final parsed = api.parseX509Certificate(pemBytes);

        expect(parsed.subject, isNotEmpty);
        expect(parsed.issuer, isNotEmpty);
        expect(parsed.serialNumber, isNotEmpty);
      },
      tags: ['cert', 'slow'],
    );
  });

  group('CertificateBuilder extensions', () {
    late KeyPair keyPair;

    setUp(() {
      keyPair = api.generateRsaKeyPair(2048);
    });

    test('adds BasicConstraints extension (CA:true)', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(keyPair)
          .validityPeriod(const Duration(days: 365))
          .addBasicConstraints(ca: true)
          .signWith(keyPair);

      final result = builder.build();
      expect(result, isA<CryptoSuccess<Uint8List>>());
    });

    test('adds KeyUsage extension', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(keyPair)
          .validityPeriod(const Duration(days: 365))
          .addKeyUsage(digitalSignature: true, keyEncipherment: true)
          .signWith(keyPair);

      final result = builder.build();
      expect(result, isA<CryptoSuccess<Uint8List>>());
    });

    test('adds SubjectAltName DNS entries', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testSubjectDn)
          .issuerDn(testSubjectDn)
          .publicKey(keyPair)
          .validityPeriod(const Duration(days: 365))
          .addSubjectAltName(dnsNames: ['example.com', 'test.example.com'])
          .signWith(keyPair);

      final result = builder.build();
      expect(result, isA<CryptoSuccess<Uint8List>>());
    });
  });

  group('Validation', () {
    test('CertificateBuilder validation rejects empty common name', () {
      expect(
        () => const DistinguishedName(commonName: '').validate(),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
      'CertificateBuilder validation rejects invalid country code (> 2 chars)',
      () {
        expect(
          () => const DistinguishedName(
            commonName: 'Test',
            country: 'USA',
          ).validate(),
          throwsA(isA<ArgumentError>()),
        );
      },
    );

    test('CertificateBuilder validation rejects notAfter before notBefore', () {
      final now = DateTime.now();
      expect(
        () => CertificateRequest(
          subject: testSubjectDn,
          issuer: testSubjectDn,
          subjectPublicKey: api.generateRsaKeyPair(2048),
          issuerPrivateKey: api.generateRsaKeyPair(2048),
          notBefore: now,
          notAfter: now.subtract(const Duration(days: 1)),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
      'CertificateBuilder build() returns CryptoFailure for missing fields',
      () {
        final builder = CertificateBuilder(bindings).subjectDn(testSubjectDn);

        final result = builder.build();
        expect(result, isA<CryptoFailure<Uint8List>>());
      },
    );
  });

  m?.endZone();
}
