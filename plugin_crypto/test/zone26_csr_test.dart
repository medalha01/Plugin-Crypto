@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/csr/openssl_csr_generator.dart';
import 'package:plugin_crypto/src/crypto/models/csr_data.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone26', 'CSR Generation');

  late OpenSslCsrGenerator generator;
  late KeyPair rsaKeyPair;
  late KeyPair ecKeyPair;

  setUpAll(() {
    final bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    generator = OpenSslCsrGenerator(PluginCryptoContext(bindings));

    final api = PluginCryptoAPI.instance;
    rsaKeyPair = api.generateRsaKeyPair(2048);
    ecKeyPair = api.generateEcKeyPair('prime256v1');
  });


  group('CSR Generation — RSA-2048', () {
    test('generates DER bytes with non-empty output', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(
            commonName: 'rsa-test.example.com',
            organization: 'TestOrg',
            country: 'US',
          ),
          subjectKeyPair: rsaKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isA<Uint8List>());
          expect(value.derBytes, isNotEmpty);
          expect(value.derBytes.length, greaterThan(100));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('generates valid PEM with correct markers', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'pem-test-rsa.local'),
          subjectKeyPair: rsaKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(
            value.pemString,
            contains('-----BEGIN CERTIFICATE REQUEST-----'),
          );
          expect(
            value.pemString,
            contains('-----END CERTIFICATE REQUEST-----'),
          );
          final lines = value.pemString.split('\n');
          expect(lines.length, greaterThan(3));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });
  });


  group('CSR Generation — EC-P256', () {
    test('generates DER bytes with non-empty output', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(
            commonName: 'ec-test.example.com',
            organization: 'ECOrg',
            state: 'California',
            country: 'US',
          ),
          subjectKeyPair: ecKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isA<Uint8List>());
          expect(value.derBytes, isNotEmpty);
          expect(value.derBytes.length, greaterThan(100));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('generates valid PEM with correct markers', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'pem-ec-test.local'),
          subjectKeyPair: ecKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(
            value.pemString,
            startsWith('-----BEGIN CERTIFICATE REQUEST-----'),
          );
          expect(
            value.pemString,
            endsWith('-----END CERTIFICATE REQUEST-----\n'),
          );
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });
  });


  group('CSR DNS SAN Extension', () {
    test('generates CSR with DNS SANs', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'san-test.local'),
          subjectKeyPair: rsaKeyPair,
          dnsNames: ['www.example.com', 'api.example.com', 'm.example.com'],
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isNotEmpty);
          expect(value.pemString, isNotEmpty);
          expect(value.subjectDn, isNotEmpty);
          expect(value.subjectDn, contains('CN=san-test.local'));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('many SANs edge case — 50 DNS names succeeds', () {
      final manyNames = List.generate(50, (final i) => 'host$i.example.com');

      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'many-san.local'),
          subjectKeyPair: rsaKeyPair,
          dnsNames: manyNames,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isNotEmpty);
          expect(value.derBytes.length, greaterThan(500));
          expect(value.pemString, isNotEmpty);
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });
  });


  group('CSR PEM Format', () {
    test('PEM output has valid base64 structure between markers', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'format-test.local'),
          subjectKeyPair: rsaKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          final pem = value.pemString;

          expect(pem, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
          expect(pem, contains('-----END CERTIFICATE REQUEST-----'));

          final headerEnd = pem.indexOf('\n');
          final footerStart = pem.indexOf('-----END');
          if (headerEnd != -1 && footerStart != -1) {
            final body = pem.substring(headerEnd + 1, footerStart).trim();
            expect(body, isNotEmpty);
            expect(body.replaceAll('\n', ''), matches(r'^[A-Za-z0-9+/=]+$'));
          }
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });
  });


  group('CSR Validation & Error Handling', () {
    test('empty commonName is rejected with CsrError', () {
      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: ''),
          subjectKeyPair: rsaKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty commonName');
        case CryptoFailure(:final error):
          expect(error, isA<CsrError>());
          expect(error.message, contains('commonName'));
      }
    });

    test('null/empty keyPair is rejected with CsrError', () {
      const emptyKeyPair = KeyPair(publicKeyPem: '', privateKeyPem: '');

      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'test.local'),
          subjectKeyPair: emptyKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty key pair');
        case CryptoFailure(:final error):
          expect(error, isA<CsrError>());
          expect(error.message, contains('privateKeyPem'));
      }
    });

    test('invalid private key PEM fails with CsrError', () {
      final badKeyPair = KeyPair(
        publicKeyPem: 'not-a-valid-key',
        privateKeyPem:
            '-----BEGIN PRIVATE KEY-----\n'
            'this-is-totally-garbage-base64-but-valid-structure\n'
            '-----END PRIVATE KEY-----\n',
      );

      final result = generator.generate(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'bad-key.local'),
          subjectKeyPair: badKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for invalid private key PEM');
        case CryptoFailure(:final error):
          expect(error, isA<CsrError>());
          expect(
            error.message,
            anyOf(
              contains('private key'),
              contains('X509_REQ'),
              contains('Failed to load'),
            ),
          );
      }
    });
  });

  m?.endZone();
}
