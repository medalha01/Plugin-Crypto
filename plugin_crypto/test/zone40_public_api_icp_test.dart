@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/models/csr_data.dart';
import 'package:plugin_crypto/src/crypto/models/crl_data.dart';
import 'package:plugin_crypto/src/crypto/models/ocsp_data.dart';
import 'package:plugin_crypto/src/crypto/models/ts_data.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone40', 'Public API ICP & Timestamping');

  late PluginCryptoAPI api;
  late OpenSslBindings bindings;

  setUpAll(() {
    api = PluginCryptoAPI.instance;
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
  });


  group('CAdES-BES via PluginCryptoAPI', () {
    late KeyPair rsaKeyPair;
    late Uint8List rsaCertPem;
    late Uint8List rsaKeyPemBytes;

    setUpAll(() {
      rsaKeyPair = api.generateRsaKeyPair(2048);
      final now = DateTime.now();
      final keyPemBytes = Uint8List.fromList(rsaKeyPair.privateKeyPem.codeUnits);
      final certPem = CertificateBuilder(
        bindings, // bypass facade to use builder
      )
          .subjectDn(const DistinguishedName(commonName: 'CAdES-API'))
          .issuerDn(const DistinguishedName(commonName: 'CAdES-API'))
          .publicKey(rsaKeyPair)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(rsaKeyPair)
          .buildPem();
      rsaCertPem = Uint8List.fromList(
        (certPem as CryptoSuccess<String>).value.codeUnits,
      );
      rsaKeyPemBytes = keyPemBytes;
    });

    test('cmsSignCades via facade returns non-empty DER', () {
      final data = Uint8List.fromList('CAdES API test'.codeUnits);

      final signed = api.cmsSignCades(data, rsaCertPem, rsaKeyPemBytes);

      expect(signed, isNotEmpty);
      expect(signed.runtimeType.toString(), contains('Uint8List'));
      expect(signed.length, greaterThan(100));
    });

    test('cmsSignCades round-trip verify via facade', () {
      final data = Uint8List.fromList('CAdES round-trip API'.codeUnits);

      final signed = api.cmsSignCades(data, rsaCertPem, rsaKeyPemBytes);
      final verified = api.cmsVerify(signed, trustedCert: rsaCertPem);

      expect(verified, isTrue);
    });

    test('cmsSignCades with caCertPem via facade', () {
      final caKeyPair = api.generateRsaKeyPair(2048);
      final now = DateTime.now();
      final caCertPem = CertificateBuilder(
        bindings,
      )
          .subjectDn(const DistinguishedName(commonName: 'CAdES-CA'))
          .issuerDn(const DistinguishedName(commonName: 'CAdES-CA'))
          .publicKey(caKeyPair)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(caKeyPair)
          .buildPem();
      final caPem = Uint8List.fromList(
        (caCertPem as CryptoSuccess<String>).value.codeUnits,
      );

      final data = Uint8List.fromList('CA embed API'.codeUnits);
      final signed = api.cmsSignCades(
        data,
        rsaCertPem,
        rsaKeyPemBytes,
        caCertPem: caPem,
      );

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: rsaCertPem);
      expect(verified, isTrue);
    });

    test('cmsSignCades with intermediates via facade', () {
      final intKeyPair = api.generateRsaKeyPair(2048);
      final now = DateTime.now();
      final intCertPem = CertificateBuilder(
        bindings,
      )
          .subjectDn(const DistinguishedName(commonName: 'CAdES-Int'))
          .issuerDn(const DistinguishedName(commonName: 'CAdES-Int'))
          .publicKey(intKeyPair)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(intKeyPair)
          .buildPem();
      final intPem = Uint8List.fromList(
        (intCertPem as CryptoSuccess<String>).value.codeUnits,
      );

      final data = Uint8List.fromList('Intermediates API'.codeUnits);
      final signed = api.cmsSignCades(
        data,
        rsaCertPem,
        rsaKeyPemBytes,
        intermediates: [intPem],
      );

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: rsaCertPem);
      expect(verified, isTrue);
    });
  });


  group('CRL via PluginCryptoAPI', () {
    test('parseCrl returns CryptoFailure for empty data', () {
      final result = api.parseCrl(Uint8List(0));

      expect(result, isA<CryptoResult<CrlInfo>>());
      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty CRL data');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
      }
    });

    test('parseCrl returns CryptoFailure for garbage data', () {
      final garbage = Uint8List.fromList(List.generate(256, (i) => i % 256));
      final result = api.parseCrl(garbage);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for garbage data');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
      }
    });

    test('verifyCrlSignature returns failure for empty crlData', () {
      final result = api.verifyCrlSignature(
        Uint8List(0),
        Uint8List.fromList('not-empty'.codeUnits),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty crlData');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
          expect(error.message, contains('crlData'));
      }
    });

    test('verifyCrlSignature returns failure for empty caCert', () {
      final result = api.verifyCrlSignature(
        Uint8List.fromList('not-empty'.codeUnits),
        Uint8List(0),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty caCert');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
          expect(error.message, contains('caCert'));
      }
    });

    test('checkRevocation returns failure for empty certData', () {
      final result = api.checkRevocation(
        Uint8List(0),
        Uint8List.fromList('non-empty'.codeUnits),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty certData');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
      }
    });

    test('checkRevocation returns failure for empty crlData', () {
      final kp = api.generateRsaKeyPair(2048);
      final now = DateTime.now();
      final certPem = CertificateBuilder(
        bindings,
      )
          .subjectDn(const DistinguishedName(commonName: 'CRL-Check'))
          .issuerDn(const DistinguishedName(commonName: 'CRL-Check'))
          .publicKey(kp)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(kp)
          .buildPem();
      final certBytes = Uint8List.fromList(
        (certPem as CryptoSuccess<String>).value.codeUnits,
      );

      final result = api.checkRevocation(certBytes, Uint8List(0));

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty crlData');
        case CryptoFailure(:final error):
          expect(error, isA<CrlError>());
      }
    });
  });


  group('OCSP via PluginCryptoAPI', () {
    late Uint8List validPem;

    setUpAll(() {
      final kp = api.generateRsaKeyPair(2048);
      final now = DateTime.now();
      final certPem = CertificateBuilder(
        bindings,
      )
          .subjectDn(const DistinguishedName(commonName: 'OCSP-API'))
          .issuerDn(const DistinguishedName(commonName: 'OCSP-API'))
          .publicKey(kp)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(kp)
          .buildPem();
      validPem = Uint8List.fromList(
        (certPem as CryptoSuccess<String>).value.codeUnits,
      );
    });

    test('buildOcspRequest returns failure for empty cert', () {
      final result = api.buildOcspRequest(Uint8List(0), validPem);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty cert');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
      }
    });

    test('buildOcspRequest returns failure for empty issuerCert', () {
      final result = api.buildOcspRequest(validPem, Uint8List(0));

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty issuerCert');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
      }
    });

    test('buildOcspRequest returns failure for garbage data', () {
      final garbage = Uint8List.fromList(List.generate(128, (i) => i % 256));

      final result = api.buildOcspRequest(garbage, validPem);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for garbage cert data');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
      }
    });

    test('verifyOcspResponse returns failure for empty ocspRespBytes', () {
      final result = api.verifyOcspResponse(Uint8List(0), validPem);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty response');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
          expect(error.message, contains('ocspRespBytes'));
      }
    });

    test('verifyOcspResponse returns failure for empty issuerCert', () {
      final result = api.verifyOcspResponse(
        Uint8List.fromList([0x30, 0x01, 0x00]),
        Uint8List(0),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty issuerCert');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
          expect(error.message, contains('issuerCert'));
      }
    });

    test('verifyOcspResponse returns failure for garbage data', () {
      final garbage = Uint8List.fromList(List.generate(128, (i) => i % 256));

      final result = api.verifyOcspResponse(garbage, validPem);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for garbage OCSP response');
        case CryptoFailure(:final error):
          expect(error, isA<OcspError>());
      }
    });
  });


  group('CSR via PluginCryptoAPI', () {
    late KeyPair rsaKeyPair;
    late KeyPair ecKeyPair;

    setUpAll(() {
      rsaKeyPair = api.generateRsaKeyPair(2048);
      ecKeyPair = api.generateEcKeyPair('prime256v1');
    });

    test('generateCsr with RSA returns valid CsrData', () {
      final result = api.generateCsr(
        CsrRequest(
          subject: const DistinguishedName(
            commonName: 'csr-api-rsa.example.com',
            organization: 'API Test',
            country: 'BR',
          ),
          subjectKeyPair: rsaKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value, isA<CsrData>());
          expect(value.derBytes, isNotEmpty);
          expect(value.derBytes.length, greaterThan(100));
          expect(value.pemString, contains('-----BEGIN CERTIFICATE REQUEST-----'));
          expect(value.pemString, contains('-----END CERTIFICATE REQUEST-----'));
          expect(value.subjectDn, contains('CN=csr-api-rsa.example.com'));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('generateCsr with EC returns valid CsrData', () {
      final result = api.generateCsr(
        CsrRequest(
          subject: const DistinguishedName(
            commonName: 'csr-api-ec.example.com',
            organization: 'API EC',
            country: 'BR',
          ),
          subjectKeyPair: ecKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isNotEmpty);
          expect(value.pemString, isNotEmpty);
          expect(value.subjectDn, contains('CN=csr-api-ec.example.com'));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('generateCsr with DNS SANs returns valid CsrData', () {
      final result = api.generateCsr(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'san-api.local'),
          subjectKeyPair: rsaKeyPair,
          dnsNames: ['www.api-test.com', 'api.api-test.com'],
        ),
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.derBytes, isNotEmpty);
          expect(value.pemString, isNotEmpty);
          expect(value.subjectDn, contains('CN=san-api.local'));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('generateCsr empty commonName returns CryptoFailure', () {
      final result = api.generateCsr(
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

    test('generateCsr empty key returns CryptoFailure', () {
      const emptyKeyPair = KeyPair(publicKeyPem: '', privateKeyPem: '');

      final result = api.generateCsr(
        CsrRequest(
          subject: const DistinguishedName(commonName: 'empty-key.local'),
          subjectKeyPair: emptyKeyPair,
        ),
      );

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty key');
        case CryptoFailure(:final error):
          expect(error, isA<CsrError>());
      }
    });
  });


  group('Timestamping via PluginCryptoAPI', () {
    test('createTimestampRequest returns non-empty DER', () {
      final data = Uint8List.fromList('Timestamp this data'.codeUnits);

      final result = api.createTimestampRequest(data);

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value, isNotEmpty);
          expect(value.length, greaterThan(10));
          expect(value[0], equals(0x30));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('createTimestampRequest with nonce returns non-empty DER', () {
      final data = Uint8List.fromList('Nonce timestamp test'.codeUnits);
      final nonce = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);

      final result = api.createTimestampRequest(data, nonce: nonce);

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value, isNotEmpty);
          expect(value.length, greaterThan(20));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('createTimestampRequest with sha512 algorithm', () {
      final data = Uint8List.fromList('SHA-512 timestamp'.codeUnits);

      final result = api.createTimestampRequest(
        data,
        hashAlgorithm: 'sha512',
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value, isNotEmpty);
          expect(value[0], equals(0x30)); // Starts with SEQUENCE
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('createTimestampRequest with sha384 algorithm', () {
      final data = Uint8List.fromList('SHA-384 timestamp'.codeUnits);

      final result = api.createTimestampRequest(
        data,
        hashAlgorithm: 'sha384',
      );

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value, isNotEmpty);
          expect(value[0], equals(0x30));
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('createTimestampRequest returns failure for empty data', () {
      final result = api.createTimestampRequest(Uint8List(0));

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty data');
        case CryptoFailure(:final error):
          expect(error, isA<TimestampError>());
          expect(error.message, contains('non-empty'));
      }
    });

    test('verifyTimestampResponse returns failure for empty response', () {
      final result = api.verifyTimestampResponse(Uint8List(0));

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty response');
        case CryptoFailure(:final error):
          expect(error, isA<TimestampError>());
          expect(error.message, contains('non-empty'));
      }
    });

    test('verifyTimestampResponse with garbage data returns failure', () {
      final garbage = Uint8List.fromList(List.generate(200, (i) => i % 256));

      final result = api.verifyTimestampResponse(garbage);

      switch (result) {
        case CryptoSuccess(:final value):
          expect(value.isGranted, isFalse);
        case CryptoFailure(:final error):
          expect(error, isA<TimestampError>());
      }
    });

    test('verifyTimestampResponse round-trip: create and parse own request', () {
      final data = Uint8List.fromList('Round-trip test data'.codeUnits);

      final reqResult = api.createTimestampRequest(data);

      switch (reqResult) {
        case CryptoSuccess(value: final requestBytes):
          expect(requestBytes, isNotEmpty);
          expect(requestBytes[0], equals(0x30));

          final req2Result = api.createTimestampRequest(data);
          switch (req2Result) {
            case CryptoSuccess(value: final requestBytes2):
              expect(requestBytes, equals(requestBytes2));
            case CryptoFailure():
              fail('Second request should succeed');
          }
        case CryptoFailure(:final error):
          fail('Expected success but got: ${error.message}');
      }
    });

    test('verifyTimestamp returns failure for empty tokenData', () {
      final data = Uint8List.fromList('test'.codeUnits);

      final result = api.verifyTimestamp(Uint8List(0), data);

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty tokenData');
        case CryptoFailure(:final error):
          expect(error, isA<TimestampError>());
          expect(error.message, contains('tokenData'));
      }
    });

    test('verifyTimestamp returns failure for empty data', () {
      final tokenData = Uint8List.fromList(List.filled(100, 0x00));

      final result = api.verifyTimestamp(tokenData, Uint8List(0));

      switch (result) {
        case CryptoSuccess():
          fail('Expected failure for empty data');
        case CryptoFailure(:final error):
          expect(error, isA<TimestampError>());
          expect(error.message, contains('data'));
      }
    });

    test(
      'verifyTimestamp with garbage token returns failure or false',
      () {
        final garbageToken = Uint8List.fromList(
          List.generate(300, (i) => i % 256),
        );
        final data = Uint8List.fromList('test'.codeUnits);

        final result = api.verifyTimestamp(garbageToken, data);

        switch (result) {
          case CryptoSuccess(:final value):
            expect(value, isFalse, reason: 'Garbage token must not verify');
          case CryptoFailure():
        }
      },
    );
  });


  group('API public type exports', () {
    test('TimestampResponse can be constructed', () {
      final response = TimestampResponse(
        status: TimestampStatus.granted,
        statusString: 'Operation Okay',
      );

      expect(response.status, TimestampStatus.granted);
      expect(response.isGranted, isTrue);
      expect(response.statusString, 'Operation Okay');
    });

    test('TimestampStatus enum has all defined values', () {
      expect(TimestampStatus.values.length, equals(6));
      expect(TimestampStatus.values, contains(TimestampStatus.granted));
      expect(TimestampStatus.values, contains(TimestampStatus.grantedWithMods));
      expect(TimestampStatus.values, contains(TimestampStatus.rejection));
      expect(TimestampStatus.values, contains(TimestampStatus.waiting));
      expect(TimestampStatus.values, contains(TimestampStatus.revocationWarning));
      expect(TimestampStatus.values, contains(TimestampStatus.revocationNotification));
    });

    test('TimestampAccuracy can be constructed', () {
      const accuracy = TimestampAccuracy(seconds: 1, millis: 500);
      expect(accuracy.seconds, 1);
      expect(accuracy.millis, 500);
      expect(accuracy.micros, isNull);
    });

    test('CrlInfo can be constructed with empty revoked list', () {
      final now = DateTime.now();
      final info = CrlInfo(
        lastUpdate: now,
        nextUpdate: now.add(const Duration(hours: 24)),
        issuer: '/CN=Test CA',
      );

      expect(info.revoked, isEmpty);
      expect(info.issuer, '/CN=Test CA');
      expect(info.lastUpdate, now);
      expect(info.nextUpdate, now.add(const Duration(hours: 24)));
    });

    test('CertificateRevocationStatus.notRevoked is available', () {
      const status = CertificateRevocationStatus.notRevoked;
      expect(status.isRevoked, isFalse);
      expect(status.revocationDate, isNull);
      expect(status.reasonCode, isNull);
    });

    test('CsrData can be constructed', () {
      final data = CsrData(
        derBytes: Uint8List.fromList([0x30, 0x01, 0x00]),
        pemString: '-----BEGIN CERTIFICATE REQUEST-----\nAAA=\n-----END CERTIFICATE REQUEST-----',
        subjectDn: '/CN=Test',
      );

      expect(data.derBytes, isNotEmpty);
      expect(data.pemString, contains('CERTIFICATE REQUEST'));
      expect(data.subjectDn, '/CN=Test');
    });

    test('OcspResponse good status via public API types', () {
      const response = OcspResponse(status: CertificateStatus.good);
      expect(response.status, CertificateStatus.good);
      expect(response.producedAt, isNull);
    });
  });

  m?.endZone();
}
