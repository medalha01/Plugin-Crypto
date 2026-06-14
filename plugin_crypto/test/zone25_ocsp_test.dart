@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/ocsp_data.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/flows/revocation/ocsp_verifier.dart';
import 'package:plugin_crypto/src/crypto/plugin_crypto_context.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone25', 'OCSP Operations');

  late OpenSslBindings bindings;
  late OpenSslOcspVerifier ocspVerifier;

  late Uint8List validPem;
  late Uint8List garbageData;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    ocspVerifier = OpenSslOcspVerifier(PluginCryptoContext(bindings));

    final api = PluginCryptoAPI.instance;
    final kp = api.generateRsaKeyPair(2048);
    const dn = DistinguishedName(commonName: 'OcspTest');
    final builder = CertificateBuilder(bindings)
        .subjectDn(dn)
        .issuerDn(dn)
        .publicKey(kp)
        .validityPeriod(const Duration(days: 365))
        .signWith(kp);
    final pemResult = builder.buildPem();
    validPem = Uint8List.fromList(
      ((pemResult as CryptoSuccess<String>).value).codeUnits,
    );

    garbageData = Uint8List.fromList(List.generate(128, (i) => i % 256));
  });

  group('buildOcspRequest — guard clauses', () {
    test('returns CryptoFailure for empty cert', () {
      final result = ocspVerifier.buildOcspRequest(Uint8List(0), validPem);
      expect(result, isA<CryptoFailure<Uint8List>>());
    });

    test('returns CryptoFailure for empty issuerCert', () {
      final result = ocspVerifier.buildOcspRequest(validPem, Uint8List(0));
      expect(result, isA<CryptoFailure<Uint8List>>());
    });

    test('returns CryptoFailure for invalid cert data', () {
      final result = ocspVerifier.buildOcspRequest(garbageData, validPem);
      expect(result, isA<CryptoFailure<Uint8List>>());
    });

    test('returns CryptoFailure for invalid issuerCert data', () {
      final result = ocspVerifier.buildOcspRequest(validPem, garbageData);
      expect(result, isA<CryptoFailure<Uint8List>>());
    });

    test('cert ID creation succeeds with valid PEM inputs', () {
      final result = ocspVerifier.buildOcspRequest(validPem, validPem);
      expect(result, isA<CryptoResult<Uint8List>>());
    });
  });

  group('verifyOcspResponse — guard clauses', () {
    test('returns CryptoFailure for empty ocspRespBytes', () {
      final result = ocspVerifier.verifyOcspResponse(Uint8List(0), validPem);
      expect(result, isA<CryptoFailure<OcspResponse>>());
      final error = (result as CryptoFailure<OcspResponse>).error;
      expect(error, isA<OcspError>());
      expect(error.message, contains('ocspRespBytes'));
    });

    test('returns CryptoFailure for empty issuerCert', () {
      final result = ocspVerifier.verifyOcspResponse(
        Uint8List.fromList([0x30, 0x01, 0x00]),
        Uint8List(0),
      );
      expect(result, isA<CryptoFailure<OcspResponse>>());
      final error = (result as CryptoFailure<OcspResponse>).error;
      expect(error, isA<OcspError>());
      expect(error.message, contains('issuerCert'));
    });

    test('returns CryptoFailure for garbage data', () {
      final result = ocspVerifier.verifyOcspResponse(garbageData, validPem);
      expect(result, isA<CryptoFailure<OcspResponse>>());
      final error = (result as CryptoFailure<OcspResponse>).error;
      expect(error, isA<OcspError>());
    });
  });

  group('CertificateStatus', () {
    test('enum has good, revoked, and unknown values', () {
      final values = CertificateStatus.values;
      expect(values.length, equals(3));
      expect(values, contains(CertificateStatus.good));
      expect(values, contains(CertificateStatus.revoked));
      expect(values, contains(CertificateStatus.unknown));
    });

    test('CertificateStatus.good toString works', () {
      expect(CertificateStatus.good.toString(), contains('good'));
    });

    test('CertificateStatus.revoked toString works', () {
      expect(CertificateStatus.revoked.toString(), contains('revoked'));
    });

    test('CertificateStatus.unknown toString works', () {
      expect(CertificateStatus.unknown.toString(), contains('unknown'));
    });
  });

  group('OcspResponse', () {
    test('can be constructed with all fields populated', () {
      final now = DateTime.now();
      final next = now.add(const Duration(hours: 6));
      final response = OcspResponse(
        status: CertificateStatus.good,
        producedAt: now,
        thisUpdate: now,
        nextUpdate: next,
      );
      expect(response.status, equals(CertificateStatus.good));
      expect(response.producedAt, equals(now));
      expect(response.thisUpdate, equals(now));
      expect(response.nextUpdate, equals(next));
    });

    test('can be constructed with revoked status', () {
      final response = OcspResponse(
        status: CertificateStatus.revoked,
        producedAt: DateTime.now(),
      );
      expect(response.status, equals(CertificateStatus.revoked));
      expect(response.producedAt, isNotNull);
    });

    test('can be constructed with unknown status', () {
      final response = OcspResponse(
        status: CertificateStatus.unknown,
        producedAt: DateTime.now(),
      );
      expect(response.status, equals(CertificateStatus.unknown));
    });
  });

  m?.endZone();
}
