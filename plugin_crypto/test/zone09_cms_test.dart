import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone09', 'CMS');

  late Uint8List ecCertPem;
  late Uint8List ecKeyPem;
  late Uint8List rsaCertPem;
  late Uint8List rsaKeyPem;

  setUpAll(() async {
    await Process.run('openssl', [
      'ecparam',
      '-genkey',
      '-name',
      'prime256v1',
      '-out',
      '/tmp/cms_ec_key.pem',
    ]);
    await Process.run('openssl', [
      'req',
      '-x509',
      '-key',
      '/tmp/cms_ec_key.pem',
      '-out',
      '/tmp/cms_ec_cert.pem',
      '-days',
      '365',
      '-subj',
      '/CN=CMSECTest',
    ]);
    ecKeyPem = await File('/tmp/cms_ec_key.pem').readAsBytes();
    ecCertPem = await File('/tmp/cms_ec_cert.pem').readAsBytes();

    await Process.run('openssl', [
      'genrsa',
      '-out',
      '/tmp/cms_rsa_key.pem',
      '2048',
    ]);
    await Process.run('openssl', [
      'req',
      '-x509',
      '-key',
      '/tmp/cms_rsa_key.pem',
      '-out',
      '/tmp/cms_rsa_cert.pem',
      '-days',
      '365',
      '-subj',
      '/CN=CMSRSATest',
    ]);
    rsaKeyPem = await File('/tmp/cms_rsa_key.pem').readAsBytes();
    rsaCertPem = await File('/tmp/cms_rsa_cert.pem').readAsBytes();
  });

  tearDownAll(() {
    File('/tmp/cms_ec_key.pem').deleteSync();
    File('/tmp/cms_ec_cert.pem').deleteSync();
    File('/tmp/cms_rsa_key.pem').deleteSync();
    File('/tmp/cms_rsa_cert.pem').deleteSync();
  });

  group('CMS Sign & Verify', () {
    late PluginCryptoAPI crypto;

    setUp(() {
      crypto = PluginCryptoAPI.instance;
    });

    test('cmsSign with EC cert returns non-empty DER data', () {
      final data = Uint8List.fromList(
        utf8.encode('test data for CMS EC signing'),
      );

      final signedData = crypto.cmsSign(data, ecCertPem, ecKeyPem);

      expect(signedData, isNotNull);
      expect(signedData.isNotEmpty, isTrue);
    });

    test('cmsVerify returns true for valid EC-signed data', () {
      final data = Uint8List.fromList(
        utf8.encode('test data for CMS EC verification'),
      );

      final signedData = crypto.cmsSign(data, ecCertPem, ecKeyPem);
      final result = crypto.cmsVerify(signedData, trustedCert: ecCertPem);

      expect(result, isTrue);
    });

    test('cmsVerify fails with mismatched trusted cert', () {
      final data = Uint8List.fromList(
        utf8.encode('test data for cross-cert CMS'),
      );

      final signedData = crypto.cmsSign(data, ecCertPem, ecKeyPem);
      final result = crypto.cmsVerify(signedData, trustedCert: rsaCertPem);

      expect(result, isFalse);
    });

    test('cmsSign with RSA cert round-trips successfully', () {
      final data = Uint8List.fromList(
        utf8.encode('test data for RSA CMS signing'),
      );

      final signedData = crypto.cmsSign(data, rsaCertPem, rsaKeyPem);

      expect(signedData, isNotNull);
      expect(signedData.isNotEmpty, isTrue);

      final result = crypto.cmsVerify(signedData, trustedCert: rsaCertPem);
      expect(result, isTrue);
    });
  });

  group('CMS Edge Cases', () {
    late PluginCryptoAPI crypto;

    setUp(() {
      crypto = PluginCryptoAPI.instance;
    });

    test('cmsSign with empty data works', () {
      final data = Uint8List(0);

      final signedData = crypto.cmsSign(data, ecCertPem, ecKeyPem);

      expect(signedData, isNotNull);
      expect(signedData.isNotEmpty, isTrue);

      final result = crypto.cmsVerify(signedData, trustedCert: ecCertPem);
      expect(result, isTrue);
    });

    test('cmsVerify with garbage data returns false or throws', () {
      final garbageData = Uint8List.fromList(
        utf8.encode('this is not valid CMS data'),
      );

      try {
        final result = crypto.cmsVerify(garbageData, trustedCert: ecCertPem);
        expect(result, isFalse);
      } catch (e) {
        expect(e, isA<Object>());
      }
    });
  });


  m?.endZone();
}
