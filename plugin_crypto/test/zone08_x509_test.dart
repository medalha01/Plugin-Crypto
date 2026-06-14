import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone08', 'X.509');

  late Uint8List testCertPem;

  setUpAll(() async {
    final result = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      '/tmp/test_key.pem',
      '-out',
      '/tmp/test_cert.pem',
      '-days',
      '365',
      '-nodes',
      '-subj',
      '/CN=PluginCryptoTest',
    ]);

    if (result.exitCode != 0) {
      throw Exception('Failed to generate test certificate:\n${result.stderr}');
    }

    final pemFile = File('/tmp/test_cert.pem');
    testCertPem = await pemFile.readAsBytes();

    await File('/tmp/test_key.pem').delete();
    await File('/tmp/test_cert.pem').delete();
  });

  group('X.509 Parsing', () {
    test('parseX509Certificate returns an X509Certificate', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert, isA<X509Certificate>());
    });

    test('subject contains the expected CN', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.subject, contains('PluginCryptoTest'));
    });

    test('issuer matches subject for a self-signed certificate', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.issuer, equals(cert.subject));
    });

    test('rawDer matches input PEM bytes', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.rawDer, equals(testCertPem));
    });

    test('serialNumber is non-empty', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.serialNumber.isNotEmpty, isTrue);
    });
  });

  group('Error handling', () {
    test('parse garbage random bytes throws', () {
      final garbage = Uint8List.fromList(List.generate(256, (_) => 0xFF));
      expect(
        () => PluginCryptoAPI.instance.parseX509Certificate(garbage),
        throwsA(anything),
      );
    });

    test('parse empty data throws', () {
      expect(
        () => PluginCryptoAPI.instance.parseX509Certificate(Uint8List(0)),
        throwsA(anything),
      );
    });

    test('parse non-PEM text throws', () {
      final notPem = Uint8List.fromList(
        utf8.encode('This is not a certificate.\nJust some random text.\n'),
      );
      expect(
        () => PluginCryptoAPI.instance.parseX509Certificate(notPem),
        throwsA(anything),
      );
    });
  });

  m?.endZone();
}
