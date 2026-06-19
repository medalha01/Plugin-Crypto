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
  late String expectedSerial;

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
    final serialResult = await Process.run('openssl', [
      'x509',
      '-in',
      pemFile.path,
      '-noout',
      '-serial',
    ]);
    expect(serialResult.exitCode, 0, reason: '${serialResult.stderr}');
    expectedSerial = (serialResult.stdout as String)
        .trim()
        .replaceFirst('serial=', '')
        .toUpperCase();

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

    test('rawDer is canonical DER regardless of PEM input', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.rawDer, isNotEmpty);
      expect(cert.rawDer.first, equals(0x30));
      expect(cert.rawDer, isNot(equals(testCertPem)));
      final reparsed =
          PluginCryptoAPI.instance.parseX509Certificate(cert.rawDer);
      expect(reparsed.rawDer, cert.rawDer);
      expect(reparsed.serialNumber, cert.serialNumber);
      expect(reparsed.subject, cert.subject);
    });

    test('serialNumber contains the actual hexadecimal serial', () {
      final cert = PluginCryptoAPI.instance.parseX509Certificate(testCertPem);
      expect(cert.serialNumber.isNotEmpty, isTrue);
      expect(cert.serialNumber, isNot('present'));
      expect(RegExp(r'^[0-9A-F]+$').hasMatch(cert.serialNumber), isTrue);
      expect(cert.serialNumber, expectedSerial);
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
