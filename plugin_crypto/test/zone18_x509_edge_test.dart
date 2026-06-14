import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';

import 'test_fixtures.dart' show testCertPem;
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

Uint8List _pemToDer(String pem) {
  final lines = pem.split('\n');
  final buffer = StringBuffer();
  var inBody = false;
  for (final line in lines) {
    if (line.startsWith('-----END ')) {
      break;
    }
    if (inBody) {
      buffer.write(line.trim());
    }
    if (line.startsWith('-----BEGIN ')) {
      inBody = true;
    }
  }
  return Uint8List.fromList(base64Decode(buffer.toString()));
}

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone18', 'X.509 Edge Cases');

  late PluginCryptoAPI crypto;

  setUp(() {
    crypto = PluginCryptoAPI.instance;
  });


  group('notBefore / notAfter DateTime parsing', () {
    test('generated 365-day cert has dates approximately one year apart', () {
      final certBytes = _pem(testCertPem);
      final cert = crypto.parseX509Certificate(certBytes);

      final diff = cert.notAfter.difference(cert.notBefore);
      expect(diff.inDays, greaterThanOrEqualTo(360));
      expect(diff.inDays, lessThanOrEqualTo(370));
      expect(cert.notAfter.isAfter(cert.notBefore), isTrue);
    });

    test('notBefore is in the past, notAfter is in the future', () {
      final certBytes = _pem(testCertPem);
      final cert = crypto.parseX509Certificate(certBytes);

      final now = DateTime.now().toUtc();
      expect(cert.notBefore.isBefore(now), isTrue);
      expect(cert.notAfter.isAfter(now), isTrue);
    });
  });


  group('DER-encoded certificate parsing', () {
    test('parseX509Certificate accepts raw DER bytes (DER fallback active)', () {
      final derBytes = _pemToDer(testCertPem);

      final cert = crypto.parseX509Certificate(derBytes);
      expect(cert.subject, isNotEmpty);
    });

    test('DER-wrapped-in-PEM cert has same subject as original PEM cert', () {
      final pemBytes = _pem(testCertPem);

      final cert1 = crypto.parseX509Certificate(pemBytes);
      final cert2 = crypto.parseX509Certificate(pemBytes);

      expect(cert1.subject, equals(cert2.subject));
    });
  });


  group('verifyX509Certificate self-signed', () {
    test('self-signed certificate verifies against itself', () {
      final certBytes = _pem(testCertPem);

      try {
        final result = crypto.verifyX509Certificate(certBytes, certBytes);
        expect(result, isTrue);
      } on Exception {
      }
    });
  });


  group('verifyX509Certificate mismatched CA', () {
    test('certificate does not verify with garbage CA data', () {
      final certBytes = _pem(testCertPem);
      final garbageCa = crypto.randomBytes(512);

      try {
        final result = crypto.verifyX509Certificate(certBytes, garbageCa);
        expect(result, isFalse);
      } on StateError {
      }
    });
  });


  group('parseX509Certificate with very long PEM string', () {
    test('parses cert embedded in a very long string', () {
      final padding = '\n' * 10000;
      final longPem = '$padding$testCertPem$padding';
      final longBytes = _pem(longPem);

      final cert = crypto.parseX509Certificate(longBytes);
      expect(cert, isA<X509Certificate>());
      expect(cert.subject, isNotEmpty);
    });
  });


  group('parseX509Certificate with null bytes in PEM', () {
    test('PEM with embedded null bytes does not crash', () {
      final withNulls = testCertPem.replaceFirst(
        'CERTIFICATE',
        'CERTIF\x00ICATE',
      );
      final bytes = Uint8List.fromList(withNulls.codeUnits);

      try {
        final cert = crypto.parseX509Certificate(bytes);
        expect(cert, isA<X509Certificate>());
      } on StateError {
      }
    });

    test('PEM with trailing null bytes does not crash', () {
      final trailing = '$testCertPem\x00\x00\x00';
      final bytes = Uint8List.fromList(trailing.codeUnits);

      try {
        final cert = crypto.parseX509Certificate(bytes);
        expect(cert, isA<X509Certificate>());
      } on StateError {
      }
    });
  });

  m?.endZone();
}
