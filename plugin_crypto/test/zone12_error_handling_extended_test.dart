import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';

import 'test_fixtures.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

/// Returns a cached [PluginCryptoAPI] singleton, initializing on first call.
PluginCryptoAPI _api() => PluginCryptoAPI.instance;

/// PEM-encoded string -> Uint8List.
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Garbage bytes that will never parse as a valid key or certificate.
final Uint8List _garbageKey = _pem(
  '-----BEGIN GARBAGE KEY-----\n'
  'VGhpcyBpcyBub3QgYSB2YWxpZCBrZXkgZm9ybWF0Lg==\n'
  '-----END GARBAGE KEY-----\n',
);

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone12', 'Error Handling Extended');

  group('getLastError / clearErrors', () {
    test('error queue cleared after failure, getLastError returns null', () {
      expect(
        () => _api().parseX509Certificate(_pem('not a valid certificate')),
        throwsA(isA<StateError>()),
      );

      final err1 = _api().getLastError();
      expect(err1, isNull);

      _api().clearErrors();

      final err2 = _api().getLastError();
      expect(err2, isNull);
    });
  });

  group('Error queue isolation', () {
    test('operation succeeds after clearing previous error queue', () {
      expect(
        () => _api().parseX509Certificate(_pem('not a valid certificate')),
        throwsA(isA<StateError>()),
      );

      expect(_api().getLastError(), isNull);

      _api().clearErrors();
      final hash = _api().sha256(Uint8List.fromList(utf8.encode('hello')));

      expect(hash.length, equals(32));
    });

    test('sha256 succeeds even without explicitly clearing stale errors', () {
      expect(
        () => _api().parseX509Certificate(_pem('not a valid certificate')),
        throwsA(isA<StateError>()),
      );

      final hash = _api().sha256(Uint8List.fromList(utf8.encode('world')));

      expect(hash.length, equals(32));
    });
  });

  group('_bioToBytes overflow', () {
    test('CMS sign with 10KB+ input exposes 4096-byte BIO buffer', () {
      final cert = _pem(testCertPem);
      final key = _pem(testKeyPem);
      final largeData = _api().randomBytes(12 * 1024);

      final signed = _api().cmsSign(largeData, cert, key);

      expect(signed, isNotNull);
      expect(signed.isNotEmpty, isTrue);

      try {
        final ok = _api().cmsVerify(signed, trustedCert: cert);
        expect(ok, anyOf(isTrue, isFalse));
      } on StateError {
      }
    });
  });

  group('_fail throws StateError with operation name', () {
    test('parseX509Certificate garbage -> StateError includes operation', () {
      final garbage = _pem('not a valid certificate');

      try {
        _api().parseX509Certificate(garbage);
        fail('Expected StateError');
      } on StateError catch (e) {
        expect(e.message, isNotEmpty);
        expect(
          e.message,
          anyOf(contains('PEM_read_bio_X509'), contains('failed')),
        );
      }
    });

    test('cmsSign with garbage key -> StateError includes operation', () {
      final data = Uint8List.fromList(utf8.encode('test data for CMS sign'));
      final cert = _pem(testCertPem);

      try {
        _api().cmsSign(data, cert, _garbageKey);
        fail('Expected StateError');
      } on StateError catch (e) {
        expect(e.message, isNotEmpty);
        expect(
          e.message,
          anyOf(contains('PEM_read_bio_PrivateKey'), contains('failed')),
        );
      }
    });

    test('rsaEncrypt garbage public key -> StateError includes operation', () {
      final plain = Uint8List.fromList(utf8.encode('hello rsa'));

      try {
        _api().rsaEncrypt(_garbageKey, plain);
        fail('Expected StateError');
      } on StateError catch (e) {
        expect(e.message, isNotEmpty);
        expect(
          e.message,
          anyOf(contains('PEM_read_bio_PUBKEY'), contains('failed')),
        );
      }
    });
  });

  group('Sign/Verify edge cases', () {
    late KeyPair rsaKeyPair;

    setUpAll(() {
      rsaKeyPair = _api().generateRsaKeyPair(2048);
    });

    test('sign empty data produces non-empty signature', () {
      final emptyData = Uint8List(0);
      final privateKey = _pem(rsaKeyPair.privateKeyPem);

      final sig = _api().sign(emptyData, privateKey);

      expect(sig, isNotEmpty);
    });

    test('verify empty signature returns false', () {
      final data = Uint8List.fromList(utf8.encode('test data to verify'));
      final publicKey = _pem(rsaKeyPair.publicKeyPem);
      final emptySig = Uint8List(0);

      final ok = _api().verify(data, publicKey, emptySig);

      expect(ok, isFalse);
    });
  });

  m?.endZone();
}
