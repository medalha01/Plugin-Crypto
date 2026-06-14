import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

/// Returns a cached [PluginCryptoAPI] singleton, initializing on first call.
PluginCryptoAPI _api() => PluginCryptoAPI.instance;


/// PEM-encoded string -> Uint8List.
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Garbage bytes that will never parse as a valid key.
final Uint8List _garbageKey = _pem(
  '-----BEGIN GARBAGE KEY-----\n'
  'VGhpcyBpcyBub3QgYSB2YWxpZCBrZXkgZm9ybWF0Lg==\n'
  '-----END GARBAGE KEY-----\n',
);

/// 1 MB of random data -- computed lazily via a closure so suites that
/// never need it don't pay the cost.
Uint8List Function() _oneMbData = () {
  Uint8List? cache;
  return () => cache ??= _api().randomBytes(1024 * 1024);
}();


void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone10', 'Error Handling');

  group('Hash edge cases', () {
    test('sha256 empty list works returns 32 bytes', () {
      final h = _api().sha256(Uint8List(0));
      expect(h.length, equals(32));
      const expected = [
        0xe3,
        0xb0,
        0xc4,
        0x42,
        0x98,
        0xfc,
        0x1c,
        0x14,
        0x9a,
        0xfb,
        0xf4,
        0xc8,
        0x99,
        0x6f,
        0xb9,
        0x24,
        0x27,
        0xae,
        0x41,
        0xe4,
        0x64,
        0x9b,
        0x93,
        0x4c,
        0xa4,
        0x95,
        0x99,
        0x1b,
        0x78,
        0x52,
        0xb8,
        0x55,
      ];
      expect(h, equals(expected));
    });

    test('sha256 1MB random data works', () {
      final data = _oneMbData();
      final h = _api().sha256(data);
      expect(h.length, equals(32));
    });

    test('sha512 1MB random data works', () {
      final data = _oneMbData();
      final h = _api().sha512(data);
      expect(h.length, equals(64));
    });
  });

  group('Sign/Verify errors', () {
    late KeyPair rsaKeyPair;

    setUpAll(() {
      rsaKeyPair = _api().generateRsaKeyPair(2048);
    });

    test('sign with garbage private key throws', () {
      final data = Uint8List.fromList(utf8.encode('test data'));
      expect(() => _api().sign(data, _garbageKey), throwsA(isA<StateError>()));
    });

    test('verify with garbage public key throws', () {
      final data = Uint8List.fromList(utf8.encode('test data'));
      final sig = _api().sign(data, _pem(rsaKeyPair.privateKeyPem));
      expect(
        () => _api().verify(data, _garbageKey, sig),
        throwsA(isA<StateError>()),
      );
    });

    test('sign empty data works', () {
      final sig = _api().sign(Uint8List(0), _pem(rsaKeyPair.privateKeyPem));
      expect(sig, isNotEmpty);
    });

    test('verify empty signature returns false', () {
      final data = Uint8List.fromList(utf8.encode('test data'));
      final ok = _api().verify(
        data,
        _pem(rsaKeyPair.publicKeyPem),
        Uint8List(0),
      );
      expect(ok, isFalse);
    });
  });

  group('RSA encrypt/decrypt errors', () {
    late KeyPair rsaKeyPair;
    late KeyPair otherKeyPair;

    setUpAll(() {
      rsaKeyPair = _api().generateRsaKeyPair(2048);
      otherKeyPair = _api().generateRsaKeyPair(2048);
    });

    test('encrypt with garbage public key throws', () {
      final plain = Uint8List.fromList(utf8.encode('hello'));
      expect(
        () => _api().rsaEncrypt(_garbageKey, plain),
        throwsA(isA<StateError>()),
      );
    });

    test('decrypt with garbage private key throws', () {
      final cipher = _api().rsaEncrypt(
        _pem(rsaKeyPair.publicKeyPem),
        Uint8List.fromList(utf8.encode('hello')),
      );
      expect(
        () => _api().rsaDecrypt(_garbageKey, cipher),
        throwsA(isA<StateError>()),
      );
    });

    test('encrypt 500 bytes with RSA-2048 throws (exceeds capacity)', () {
      final big = _api().randomBytes(500);
      expect(
        () => _api().rsaEncrypt(_pem(rsaKeyPair.publicKeyPem), big),
        throwsA(isA<StateError>()),
      );
    });

    test('decrypt with wrong key fails', () {
      final plain = Uint8List.fromList(utf8.encode('secret message'));
      final cipher = _api().rsaEncrypt(_pem(rsaKeyPair.publicKeyPem), plain);
      try {
        final result = _api().rsaDecrypt(
          _pem(otherKeyPair.privateKeyPem),
          cipher,
        );
        expect(result, isNot(equals(plain)));
      } on StateError {
      }
    });
  });

  group('Memory stress', () {
    test('1000 randomBytes calls no crash', () {
      for (var i = 0; i < 1000; i++) {
        final r = _api().randomBytes(32);
        expect(r.length, equals(32));
      }
    });

    test('1000 sha256 calls no crash', () {
      final data = Uint8List.fromList(utf8.encode('stress test payload'));
      for (var i = 0; i < 1000; i++) {
        final h = _api().sha256(data);
        expect(h.length, equals(32));
      }
    });

    test('1000 sign operations no crash', () {
      final kp = _api().generateRsaKeyPair(2048);
      final priv = _pem(kp.privateKeyPem);
      final data = Uint8List.fromList(utf8.encode('sign stress'));
      for (var i = 0; i < 1000; i++) {
        final sig = _api().sign(data, priv);
        expect(sig, isNotEmpty);
      }
    });
  });

  group('GCM errors', () {
    test('decrypt with wrong 16-byte tag throws AesGcmAuthFailure', () {
      final key = _api().randomBytes(16); // AES-128 key
      final iv = _api().randomBytes(12); // GCM IV
      final plain = Uint8List.fromList(utf8.encode('GCM test data'));

      final enc = _api().aes128GcmEncrypt(key, iv, plain);
      expect(enc.tag.length, equals(16));

      final badTag = Uint8List(16); // all-zero 16-byte tag
      expect(
        () => _api().aes128GcmDecrypt(key, iv, enc.ciphertext, badTag),
        throwsA(isA<AesGcmAuthFailure>()),
        reason: 'Wrong GCM tag must throw AesGcmAuthFailure',
      );
    });
  });

  m?.endZone();
}
