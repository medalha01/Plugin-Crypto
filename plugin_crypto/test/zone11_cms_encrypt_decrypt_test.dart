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

const String _prebakedRsaCertPem = '''-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUHN42HHLHh8IGF01ZWanmuxFq+DMwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKQ01TVGVzdFJTQTAeFw0yNjA1MjUxMjAxMjZaFw0yNzA1
MjUxMjAxMjZaMBUxEzARBgNVBAMMCkNNU1Rlc3RSU0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCun/MG/RaR+jIfaTOQwNv0FqGM+9JjbHaVYIx3oeNQ
hY1TzZ4PfYwlS0GIrIB0jWz10iJgABlomGCdn9PDWpZFcLULKdSEZsu0vlGWxw65
rcgbthepe4j0WRK0vHvgSQ1akAvkM6As4Soml63UR7vSyWvC0A2g9bmQWrrCVkIU
bvZJ+GJ6O6BqWpnIc5XpFJk+6xHavvhMyUeiohthuUSnKY/QFL9JvdO5uSd17Roy
ThO/w3156JXn9DXk13RFx2lQYd2KH62xMoDJPxqL1h/SlvSGOQRby7x7iK15jw1W
UwF/j2pBxeToq3AtAImg5IK0dK9k3UQe8JCGkytlSyQdAgMBAAGjUzBRMB0GA1Ud
DgQWBBSRvdjFDFohVOUFsPBbkMpyNK/N6TAfBgNVHSMEGDAWgBSRvdjFDFohVOUF
sPBbkMpyNK/N6TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBP
TToG0y7bBNnzUW+9Qs5cKK3LuAKN93q33PZm8xbtD9anDT0MyOEmExQx43OFPKWw
Mo/7+O31pbhCAh4i3dlwFzp0UhlzoqkCeHkuVXrRJ3UWUr3pX0QWeufsrsEdhHiw
iMF4D6iYiTWw2Hzd3xCV1rn3LHhCLdbXtntcURdsQqD9Z9xuO9bEDlhUfJ7+Y/7+
7FmRNRmra1D+3faZ66o8ZDacqIe9Ko6kmVN7Ksc10Wr+/NLD1bCzt2+wLJCC5GMA
wtcPVopuRhg0QeMlT2iIOqFjzAKIhp3cpqMn2ZFG5ZgujWApcUYeoKn/fUM0+nKb
5qW8p3fzQ4uY67YIAPlc
-----END CERTIFICATE-----
''';

/// Private key corresponding to [_prebakedRsaCertPem] (PEM, unencrypted).
const String _prebakedRsaKeyPem = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCun/MG/RaR+jIf
aTOQwNv0FqGM+9JjbHaVYIx3oeNQhY1TzZ4PfYwlS0GIrIB0jWz10iJgABlomGCd
n9PDWpZFcLULKdSEZsu0vlGWxw65rcgbthepe4j0WRK0vHvgSQ1akAvkM6As4Som
l63UR7vSyWvC0A2g9bmQWrrCVkIUbvZJ+GJ6O6BqWpnIc5XpFJk+6xHavvhMyUei
ohthuUSnKY/QFL9JvdO5uSd17RoyThO/w3156JXn9DXk13RFx2lQYd2KH62xMoDJ
PxqL1h/SlvSGOQRby7x7iK15jw1WUwF/j2pBxeToq3AtAImg5IK0dK9k3UQe8JCG
kytlSyQdAgMBAAECggEAIzpHR8Ck3fwQQn/xlCEj/kDWhF+E2OPXpFje3X9+IQ9g
LGjNmyhjrl5ZMR5Dp7+kHI8wuhcrCQu8afAFQ2Kx7/5Ft6PPqIooTCUcxoMPuGuT
c+uvKFSwk0Ko4GcpwlxaYkuu6nFzvboKy9BLlAiInoRdxeY86ZzIu5NiG7RVDlPi
8trN+Dc9vqCZOS142okABdgGzZQw/4GIZiNhriy3ZdjOCJvfMnwcoMQsbWMyxl2s
cV8eX1+WYWnyNnLsGxFkBpdhqn40syTcrQjCIh5ob9jkW4CITK4t/1EBPUNdFCrP
bH+TilwVfEQzROmRwUswamswkt77PwUYg1CzTYUhwQKBgQDTpN1Cln2IAm8xYsR9
KfcdJlYYukUj6Lh8ZMVs/TVESAZGLgq2ump+LFhV2og37vUQqmuUKtcG8HqorR9J
XAtIRAHhDILAxI3RcvJXMQbyIRB2slfkVkwtAJLCI2puKxUpyDPQWFxH3cO6/bCo
3FEvKBrhtnEEe9F9VpPSYWEBkQKBgQDTOO3MgvYnAh70kj6TrtVnhBq9ktC4YNdO
fciztOxMsLECO6sKqd3MOzR0PxjmVnhEkZD/s9XKCykpws1cCZjUCp/XRvQOTLZY
+sMMm5ty5HGsFBvqV75cgcbCYNbVWyXq8BeAFSRL4on/ye4F7apG/TnkpRQ9qYEt
eYPgW/0zzQKBgDBr3btoVtwRQoNYB4BjY4glxzjtFPh8PAkpvQmMfO1cVSMlUYow
6EBpwOQTlWrGnwbrFqXVj1ClIEsLIMdV6bbk6FEm3Ztg3Nl4pP1R2Db5XZzqfLVf
ERqSsQD9vVHrRXJDvacDMEm48RkNBaf8kA5r7IqLhRvzgCBe+H7/jIQhAoGBALRp
Nqvs3CTbaedKFor71Skyq8hqYz5o8N4JD+l2yjKC5N3cay6Tgm/TzezQjAsJpnYi
w2+0ghGt0L3rto47YD8UyAwPfZvNKB7+KKVXL8JFn1X0YxeZVG4dJtCV+EmKLevq
oJf09uieGXLSXizQIBW8aruByLUWV9CortxulemtAoGAQpXxDdQR/Fe+XpSJ+/4j
yGoNlHH7PybJQTmNPA9FEC6uh7M8yZjqxZRuQiJBiWX53dk0bKbvYhhy/Klyr/4R
pLxfnFCWHfLFGvPdsVNGf5UDy0fJZchafGPSueWCyZ2zPt9v/ugfl52MJ+2JoIn/
ZEVdLInoQc1x34D5UsFMBjM=
-----END PRIVATE KEY-----
''';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone11_cms_encrypt_decrypt', 'CMS Encrypt/Decrypt');

  final rsaCertPem = _pem(_prebakedRsaCertPem);
  final rsaKeyPem = _pem(_prebakedRsaKeyPem);

  late Uint8List rsaKey2Pem;

  setUpAll(() {
    final kp = _api().generateRsaKeyPair(2048);
    rsaKey2Pem = _pem(kp.privateKeyPem);
  });

  group('CMS Encrypt/Decrypt round-trip with EC certificate', () {
    test('encrypt then decrypt returns original data', () {
      final data = Uint8List.fromList(
        utf8.encode('Secret message for EC CMS encrypt'),
      );
      final ecCert = _pem(testCertPem);
      final ecKey = _pem(testKeyPem);

      final encrypted = _api().cmsEncrypt(data, ecCert);
      final decrypted = _api().cmsDecrypt(encrypted, ecCert, ecKey);

      expect(decrypted, equals(data));
    });
  });

  group('CMS Encrypt/Decrypt round-trip with RSA certificate', () {
    test('encrypt then decrypt returns original data', () {
      final data = Uint8List.fromList(
        utf8.encode('Secret message for RSA CMS encrypt'),
      );

      final encrypted = _api().cmsEncrypt(data, rsaCertPem);
      final decrypted = _api().cmsDecrypt(encrypted, rsaCertPem, rsaKeyPem);

      expect(decrypted, equals(data));
    });
  });

  group('CMS Encrypt errors', () {
    test('encrypt with garbage certificate throws StateError', () {
      final data = Uint8List.fromList(utf8.encode('some data'));
      final garbageCert = _pem(
        '-----BEGIN GARBAGE-----\n'
        'not a real certificate\n'
        '-----END GARBAGE-----\n',
      );

      expect(
        () => _api().cmsEncrypt(data, garbageCert),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('CMS Decrypt errors', () {
    test('decrypt with wrong private key throws StateError', () {
      final data = Uint8List.fromList(utf8.encode('data for wrong key test'));

      final encrypted = _api().cmsEncrypt(data, rsaCertPem);

      expect(
        () => _api().cmsDecrypt(encrypted, rsaCertPem, rsaKey2Pem),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('CMS Encrypt/Decrypt data size edge cases', () {
    test('encrypt/decrypt round-trip with 10KB+ data', () {
      final largeData = Uint8List(10 * 1024 + 37);
      for (var i = 0; i < largeData.length; i++) {
        largeData[i] = 0x30 + (i % 48); // ASCII '0'-'o' range
      }

      final encrypted = _api().cmsEncrypt(largeData, rsaCertPem);
      final decrypted = _api().cmsDecrypt(encrypted, rsaCertPem, rsaKeyPem);

      expect(decrypted, equals(largeData));
    });

    test('encrypt/decrypt round-trip with empty data', () {
      final emptyData = Uint8List(0);

      final encrypted = _api().cmsEncrypt(emptyData, rsaCertPem);
      final decrypted = _api().cmsDecrypt(encrypted, rsaCertPem, rsaKeyPem);

      expect(decrypted, equals(emptyData));
      expect(decrypted, isEmpty);
    });
  });

  m?.endZone();
}
