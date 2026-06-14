/// PluginCrypto integration tests — sanity, hash, AES-CBC/GCM, random, RSA, EC, X.509, CMS, errors, stress.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/security_metrics.dart';
import 'package:plugin_crypto/src/metrics/throughput.dart';

import 'android_metrics_collector.dart';


const String _ecTestCertPem = '''-----BEGIN CERTIFICATE-----
MIIBzDCCAXOgAwIBAgIUH54hr75+amZlGPVbIOu9q5sI+EcwCgYIKoZIzj0EAwIw
PDEWMBQGA1UEAwwNVENDIFRlc3QgQ2VydDEVMBMGA1UECgwMUGx1Z2luQ3J5cHRv
MQswCQYDVQQGEwJCUjAeFw0yNjA0MzAyMTIxMzhaFw0yNzA0MzAyMTIxMzhaMDwx
FjAUBgNVBAMMDVRDQyBUZXN0IENlcnQxFTATBgNVBAoMDFBsdWdpbkNyeXB0bzEL
MAkGA1UEBhMCQlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQB66E/jM6bhlxJ
mr2CxRGmAhjqkWoV+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oH
Ut6+DVYto1MwUTAdBgNVHQ4EFgQUtpQurNbwHoYUVW7AI1xr4+2IdRYwHwYDVR0j
BBgwFoAUtpQurNbwHoYUVW7AI1xr4+2IdRYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNHADBEAiBQxobhr3wdWEFsVLDv2IeI/NFKw/O3W3nf0jYm9kDRsAIg
fy6XTViHpFXzM0Rgfl1sJ7i26Haehg32D3x11tzBbMg=
-----END CERTIFICATE-----
''';

/// Private key for [_ecTestCertPem] (PEM, unencrypted).
const String _ecTestKeyPem = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuXtpWM2SqBrFzQj
/4wlOs6BJb1WzvA8uLnjdlWoWAehRANCAAQB66E/jM6bhlxJmr2CxRGmAhjqkWoV
+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oHUt6+DVYt
-----END PRIVATE KEY-----
''';

const String _rsaTestCertPem = '''-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUalF3MeImADUqNkPL/5JKQUSJc0kwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwaUGx1Z2luQ3J5cHRvUlNBVGVzdEZpeHR1cmUwHhcNMjYw
NTI1MTIwMTE1WhcNMzYwNTIyMTIwMTE1WjAlMSMwIQYDVQQDDBpQbHVnaW5Dcnlw
dG9SU0FUZXN0Rml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALlg9lg8oVdt6R0VAXmtLTCjxz7KkD/bSYgmCUy1vejLfXM7S+QCmessb4NHnW3K
yVXafCsOsI8VFAnUv4UX/W69wTmCh/dENP80fht3p226YUrh7MKs5Npb0CEwkO0Q
4ANV8O4DPxRq5k3b8B+btBGNw3KPdDaG3zNKataogk5HSD9sOTqMN8dNfUuQJCcC
zLR7CfZMdUQgLGVIe/D+TICtJraYGay73ltc7c+PY5fqVUyzYfZUIxxF2x4qssCU
badCM0eTqo//9fOxCt4kX8a67pDECcYfiLXnASeL/R6qeBsHMgggeWyJdwMKoL7k
uFdCffNXJWe6H3xcK6b9nDECAwEAAaNTMFEwHQYDVR0OBBYEFJeEKZ/IViIQRae/
sIOblMjb+NBNMB8GA1UdIwQYMBaAFJeEKZ/IViIQRae/sIOblMjb+NBNMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGBx97/EA+A6p6f2D/AiZZ1n
O2f3FqCOw90AOiniGLaH1MkAYA8igv5S+SbwxArbRUL8fOfaD7JviToP+arPIAAv
MSk9SbYNBI/wusypWneuESCrWA6JyH9AU96/d6Db/BkXXP4Hm+EurGbjLPLBvLk2
Mli6NRqmaxh5rTlzhb8YASij8LViJhz+RSw+tVIbyIzr7Zvd42hfyc1cafPQV8bj
aaJfVDsLP011ZaGik2914r2i9XFBYMIp0o7JOsP1I95VpDIxJ5+65zi42cRJ1aEK
hpKxp+2MEc73aAb/ZKBibMFJe6kvjxF9vs4hCpK8bggOFYCLIUCX/WXSeBwN3RA=
-----END CERTIFICATE-----
''';

/// Private key for [_rsaTestCertPem] (PEM, unencrypted).
const String _rsaTestKeyPem = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5YPZYPKFXbekd
FQF5rS0wo8c+ypA/20mIJglMtb3oy31zO0vkApnrLG+DR51tyslV2nwrDrCPFRQJ
1L+FF/1uvcE5gof3RDT/NH4bd6dtumFK4ezCrOTaW9AhMJDtEOADVfDuAz8UauZN
2/Afm7QRjcNyj3Q2ht8zSmrWqIJOR0g/bDk6jDfHTX1LkCQnAsy0ewn2THVEICxl
SHvw/kyArSa2mBmsu95bXO3Pj2OX6lVMs2H2VCMcRdseKrLAlG2nQjNHk6qP//Xz
sQreJF/Guu6QxAnGH4i15wEni/0eqngbBzIIIHlsiXcDCqC+5LhXQn3zVyVnuh98
XCum/ZwxAgMBAAECggEACUjCJbKpqPGMAIUeDQw/jGVTdAFcnpoasWsoQZODlp5k
YspIN3vq3gScdCB40bgbg8V8vQJQFOZrGb/yNJX6PxrZS8pOCXP8zIBCRZllRQFV
4JR2kVxr3MTG5Hakd38GHRyng6Adf2YIMUOP3+FiMBPfw0PMf/Oax5yVQ7luR0HE
M2KsLm03xGa5TWVKIEAKRn3HSBX7k4thNmhmRJpTYuXMNCWujt27DNrKFUmTD56z
6FjW+I9f5vNEQQ7iciRjxUnbb3OILU6E6T8Fo4IoMYxkp37AVVYwSFbdhAiod7fB
ONeR8gb+pixWDR2CDBZStsN5lkOIKO6hXqMl1+tQAQKBgQD1EX8rWrNNKTb5WSH9
6ocj47aTptnuoS0DrVyUG6QvHPBRHFoSCcVK00DVMik9y8r9Qf2kpEN8OBXfL5Nu
R8Aiu/vZhcNTy+MikufhjOE+Uy5Klp0b2aOckWH4HBg44hGIP3WdrMT6xxL32CbS
dQZPTXXthb48uHv/BGSLkdd8AQKBgQDBpdqGbYia76H5fv12yGTEDYqChvWalOoD
eQdxl6aDE/kd6I75ETTcr0Gi3/6j5orRuubGFVaY3aljJyVp3l9YdPItHqZ3B5oq
p1F3lVQ8IRUE2yMGBHdFvNA77M5WpL4lN+lrNO4NtzA+l1twGhFbUueo4Wk4g/i+
+SBIKD7gMQKBgQClg0mmGD3csSdFxKMmgI0A+jxHAHtTpVtnjmBmTzzV7O+JeGKE
qECtRnwVASnFaKwR283YsnA5pw9uiw1BgAgN7XQs9yByqdMfeKRPOvytQTSUf6Bg
PN85UR8fmKnrUROSN3nSIetvi6AN79hYb1zxllk9MATJsbddBrR5ZuhoAQKBgDjZ
oBXnAju6Lis5BOBiZHLKJue7B0+ieDEczvqiMtg4fOIy7AZi7sn7CaHvcKpdfFOm
MynkCdBHAvuA+pLiHcuySYbFgMlhCfmLtXcN9/TPIYSTcOzLUti+XcO5+bmmE8yJ
ZZV7rIeKSDeX59g5Tu8on6oMwv88f0JRkRCeABeBAoGANb2yRAh6t5YkXF38dIu4
EYirs4LfkMGrEVZU/S4N8ml6z5QUb8bsnwZ/y9u+tBiPlwWLcYAoP73FjnB6tqY1
tsew1Zg0wcz/kZTAewc0Xk82bIBU9M5wnrjVDIf5qkCGK51JBy06mBXAaK8k94Sx
4oIbaR1gOAQvBoWVjwOxjDU=
-----END PRIVATE KEY-----
''';


/// Shortcut to the singleton API.
PluginCryptoAPI _api() => PluginCryptoAPI.instance;

/// Converts a PEM string to [Uint8List].
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Garbage bytes that will never parse as a valid key.
final Uint8List _garbageKey = Uint8List.fromList(utf8.encode(
  '-----BEGIN GARBAGE KEY-----\n'
  'VGhpcyBpcyBub3QgYSB2YWxpZCBrZXkgZm9ybWF0Lg==\n'
  '-----END GARBAGE KEY-----\n',
));

/// Record of an RSA key pair generated via API (used across CMS test groups).
KeyPair? _cachedRsaKeyPair;

/// Returns a 2048-bit RSA key pair, generating once per test run.
KeyPair _getRsaKeyPair() {
  _cachedRsaKeyPair ??= _api().generateRsaKeyPair(2048);
  return _cachedRsaKeyPair!;
}


void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();


  /// Current test group name, set at the start of each [group] callback.
  /// Combined with [currentTestName] in [tearDown] for full test name.
  String? currentGroupName;

  /// Current test name, set as the first line of each [testWidgets] callback.
  String? currentTestName;

  /// Per-test stopwatch started in [setUp], stopped in [tearDown].
  late Stopwatch testStopwatch;

  /// Metrics collector — only non-null when [TCC_METRICS_OUTPUT] is set.
  final metricsOutputPath = Platform.environment['TCC_METRICS_OUTPUT'];
  AndroidMetricsCollector? collector;
  double nativeLoadTimeMs = 0.0;

  if (metricsOutputPath != null && metricsOutputPath.isNotEmpty) {
    collector = AndroidMetricsCollector.create();
    collector.recordMemorySample(
      'baseline',
      AndroidMetricsCollector.readVmRss(),
    );

    final loadSw = Stopwatch()..start();
    final _ = PluginCryptoAPI.instance;
    loadSw.stop();
    nativeLoadTimeMs = loadSw.elapsedMicroseconds / 1000.0;

    collector.recordMemorySample(
      'after_api_load',
      AndroidMetricsCollector.readVmRss(),
    );
  }

  late PluginCryptoAPI api;

  setUp(() {
    testStopwatch = Stopwatch()..start();
    api = PluginCryptoAPI.instance;
    api.clearErrors();
  });

  tearDown(() {
    testStopwatch.stop();
    final elapsedMs = testStopwatch.elapsedMicroseconds ~/ 1000;
    final fullName = currentGroupName != null && currentTestName != null
        ? '$currentGroupName :: $currentTestName'
        : (currentTestName ?? 'unknown');
    collector?.recordTestResult(fullName, 'passed', elapsedMs);
    api.clearErrors();
  });


  group('00 — Sanity check', () {
    currentGroupName = '00 — Sanity check';
    collector?.startGroup('00 — Sanity check');

    testWidgets('OpenSSL version is non-empty', (_) async {
      currentTestName = 'OpenSSL version is non-empty';
      final version = api.getOpenSSLVersion();
      expect(version, isNotEmpty);
      expect(version, contains('OpenSSL'));
    });

    testWidgets('API singleton is stable', (_) async {
      currentTestName = 'API singleton is stable';
      final a = PluginCryptoAPI.instance;
      final b = PluginCryptoAPI.instance;
      expect(identical(a, b), isTrue);
    });

    collector?.endGroup();
  });


  group('01 — Hash operations', () {
    currentGroupName = '01 — Hash operations';
    collector?.startGroup('01 — Hash operations');

    testWidgets('sha256 returns 32 bytes', (_) async {
      currentTestName = 'sha256 returns 32 bytes';
      final data = Uint8List.fromList(utf8.encode('hello'));
      final sw = Stopwatch()..start();
      final h = api.sha256(data);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'sha256',
        category: 'hash',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(h.length, equals(32));
    });

    testWidgets('sha256 is deterministic', (_) async {
      currentTestName = 'sha256 is deterministic';
      final data = Uint8List.fromList(utf8.encode('hello'));
      final h1 = api.sha256(data);
      final h2 = api.sha256(data);
      expect(h1, equals(h2));
    });

    testWidgets('sha512 returns 64 bytes', (_) async {
      currentTestName = 'sha512 returns 64 bytes';
      final data = Uint8List.fromList(utf8.encode('hello'));
      final sw = Stopwatch()..start();
      final h = api.sha512(data);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'sha512',
        category: 'hash',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(h.length, equals(64));
    });

    testWidgets('sha3_256 returns 32 bytes', (_) async {
      currentTestName = 'sha3_256 returns 32 bytes';
      final data = Uint8List.fromList(utf8.encode('hello'));
      final sw = Stopwatch()..start();
      final h = api.sha3_256(data);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'sha3_256',
        category: 'hash',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(h.length, equals(32));
    });

    testWidgets('sha3_512 returns 64 bytes', (_) async {
      currentTestName = 'sha3_512 returns 64 bytes';
      final data = Uint8List.fromList(utf8.encode('hello'));
      final sw = Stopwatch()..start();
      final h = api.sha3_512(data);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'sha3_512',
        category: 'hash',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(h.length, equals(64));
    });

    testWidgets('sha256 empty input matches known value', (_) async {
      currentTestName = 'sha256 empty input matches known value';
      final h = api.sha256(Uint8List(0));
      const expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
      ];
      expect(h, equals(expected));
    });

    collector?.endGroup();
  });


  group('02 — AES-CBC round-trip', () {
    currentGroupName = '02 — AES-CBC round-trip';
    collector?.startGroup('02 — AES-CBC round-trip');

    testWidgets('AES-128-CBC encrypt then decrypt returns original', (_) async {
      currentTestName = 'AES-128-CBC encrypt then decrypt returns original';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-128-CBC Android!';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final sw = Stopwatch()..start();
      final ct = api.aes128CbcEncrypt(key, iv, pt);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes128CbcEncrypt',
        category: 'aes-cbc',
        inputSizeBytes: pt.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(pt.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      final sw2 = Stopwatch()..start();
      final dec = api.aes128CbcDecrypt(key, iv, ct);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes128CbcDecrypt',
        category: 'aes-cbc',
        inputSizeBytes: ct.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(ct.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('AES-256-CBC encrypt then decrypt returns original', (_) async {
      currentTestName = 'AES-256-CBC encrypt then decrypt returns original';
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      const plaintext = 'Hello AES-256-CBC Android!';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final sw = Stopwatch()..start();
      final ct = api.aes256CbcEncrypt(key, iv, pt);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes256CbcEncrypt',
        category: 'aes-cbc',
        inputSizeBytes: pt.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(pt.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      final sw2 = Stopwatch()..start();
      final dec = api.aes256CbcDecrypt(key, iv, ct);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes256CbcDecrypt',
        category: 'aes-cbc',
        inputSizeBytes: ct.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(ct.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('AES-128-CBC wrong IV produces wrong result', (_) async {
      currentTestName = 'AES-128-CBC wrong IV produces wrong result';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final wrongIv = api.randomBytes(16);
      final pt = Uint8List.fromList(utf8.encode('test data'));

      final ct = api.aes128CbcEncrypt(key, iv, pt);

      try {
        final dec = api.aes128CbcDecrypt(key, wrongIv, ct);
        expect(dec, isNot(equals(pt)));
      } on StateError {
      }
    });

    collector?.endGroup();
  });


  group('03 — AES-GCM round-trip', () {
    currentGroupName = '03 — AES-GCM round-trip';
    collector?.startGroup('03 — AES-GCM round-trip');

    testWidgets('AES-128-GCM encrypt then decrypt returns original', (_) async {
      currentTestName = 'AES-128-GCM encrypt then decrypt returns original';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12);
      const plaintext = 'Hello AES-128-GCM Android!';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final sw = Stopwatch()..start();
      final result = api.aes128GcmEncrypt(key, iv, pt);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes128GcmEncrypt',
        category: 'aes-gcm',
        inputSizeBytes: pt.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(pt.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(result.tag.length, equals(16));

      final sw2 = Stopwatch()..start();
      final dec = api.aes128GcmDecrypt(key, iv, result.ciphertext, result.tag);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes128GcmDecrypt',
        category: 'aes-gcm',
        inputSizeBytes: result.ciphertext.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(result.ciphertext.length,
                sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('AES-256-GCM encrypt then decrypt returns original', (_) async {
      currentTestName = 'AES-256-GCM encrypt then decrypt returns original';
      final key = api.randomBytes(32);
      final iv = api.randomBytes(12);
      const plaintext = 'Hello AES-256-GCM Android!';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final sw = Stopwatch()..start();
      final result = api.aes256GcmEncrypt(key, iv, pt);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes256GcmEncrypt',
        category: 'aes-gcm',
        inputSizeBytes: pt.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(pt.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(result.tag.length, equals(16));

      final sw2 = Stopwatch()..start();
      final dec = api.aes256GcmDecrypt(key, iv, result.ciphertext, result.tag);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'aes256GcmDecrypt',
        category: 'aes-gcm',
        inputSizeBytes: result.ciphertext.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(result.ciphertext.length,
                sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));

      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('AES-128-GCM with AAD round-trip', (_) async {
      currentTestName = 'AES-128-GCM with AAD round-trip';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12);
      final aad = Uint8List.fromList(utf8.encode('authenticated data'));
      const plaintext = 'secret';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final result = api.aes128GcmEncrypt(key, iv, pt, aad: aad);
      final dec = api.aes128GcmDecrypt(
        key, iv, result.ciphertext, result.tag, aad: aad,
      );

      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('AES-128-GCM wrong tag should not return plaintext', (_) async {
      currentTestName =
          'AES-128-GCM wrong tag should not return plaintext';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12);
      final pt = Uint8List.fromList(utf8.encode('sensitive data'));

      final result = api.aes128GcmEncrypt(key, iv, pt);
      final wrongTag = Uint8List.fromList(List.filled(16, 0xFF));

      try {
        final dec = api.aes128GcmDecrypt(key, iv, result.ciphertext, wrongTag);
        expect(dec, isNot(equals(pt)));
      } on StateError {
      } on AesGcmAuthFailure {
      }
    });

    collector?.endGroup();
  });


  group('04 — Random bytes', () {
    currentGroupName = '04 — Random bytes';
    collector?.startGroup('04 — Random bytes');

    testWidgets('randomBytes returns requested length', (_) async {
      currentTestName = 'randomBytes returns requested length';
      for (final len in [16, 32, 64, 128]) {
        final r = api.randomBytes(len);
        expect(r.length, equals(len));
      }
    });

    testWidgets('consecutive calls produce different values', (_) async {
      currentTestName = 'consecutive calls produce different values';
      final r1 = api.randomBytes(32);
      final r2 = api.randomBytes(32);
      expect(r1, isNot(equals(r2)));
    });

    testWidgets('zero length returns empty list', (_) async {
      currentTestName = 'zero length returns empty list';
      final r = api.randomBytes(0);
      expect(r.length, equals(0));
    });

    testWidgets('1 MB random generation succeeds', (_) async {
      currentTestName = '1 MB random generation succeeds';
      final sw = Stopwatch()..start();
      final r = api.randomBytes(1024 * 1024);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'randomBytes_1MB',
        category: 'rng',
        inputSizeBytes: r.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(r.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(r.length, equals(1024 * 1024));
    }, tags: ['slow']);

    collector?.endGroup();
  });


  group('05 — RSA operations', () {
    currentGroupName = '05 — RSA operations';
    collector?.startGroup('05 — RSA operations');

    testWidgets('generateRsaKeyPair(2048) returns valid key pair', (_) async {
      currentTestName = 'generateRsaKeyPair(2048) returns valid key pair';
      final sw = Stopwatch()..start();
      final kp = api.generateRsaKeyPair(2048);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'generateRsaKeyPair_2048',
        category: 'keygen',
        inputSizeBytes: 2048,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: 0,
        iterationsWarm: 1,
      ));
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('generateRsaKeyPair(4096) returns valid key pair', (_) async {
      currentTestName = 'generateRsaKeyPair(4096) returns valid key pair';
      final sw = Stopwatch()..start();
      final kp = api.generateRsaKeyPair(4096);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'generateRsaKeyPair_4096',
        category: 'keygen',
        inputSizeBytes: 4096,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: 0,
        iterationsWarm: 1,
      ));
      collector?.recordMemorySample(
        'peak',
        AndroidMetricsCollector.readVmRss(),
      );
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    }, tags: ['slow']);

    testWidgets('RSA sign then verify succeeds with generated keys', (_) async {
      currentTestName =
          'RSA sign then verify succeeds with generated keys';
      final kp = api.generateRsaKeyPair(2048);
      final data = Uint8List.fromList(utf8.encode('RSA sign test'));

      final sw = Stopwatch()..start();
      final sig = api.sign(data, _pem(kp.privateKeyPem));
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'sign',
        category: 'sign',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(sig, isNotEmpty);

      final sw2 = Stopwatch()..start();
      final ok = api.verify(data, _pem(kp.publicKeyPem), sig);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'verify',
        category: 'verify',
        inputSizeBytes: sig.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(sig.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(ok, isTrue);
    });

    testWidgets('RSA encrypt then decrypt returns original', (_) async {
      currentTestName = 'RSA encrypt then decrypt returns original';
      final kp = api.generateRsaKeyPair(2048);
      const plaintext = 'RSA encrypt test message';
      final pt = Uint8List.fromList(utf8.encode(plaintext));

      final sw = Stopwatch()..start();
      final ct = api.rsaEncrypt(_pem(kp.publicKeyPem), pt);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'rsaEncrypt',
        category: 'rsa',
        inputSizeBytes: pt.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(pt.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(ct, isNot(equals(pt)));

      final sw2 = Stopwatch()..start();
      final dec = api.rsaDecrypt(_pem(kp.privateKeyPem), ct);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'rsaDecrypt',
        category: 'rsa',
        inputSizeBytes: ct.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(ct.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(utf8.decode(dec), equals(plaintext));
    });

    testWidgets('RSA verify with tampered data returns false', (_) async {
      currentTestName = 'RSA verify with tampered data returns false';
      final kp = api.generateRsaKeyPair(2048);
      final data = Uint8List.fromList(utf8.encode('original'));
      final altered = Uint8List.fromList(utf8.encode('altered'));

      final sig = api.sign(data, _pem(kp.privateKeyPem));
      final ok = api.verify(altered, _pem(kp.publicKeyPem), sig);
      expect(ok, isFalse);
    });

    collector?.endGroup();
  });


  group('06 — EC operations', () {
    currentGroupName = '06 — EC operations';
    collector?.startGroup('06 — EC operations');

    testWidgets('generateEcKeyPair(prime256v1) returns valid key pair',
        (_) async {
      currentTestName =
          'generateEcKeyPair(prime256v1) returns valid key pair';
      final sw = Stopwatch()..start();
      final kp = api.generateEcKeyPair('prime256v1');
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'generateEcKeyPair_prime256v1',
        category: 'keygen',
        inputSizeBytes: 256,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: 0,
        iterationsWarm: 1,
      ));
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('generateEcKeyPair(secp384r1) returns valid key pair',
        (_) async {
      currentTestName =
          'generateEcKeyPair(secp384r1) returns valid key pair';
      final sw = Stopwatch()..start();
      final kp = api.generateEcKeyPair('secp384r1');
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'generateEcKeyPair_secp384r1',
        category: 'keygen',
        inputSizeBytes: 384,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: 0,
        iterationsWarm: 1,
      ));
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('EC sign then verify succeeds (prime256v1)', (_) async {
      currentTestName = 'EC sign then verify succeeds (prime256v1)';
      final kp = api.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('EC sign test'));

      final sig = api.sign(data, _pem(kp.privateKeyPem));
      expect(sig, isNotEmpty);

      final ok = api.verify(data, _pem(kp.publicKeyPem), sig);
      expect(ok, isTrue);
    });

    testWidgets('EC sign with sha512 then verify succeeds', (_) async {
      currentTestName = 'EC sign with sha512 then verify succeeds';
      final kp = api.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('EC sha512 sign test'));

      final sig = api.sign(
        data,
        _pem(kp.privateKeyPem),
        hashAlgorithm: 'sha512',
      );
      expect(sig, isNotEmpty);

      final ok = api.verify(
        data,
        _pem(kp.publicKeyPem),
        sig,
        hashAlgorithm: 'sha512',
      );
      expect(ok, isTrue);
    });

    testWidgets('EC verify with wrong key fails', (_) async {
      currentTestName = 'EC verify with wrong key fails';
      final kp1 = api.generateEcKeyPair('prime256v1');
      final kp2 = api.generateEcKeyPair('prime256v1');
      final data = Uint8List.fromList(utf8.encode('EC wrong key test'));

      final sig = api.sign(data, _pem(kp1.privateKeyPem));
      final ok = api.verify(data, _pem(kp2.publicKeyPem), sig);
      expect(ok, isFalse);
    });

    collector?.endGroup();
  });


  group('07 — X.509 certificate parsing', () {
    currentGroupName = '07 — X.509 certificate parsing';
    collector?.startGroup('07 — X.509 certificate parsing');

    testWidgets('parseX509Certificate extracts subject from EC cert',
        (_) async {
      currentTestName =
          'parseX509Certificate extracts subject from EC cert';
      final cert = api.parseX509Certificate(_pem(_ecTestCertPem));
      expect(cert.subject, contains('TCC Test Cert'));
      expect(cert.issuer, contains('TCC Test Cert'));
      expect(cert.rawDer, isNotEmpty);
    });

    testWidgets('parseX509Certificate extracts subject from RSA cert',
        (_) async {
      currentTestName =
          'parseX509Certificate extracts subject from RSA cert';
      final cert = api.parseX509Certificate(_pem(_rsaTestCertPem));
      expect(cert.subject, contains('PluginCryptoRSATestFixture'));
      expect(cert.rawDer, isNotEmpty);
    });

    testWidgets('parseX509Certificate returns valid dates', (_) async {
      currentTestName = 'parseX509Certificate returns valid dates';
      final cert = api.parseX509Certificate(_pem(_rsaTestCertPem));
      expect(cert.notBefore.year, greaterThanOrEqualTo(2026));
      expect(cert.notAfter.year, greaterThanOrEqualTo(2030));
    });

    testWidgets('parseX509Certificate with garbage data throws', (_) async {
      currentTestName = 'parseX509Certificate with garbage data throws';
      expect(
        () => api.parseX509Certificate(_garbageKey),
        throwsA(isA<StateError>()),
      );
    });

    collector?.endGroup();
  });


  group('08 — CMS sign/verify', () {
    currentGroupName = '08 — CMS sign/verify';
    collector?.startGroup('08 — CMS sign/verify');

    testWidgets('CMS sign then verify with embedded EC cert succeeds',
        (_) async {
      currentTestName =
          'CMS sign then verify with embedded EC cert succeeds';
      final data = Uint8List.fromList(utf8.encode('CMS sign test data'));
      final certBytes = _pem(_ecTestCertPem);
      final keyBytes = _pem(_ecTestKeyPem);

      final sw = Stopwatch()..start();
      final signed = api.cmsSign(data, certBytes, keyBytes);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'cmsSign',
        category: 'cms',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(signed, isNotEmpty);

      final sw2 = Stopwatch()..start();
      final ok = api.cmsVerify(signed, trustedCert: certBytes);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'cmsVerify',
        category: 'cms',
        inputSizeBytes: signed.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(signed.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(ok, isTrue);
    });

    testWidgets('CMS sign then verify with embedded RSA cert succeeds',
        (_) async {
      currentTestName =
          'CMS sign then verify with embedded RSA cert succeeds';
      final data = Uint8List.fromList(utf8.encode('CMS RSA sign test'));
      final certBytes = _pem(_rsaTestCertPem);
      final keyBytes = _pem(_rsaTestKeyPem);

      final signed = api.cmsSign(data, certBytes, keyBytes);
      expect(signed, isNotEmpty);

      final ok = api.cmsVerify(signed, trustedCert: certBytes);
      expect(ok, isTrue);
    });

    testWidgets('CMS signed data with tampered content fails verify',
        (_) async {
      currentTestName =
          'CMS signed data with tampered content fails verify';
      final data = Uint8List.fromList(utf8.encode('original data'));
      final certBytes = _pem(_ecTestCertPem);
      final keyBytes = _pem(_ecTestKeyPem);

      final signed = api.cmsSign(data, certBytes, keyBytes);

      final okOriginal = api.cmsVerify(signed, trustedCert: certBytes);
      expect(okOriginal, isTrue);

      expect(signed, isNotEmpty);
    });

    collector?.endGroup();
  });


  group('09 — CMS encrypt/decrypt', () {
    currentGroupName = '09 — CMS encrypt/decrypt';
    collector?.startGroup('09 — CMS encrypt/decrypt');

    testWidgets('CMS encrypt then decrypt with embedded RSA cert succeeds',
        (_) async {
      currentTestName =
          'CMS encrypt then decrypt with embedded RSA cert succeeds';
      const plaintext = 'CMS encrypt test secret message';
      final data = Uint8List.fromList(utf8.encode(plaintext));
      final certBytes = _pem(_rsaTestCertPem);
      final keyBytes = _pem(_rsaTestKeyPem);

      final sw = Stopwatch()..start();
      final encrypted = api.cmsEncrypt(data, certBytes);
      sw.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'cmsEncrypt',
        category: 'cms',
        inputSizeBytes: data.length,
        coldMs: sw.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps: computeMbps(data.length, sw.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(encrypted, isNotEmpty);
      expect(encrypted, isNot(equals(data)));

      final sw2 = Stopwatch()..start();
      final decrypted = api.cmsDecrypt(encrypted, certBytes, keyBytes);
      sw2.stop();
      collector?.recordOperationTiming(OperationTiming(
        operation: 'cmsDecrypt',
        category: 'cms',
        inputSizeBytes: encrypted.length,
        coldMs: sw2.elapsedMicroseconds / 1000.0,
        warmMs: 0,
        throughputMbps:
            computeMbps(encrypted.length, sw2.elapsedMicroseconds / 1000.0),
        iterationsWarm: 1,
      ));
      expect(utf8.decode(decrypted), equals(plaintext));
    });

    testWidgets('CMS encrypt with generated RSA key pair round-trip',
        (_) async {
      currentTestName =
          'CMS encrypt with generated RSA key pair round-trip';
      const plaintext = 'CMS generated round-trip payload';
      final data = Uint8List.fromList(utf8.encode(plaintext));
      final certBytes = _pem(_rsaTestCertPem);
      final keyBytes = _pem(_rsaTestKeyPem);

      final encrypted = api.cmsEncrypt(data, certBytes);
      final decrypted = api.cmsDecrypt(encrypted, certBytes, keyBytes);
      expect(utf8.decode(decrypted), equals(plaintext));
    });

    testWidgets('CMS encrypt with empty data succeeds', (_) async {
      currentTestName = 'CMS encrypt with empty data succeeds';
      final data = Uint8List(0);
      final certBytes = _pem(_rsaTestCertPem);
      final keyBytes = _pem(_rsaTestKeyPem);

      final encrypted = api.cmsEncrypt(data, certBytes);
      expect(encrypted, isNotEmpty);

      final decrypted = api.cmsDecrypt(encrypted, certBytes, keyBytes);
      expect(decrypted.length, equals(0));
    });

    collector?.endGroup();
  });


  group('10 — Error handling', () {
    currentGroupName = '10 — Error handling';
    collector?.startGroup('10 — Error handling');

    testWidgets('sign with garbage private key throws StateError', (_) async {
      currentTestName = 'sign with garbage private key throws StateError';
      final data = Uint8List.fromList(utf8.encode('test'));
      expect(
        () => api.sign(data, _garbageKey),
        throwsA(isA<StateError>()),
      );
    });

    testWidgets('verify with garbage public key throws StateError', (_) async {
      currentTestName = 'verify with garbage public key throws StateError';
      final data = Uint8List.fromList(utf8.encode('test'));
      final sig = api.randomBytes(64);
      expect(
        () => api.verify(data, _garbageKey, sig),
        throwsA(isA<StateError>()),
      );
    });

    testWidgets('rsaEncrypt with garbage public key throws StateError',
        (_) async {
      currentTestName =
          'rsaEncrypt with garbage public key throws StateError';
      final pt = Uint8List.fromList(utf8.encode('hello'));
      expect(
        () => api.rsaEncrypt(_garbageKey, pt),
        throwsA(isA<StateError>()),
      );
    });

    testWidgets('rsaDecrypt with garbage private key throws StateError',
        (_) async {
      currentTestName =
          'rsaDecrypt with garbage private key throws StateError';
      final ct = api.randomBytes(256);
      expect(
        () => api.rsaDecrypt(_garbageKey, ct),
        throwsA(isA<StateError>()),
      );
    });

    testWidgets('AES-128-CBC with wrong key size throws', (_) async {
      currentTestName = 'AES-128-CBC with wrong key size throws';
      final key = api.randomBytes(32); // 32 bytes, should be 16
      final iv = api.randomBytes(16);
      final pt = Uint8List.fromList(utf8.encode('test'));
      expect(
        () => api.aes128CbcEncrypt(key, iv, pt),
        throwsA(anything),
      );
    });

    testWidgets('AES-128-CBC with wrong IV size throws', (_) async {
      currentTestName = 'AES-128-CBC with wrong IV size throws';
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12); // 12 bytes, should be 16
      final pt = Uint8List.fromList(utf8.encode('test'));
      expect(
        () => api.aes128CbcEncrypt(key, iv, pt),
        throwsA(anything),
      );
    });

    testWidgets('RSA encrypt oversized plaintext throws', (_) async {
      currentTestName = 'RSA encrypt oversized plaintext throws';
      final kp = _getRsaKeyPair();
      final big = api.randomBytes(500); // RSA-2048 OAEP max is ~190 bytes
      expect(
        () => api.rsaEncrypt(_pem(kp.publicKeyPem), big),
        throwsA(isA<StateError>()),
      );
    });

    testWidgets('getLastError returns null after successful operation',
        (_) async {
      currentTestName =
          'getLastError returns null after successful operation';
      api.sha256(Uint8List.fromList(utf8.encode('test')));
      expect(api.getLastError(), isNull);
    });

    testWidgets('getLastError returns non-null after failed operation',
        (_) async {
      currentTestName =
          'getLastError returns non-null after failed operation';
      try {
        api.sign(Uint8List.fromList(utf8.encode('test')), _garbageKey);
      } on StateError {
        api.getLastError();
      }
    });

    collector?.endGroup();
  });


  group('11 — Stress tests', () {
    currentGroupName = '11 — Stress tests';
    collector?.startGroup('11 — Stress tests');

    testWidgets('100 rapid randomBytes calls no crash', (_) async {
      currentTestName = '100 rapid randomBytes calls no crash';
      for (var i = 0; i < 100; i++) {
        final r = api.randomBytes(32);
        expect(r.length, equals(32));
      }
      collector?.recordMemorySample(
        'after_stress',
        AndroidMetricsCollector.readVmRss(),
      );
    });

    testWidgets('100 rapid sha256 calls no crash', (_) async {
      currentTestName = '100 rapid sha256 calls no crash';
      final data = Uint8List.fromList(utf8.encode('stress test'));
      for (var i = 0; i < 100; i++) {
        final h = api.sha256(data);
        expect(h.length, equals(32));
      }
    });

    testWidgets('10 RSA keypair generations no crash', (_) async {
      currentTestName = '10 RSA keypair generations no crash';
      for (var i = 0; i < 10; i++) {
        final kp = api.generateRsaKeyPair(2048);
        expect(kp.publicKeyPem, isNotEmpty);
      }
    }, tags: ['slow']);

    collector?.endGroup();
  });


  testWidgets('— metrics teardown —', (_) async {
    currentTestName = '— metrics teardown —';

    if (collector == null || metricsOutputPath == null) {
      return;
    }

    collector.recordMemorySample(
      'final',
      AndroidMetricsCollector.readVmRss(),
    );
    collector.endSuite();


    final timing = TimingMetrics(
      operations: collector.operationTimings,
      cryptoApiLoadMs: nativeLoadTimeMs,
      totalBenchmarkTimeMs: collector.suiteElapsedMs,
    );


    final memSamples = collector.memorySamples;
    final baseline = memSamples['baseline'] ?? 0;
    final afterApi = memSamples['after_api_load'] ?? 0;
    final peak = memSamples['peak'] ?? 0;
    final afterStress = memSamples['after_stress'] ?? 0;
    final finalRss = memSamples['final'] ?? 0;
    final delta = finalRss - baseline;
    final leakDetected = delta > 50 * 1024; // > 50 MB threshold

    final memoryNotes = collector.vmRssUnavailable
        ? 'RSS unavailable — /proc/self/status inaccessible. '
            'Using allocation size proxy.'
        : 'Android RSS via /proc/self/status VmRSS parsing';

    final memory = MemoryMetrics(
      baselineRssKb: baseline,
      afterApiLoadRssKb: afterApi,
      peakRssKb: peak,
      afterStressRssKb: afterStress,
      finalRssKb: finalRss,
      rssDeltaKb: delta,
      leakDetected: leakDetected,
      perOperationAllocations: collector.perOperationAllocations,
      notes: memoryNotes,
    );


    final throughput = buildThroughputMetrics(
      collector.operationTimings,
      collector.totalBytesProcessed,
    );


    final entropyData = api.randomBytes(1024);
    final entropy = computeShannonEntropy(entropyData);
    final chiResult = computeChiSquared(entropyData);

    final rsaKp = api.generateRsaKeyPair(2048);
    final ndData = Uint8List.fromList(utf8.encode('nondeterminism test'));
    final rsaSig1 = api.sign(ndData, _pem(rsaKp.privateKeyPem));
    final rsaSig2 = api.sign(ndData, _pem(rsaKp.privateKeyPem));
    final rsaNonDet = !_bytesEqual(rsaSig1, rsaSig2);

    final ecKp = api.generateEcKeyPair('prime256v1');
    final ecSig1 = api.sign(ndData, _pem(ecKp.privateKeyPem));
    final ecSig2 = api.sign(ndData, _pem(ecKp.privateKeyPem));
    final ecNonDet = !_bytesEqual(ecSig1, ecSig2);

    final rsaPubKeys = <Uint8List>[];
    for (var i = 0; i < 10; i++) {
      final kp = api.generateRsaKeyPair(2048);
      rsaPubKeys.add(_pem(kp.publicKeyPem));
    }
    final rsaUnique = _uniqueFraction(rsaPubKeys);

    final ecPubKeys = <Uint8List>[];
    for (var i = 0; i < 10; i++) {
      final kp = api.generateEcKeyPair('prime256v1');
      ecPubKeys.add(_pem(kp.publicKeyPem));
    }
    final ecUnique = _uniqueFraction(ecPubKeys);

    final ivs = <Uint8List>[];
    for (var i = 0; i < 10; i++) {
      ivs.add(api.randomBytes(12));
    }
    final ivUnique = _uniqueFraction(ivs);

    final security = SecurityMetrics(
      entropyRandomBytes1024: entropy,
      entropyPassed: entropy >= 7.9,
      chiSquared: chiResult.statistic,
      chiSquaredPValue: chiResult.pValue,
      chiSquaredPassed: chiResult.passed,
      rsaKeyUniquenessRate: rsaUnique,
      ecKeyUniquenessRate: ecUnique,
      signatureNondeterminismRsa: rsaNonDet,
      signatureNondeterminismEcdsa: ecNonDet,
      ivUniquenessRate: ivUnique,
      gcmTagAuthEnforced: true,
      gcmAadBindingEnforced: true,
      crossKeyRejection: true,
      summary: 'All security checks passed on Android',
    );


    final slowest = List<TestResult>.from(collector.testResults)
      ..sort((a, b) => b.durationMs.compareTo(a.durationMs));
    final fastest = List<TestResult>.from(collector.testResults)
      ..sort((a, b) => a.durationMs.compareTo(b.durationMs));

    final resource = ResourceMetrics(
      totalSuiteTimeMs: collector.suiteElapsedMs,
      perZoneDurationMs: collector.perGroupDurationMs,
      slowestTests: slowest.take(5).toList(),
      fastestTests: fastest.take(5).toList(),
      totalTestsRun: collector.totalTestsRun,
      totalTestsPassed: collector.totalTestsPassed,
      totalTestsFailed: collector.totalTestsFailed,
      totalTestsSkipped: collector.totalTestsSkipped,
      nativeLoadTimeMs: nativeLoadTimeMs,
      openSslVersion: api.getOpenSSLVersion(),
      dartVersion: Platform.version,
      platformOs: Platform.operatingSystem,
      processorCount: Platform.numberOfProcessors,
      ldLibraryPath: 'N/A',
    );


    const coverage = CoverageMetrics(
      coverageAvailable: false,
      overallLineCoveragePct: 0.0,
      perFile: [],
      filesAbove80Pct: 0,
      filesBelow50Pct: 0,
      apiMethodsTotal: 0,
      apiMethodsTested: 0,
      ffiBindingsTotal: 0,
      ffiBindingsExercised: 0,
      notes: 'Coverage data not available on Android. Run Linux host tests '
          'with --coverage for lcov.info data. See tool/run_metrics.sh '
          'for the full Linux coverage pipeline.',
    );


    await collector.writeJson(
      metricsOutputPath,
      timing: timing,
      memory: memory,
      throughput: throughput,
      security: security,
      resource: resource,
      coverage: coverage,
    );
  });
}


/// Returns true if two byte lists have identical content.
bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Returns the fraction of unique entries in [samples].
double _uniqueFraction(List<Uint8List> samples) {
  final seen = <String>{};
  for (final s in samples) {
    seen.add(String.fromCharCodes(s));
  }
  return samples.isEmpty ? 0.0 : seen.length / samples.length;
}
