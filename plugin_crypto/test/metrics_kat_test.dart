@Tags(['metrics'])
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

import 'fixtures/helpers.dart' as helpers;
import 'fixtures/test_vectors.dart';

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();

  int sha256Passed = 0;
  int sha256Failed = 0;
  int sha512Passed = 0;
  int sha512Failed = 0;
  int sha3_256Passed = 0;
  int sha3_256Failed = 0;
  int sha3_512Passed = 0;
  int sha3_512Failed = 0;
  int aesCbc128Passed = 0;
  int aesCbc128Failed = 0;
  int aesCbc256Passed = 0;
  int aesCbc256Failed = 0;
  int aesGcm128Passed = 0;
  int aesGcm128Failed = 0;
  int aesGcm256Passed = 0;
  int aesGcm256Failed = 0;

  group('KAT: SHA-256', () {
    for (final v in sha256Vectors) {
      test('${v.expectedHex.substring(0, 16)}...', () {
        try {
          final digest = api.sha256(v.input);
          final hex = digest
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join();
          expect(hex, v.expectedHex);
          sha256Passed++;
        } catch (_) {
          sha256Failed++;
          rethrow;
        }
      });
    }
  });

  group('KAT: SHA-512', () {
    for (final v in sha512Vectors) {
      test('${v.expectedHex.substring(0, 16)}...', () {
        try {
          final digest = api.sha512(v.input);
          final hex = digest
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join();
          expect(hex, v.expectedHex);
          sha512Passed++;
        } catch (_) {
          sha512Failed++;
          rethrow;
        }
      });
    }
  });

  group('KAT: SHA3-256', () {
    for (final v in sha3_256Vectors) {
      test('${v.expectedHex.substring(0, 16)}...', () {
        try {
          final digest = api.sha3_256(v.input);
          final hex = digest
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join();
          expect(hex, v.expectedHex);
          sha3_256Passed++;
        } catch (_) {
          sha3_256Failed++;
          rethrow;
        }
      });
    }
  });

  group('KAT: SHA3-512', () {
    for (final v in sha3_512Vectors) {
      test('${v.expectedHex.substring(0, 16)}...', () {
        try {
          final digest = api.sha3_512(v.input);
          final hex = digest
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join();
          expect(hex, v.expectedHex);
          sha3_512Passed++;
        } catch (_) {
          sha3_512Failed++;
          rethrow;
        }
      });
    }
  });

  group('KAT: AES-CBC', () {
    group('AES-128-CBC', () {
      for (final v in aes128CbcVectors) {
        test(v.description, () {
          try {
            final ct = api.aes128CbcEncrypt(v.key, v.iv, v.plaintext);
            final pt = api.aes128CbcDecrypt(v.key, v.iv, ct);
            expect(pt, equals(v.plaintext));
            aesCbc128Passed++;
          } catch (_) {
            aesCbc128Failed++;
            rethrow;
          }
        });
      }
    });

    group('AES-256-CBC', () {
      for (final v in aes256CbcVectors) {
        test(v.description, () {
          try {
            final ct = api.aes256CbcEncrypt(v.key, v.iv, v.plaintext);
            final pt = api.aes256CbcDecrypt(v.key, v.iv, ct);
            expect(pt, equals(v.plaintext));
            aesCbc256Passed++;
          } catch (_) {
            aesCbc256Failed++;
            rethrow;
          }
        });
      }
    });
  });

  group('KAT: AES-GCM', () {
    group('AES-128-GCM', () {
      for (final v in aes128GcmVectors) {
        test(v.description, () {
          try {
            final result = api.aes128GcmEncrypt(
              v.key,
              v.iv,
              v.plaintext,
              aad: v.aad,
            );
            expect(result.ciphertext, equals(v.ciphertext));
            expect(result.tag, equals(v.tag));
            final pt = api.aes128GcmDecrypt(
              v.key,
              v.iv,
              result.ciphertext,
              result.tag,
              aad: v.aad,
            );
            expect(pt, equals(v.plaintext));
            aesGcm128Passed++;
          } catch (_) {
            aesGcm128Failed++;
            rethrow;
          }
        });
      }
    });

    group('AES-256-GCM', () {
      for (final v in aes256GcmVectors) {
        test(v.description, () {
          try {
            final result = api.aes256GcmEncrypt(
              v.key,
              v.iv,
              v.plaintext,
              aad: v.aad,
            );
            expect(result.ciphertext, equals(v.ciphertext));
            expect(result.tag, equals(v.tag));
            final pt = api.aes256GcmDecrypt(
              v.key,
              v.iv,
              result.ciphertext,
              result.tag,
              aad: v.aad,
            );
            expect(pt, equals(v.plaintext));
            aesGcm256Passed++;
          } catch (_) {
            aesGcm256Failed++;
            rethrow;
          }
        });
      }
    });
  });

  tearDownAll(() {
    void record(String standard, String algorithm, int passed, int failed) {
      final total = passed + failed;
      if (total == 0) return;
      final allPassed = failed == 0;
      final details =
          '$passed/$total vectors passed${failed > 0 ? ', $failed FAILED' : ''}';
      _collector.recordKatSummary(
        KatSummary(
          standard: standard,
          algorithm: algorithm,
          vectorsTested: total,
          vectorsPassed: passed,
          vectorsFailed: failed,
          passRate: total > 0 ? passed / total : 0.0,
          allPassed: allPassed,
          details: details,
        ),
      );
    }

    record('NIST CAVP', 'SHA-256', sha256Passed, sha256Failed);
    record('NIST CAVP', 'SHA-512', sha512Passed, sha512Failed);
    record('NIST CAVP', 'SHA3-256', sha3_256Passed, sha3_256Failed);
    record('NIST CAVP', 'SHA3-512', sha3_512Passed, sha3_512Failed);
    record('NIST SP 800-38A', 'AES-128-CBC', aesCbc128Passed, aesCbc128Failed);
    record('NIST SP 800-38A', 'AES-256-CBC', aesCbc256Passed, aesCbc256Failed);
    record('NIST SP 800-38D', 'AES-128-GCM', aesGcm128Passed, aesGcm128Failed);
    record('NIST SP 800-38D', 'AES-256-GCM', aesGcm256Passed, aesGcm256Failed);
  });
}
