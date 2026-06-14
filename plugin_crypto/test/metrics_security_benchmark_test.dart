@Tags(['metrics'])
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/security_benchmark.dart';

import 'fixtures/helpers.dart' as helpers;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();

  group('HashBatchPerformance', () {
    test('batchHash sha256 at 100 iterations', () {
      final result = SecurityBenchmark.batchHash(api, 100, 1024);
      expect(result.totalBytes, greaterThan(0));
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
      expect(result.iterations, 100);
      expect(result.avgMsPerOp, greaterThan(0));
    });

    test('batchHash sha256 at 1000 iterations', () {
      final result = SecurityBenchmark.batchHash(api, 1000, 1024);
      expect(result.totalBytes, greaterThan(0));
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
      expect(result.iterations, 1000);
    });

    test('batchHash sha512 at 100 iterations, 1KB', () {
      final result = SecurityBenchmark.batchHash(api, 100, 1024);
      expect(result.totalBytes, 100 * 1024);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchHash sha3_256 at 100 iterations, 64KB', () {
      final result = SecurityBenchmark.batchHash(api, 100, 65536);
      expect(result.totalBytes, 100 * 65536);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchHash at 1000 iterations, 1MB', () {
      final result = SecurityBenchmark.batchHash(api, 1000, 1048576);
      expect(result.totalBytes, 1000 * 1048576);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
      expect(
        result.avgMsPerOp,
        lessThan(100),
        reason: 'Single hash operation should be well under 100ms',
      );
    });
  });

  group('CipherBatchPerformance', () {
    for (final cipher in ['aes128cbc', 'aes256cbc', 'aes128gcm', 'aes256gcm']) {
      test('batchEncrypt $cipher at 100 iterations, 1KB', () {
        final result = SecurityBenchmark.batchEncrypt(api, 100, 1024, cipher);
        expect(result.totalBytes, 100 * 1024);
        expect(result.elapsedMs, greaterThan(0));
        expect(result.operationsPerSec, greaterThan(0));
        expect(result.iterations, 100);
      });

      test('batchDecrypt $cipher at 100 iterations, 1KB', () {
        final result = SecurityBenchmark.batchDecrypt(api, 100, 1024, cipher);
        expect(result.totalBytes, 100 * 1024);
        expect(result.elapsedMs, greaterThan(0));
        expect(result.operationsPerSec, greaterThan(0));
        expect(result.iterations, 100);
      });
    }
  });

  group('KeyGenBatch', () {
    test(
      'batchKeyGen RSA-2048 at 10 iterations',
      () {
        final result = SecurityBenchmark.batchKeyGen(api, 10, 'rsa2048');
        expect(result.iterations, 10);
        expect(result.elapsedMs, greaterThan(0));
        expect(result.operationsPerSec, greaterThan(0));
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test(
      'batchKeyGen RSA-4096 at 10 iterations',
      () {
        final result = SecurityBenchmark.batchKeyGen(api, 10, 'rsa4096');
        expect(result.iterations, 10);
        expect(result.elapsedMs, greaterThan(0));
        expect(result.operationsPerSec, greaterThan(0));
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );

    test('batchKeyGen EC P-256 at 10 iterations', () {
      final result = SecurityBenchmark.batchKeyGen(api, 10, 'ecp256');
      expect(result.iterations, 10);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchKeyGen EC P-384 at 10 iterations', () {
      final result = SecurityBenchmark.batchKeyGen(api, 10, 'ecp384');
      expect(result.iterations, 10);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });
  });

  group('SignVerifyBatch', () {
    test('batchSign ECDSA P-256 at 100 iterations', () {
      final result = SecurityBenchmark.batchSign(api, 100);
      expect(result.iterations, 100);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchVerify ECDSA P-256 at 100 iterations', () {
      final result = SecurityBenchmark.batchVerify(api, 100);
      expect(result.iterations, 100);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchRsaSign RSA-2048 at 50 iterations', () {
      final result = SecurityBenchmark.batchRsaSign(api, 50, 2048);
      expect(result.iterations, 50);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });

    test('batchRsaVerify RSA-2048 at 50 iterations', () {
      final result = SecurityBenchmark.batchRsaVerify(api, 50, 2048);
      expect(result.iterations, 50);
      expect(result.elapsedMs, greaterThan(0));
      expect(result.operationsPerSec, greaterThan(0));
    });
  });

  group('CipherSuiteComparison', () {
    test(
      'compareCiphers returns 4 results sorted by encryption throughput',
      () {
        final results = CipherSuiteComparison.compareCiphers(
          api,
          dataSizeBytes: 1024,
          iterations: 50,
        );
        expect(results.length, 4, reason: 'Should return all 4 AES variants');
        for (final r in results) {
          expect(
            r.encryptMBps,
            greaterThan(0),
            reason: '${r.name} encrypt throughput should be positive',
          );
          expect(
            r.decryptMBps,
            greaterThan(0),
            reason: '${r.name} decrypt throughput should be positive',
          );
          expect(r.keySizeBits, anyOf(128, 256));
        }
        for (var i = 1; i < results.length; i++) {
          expect(
            results[i].encryptMBps,
            lessThanOrEqualTo(results[i - 1].encryptMBps),
            reason: 'Results should be sorted by encrypt throughput descending',
          );
        }
      },
    );

    test(
      'compareCertificates returns RSA-2048 and RSA-4096 results',
      () {
        final results = CipherSuiteComparison.compareCertificates(api);
        expect(results.length, 2);
        expect(results[0].name.contains('RSA'), isTrue);
        expect(results[1].name.contains('RSA'), isTrue);
        expect(
          results.map((r) => r.keySizeBits).toSet(),
          containsAll([2048, 4096]),
        );
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );

    test('compareCurves returns P-256, P-384, P-521 results', () {
      final results = CipherSuiteComparison.compareCurves(api);
      expect(results.length, 3);
      final names = results.map((r) => r.name).toSet();
      expect(names, contains('ECDSA-P-256'));
      expect(names, contains('ECDSA-P-384'));
      expect(names, contains('ECDSA-P-521'));
    });
  });

  group('TLSHandshakeSimulation', () {
    test('simulateHandshake returns non-zero timings', () {
      final result = TlsHandshakeSimulator.simulateHandshake(
        api,
        'TLS_AES_128_GCM_SHA256',
      );
      expect(result.handshakeTimeMs, greaterThan(0));
      expect(result.keyExchangeTimeMs, greaterThan(0));
      expect(result.certificateVerifyTimeMs, greaterThan(0));
      expect(result.hmacDerivationTimeMs, greaterThan(0));
      expect(result.cipherSuite, 'TLS_AES_128_GCM_SHA256');
    });

    test('simulateBulkTransfer returns valid throughput metrics', () {
      final result = TlsHandshakeSimulator.simulateBulkTransfer(
        api,
        'TLS_AES_128_GCM_SHA256',
        65536,
      );
      expect(result.bulkTransferEncryptMbps, greaterThan(0));
      expect(result.bulkTransferDecryptMbps, greaterThan(0));
      expect(result.numBulkTransfers, 1);
      expect(result.totalSessionMs, greaterThan(0));
    });

    test('simulateHandshake with TLS_AES_256_GCM_SHA384', () {
      final result = TlsHandshakeSimulator.simulateHandshake(
        api,
        'TLS_AES_256_GCM_SHA384',
      );
      expect(result.handshakeTimeMs, greaterThan(0));
      expect(result.cipherSuite, 'TLS_AES_256_GCM_SHA384');
    });

    test('simulateFullSession combines handshake and bulk transfers', () {
      final result = TlsHandshakeSimulator.simulateFullSession(
        api,
        'TLS_AES_128_GCM_SHA256',
        dataSizeBytes: 65536,
        numTransfers: 3,
      );
      expect(result.handshakeTimeMs, greaterThan(0));
      expect(result.numBulkTransfers, 3);
      expect(
        result.totalSessionMs,
        greaterThan(result.handshakeTimeMs),
        reason: 'Session time should include transfers',
      );
      expect(result.bulkTransferEncryptMbps, greaterThan(0));
      expect(result.bulkTransferDecryptMbps, greaterThan(0));
    });
  });

  group('WireUp', () {
    test('TimingMetrics includes cipherSuites when populated', () {
      final cipherResults = CipherSuiteComparison.compareCiphers(
        api,
        dataSizeBytes: 1024,
        iterations: 20,
      );

      final cipherMetrics = cipherResults.map((r) {
        return CipherPerformanceMetrics(
          cipherName: r.name,
          encryptMbps: r.encryptMBps,
          decryptMbps: r.decryptMBps,
          hwAccelerated: r.hwAccelerated,
          keySizeBits: r.keySizeBits,
          blockSizeBytes: 16,
          throughputRatio: r.ratio,
          comparisonRank: cipherResults.indexOf(r) + 1,
        );
      }).toList();

      final timing = TimingMetrics(
        operations: [],
        cryptoApiLoadMs: 0,
        totalBenchmarkTimeMs: 100,
        cipherSuites: cipherMetrics,
      );

      expect(timing.cipherSuites.length, 4);
      expect(timing.cipherSuites.first.cipherName, isNotEmpty);

      final json = timing.toJson();
      expect(json['cipher_suites'], isA<List<Object?>>());
      expect((json['cipher_suites'] as List).length, 4);

      final restored = TimingMetrics.fromJson(json);
      expect(restored.cipherSuites.length, 4);
      expect(
        restored.cipherSuites.first.cipherName,
        timing.cipherSuites.first.cipherName,
      );
    });

    test('MetricsReport includes cipherSuiteComparison and tlsSimulation', () {
      final cipherResults = CipherSuiteComparison.compareCiphers(
        api,
        dataSizeBytes: 1024,
        iterations: 20,
      );

      final cipherMetrics = cipherResults.map((r) {
        return CipherPerformanceMetrics(
          cipherName: r.name,
          encryptMbps: r.encryptMBps,
          decryptMbps: r.decryptMBps,
          hwAccelerated: r.hwAccelerated,
          keySizeBits: r.keySizeBits,
          blockSizeBytes: 16,
          throughputRatio: r.ratio,
          comparisonRank: cipherResults.indexOf(r) + 1,
        );
      }).toList();

      final comparison = CipherSuiteComparisonMetrics(
        perCipher: cipherMetrics,
        fastestCipher: cipherMetrics.first.cipherName,
        slowestCipher: cipherMetrics.last.cipherName,
        overallThroughputRatio:
            cipherMetrics.first.encryptMbps / cipherMetrics.last.encryptMbps,
      );

      final tlsResult = TlsHandshakeSimulator.simulateFullSession(
        api,
        'TLS_AES_128_GCM_SHA256',
        dataSizeBytes: 65536,
        numTransfers: 2,
      );
      final tlsSim = TlsSimulationMetrics(
        handshakeTimeMs: tlsResult.handshakeTimeMs,
        cipherSuite: tlsResult.cipherSuite,
        keyExchangeTimeMs: tlsResult.keyExchangeTimeMs,
        certificateVerifyTimeMs: tlsResult.certificateVerifyTimeMs,
        hmacDerivationTimeMs: tlsResult.hmacDerivationTimeMs,
        bulkTransferEncryptMbps: tlsResult.bulkTransferEncryptMbps,
        bulkTransferDecryptMbps: tlsResult.bulkTransferDecryptMbps,
        numBulkTransfers: tlsResult.numBulkTransfers,
        totalSessionMs: tlsResult.totalSessionMs,
      );

      _collector.recordCipherSuiteComparison(comparison);
      _collector.recordTlsSimulation(tlsSim);

      final report = _collector.buildReport(
        TimingMetrics(
          operations: [],
          cryptoApiLoadMs: 0,
          totalBenchmarkTimeMs: 100,
        ),
        MemoryMetrics(
          baselineRssKb: 0,
          afterApiLoadRssKb: 0,
          peakRssKb: 0,
          afterStressRssKb: 0,
          finalRssKb: 0,
          rssDeltaKb: 0,
          leakDetected: false,
          perOperationAllocations: {},
          notes: '',
        ),
        ThroughputMetrics(
          sha256Mbps: 0,
          sha384Mbps: 0,
          sha512Mbps: 0,
          sha3_256Mbps: 0,
          sha3_512Mbps: 0,
          aes128CbcEncryptMbps: 0,
          aes128CbcDecryptMbps: 0,
          aes256CbcEncryptMbps: 0,
          aes256CbcDecryptMbps: 0,
          aes128GcmEncryptMbps: 0,
          aes128GcmDecryptMbps: 0,
          aes256GcmEncryptMbps: 0,
          aes256GcmDecryptMbps: 0,
          rsa2048KeygenOpsPerMin: 0,
          rsa4096KeygenOpsPerMin: 0,
          ecPrime256v1KeygenOpsPerMin: 0,
          ecSecp384r1KeygenOpsPerMin: 0,
          ecSecp521r1KeygenOpsPerMin: 0,
          rsaSignPerSec: 0,
          rsaVerifyPerSec: 0,
          ecSignPerSec: 0,
          ecVerifyPerSec: 0,
          totalBytesProcessed: 0,
        ),
        SecurityMetrics(
          entropyRandomBytes1024: 0,
          entropyPassed: false,
          chiSquared: 0,
          chiSquaredPValue: 0,
          chiSquaredPassed: false,
          rsaKeyUniquenessRate: 0,
          ecKeyUniquenessRate: 0,
          signatureNondeterminismRsa: false,
          signatureNondeterminismEcdsa: false,
          ivUniquenessRate: 0,
          gcmTagAuthEnforced: false,
          gcmAadBindingEnforced: false,
          crossKeyRejection: false,
          summary: '',
        ),
        ResourceMetrics(
          totalSuiteTimeMs: 0,
          perZoneDurationMs: {},
          slowestTests: [],
          fastestTests: [],
          totalTestsRun: 0,
          totalTestsPassed: 0,
          totalTestsFailed: 0,
          totalTestsSkipped: 0,
          nativeLoadTimeMs: 0,
          openSslVersion: '',
          dartVersion: '',
          platformOs: '',
          processorCount: 0,
          ldLibraryPath: '',
        ),
        CoverageMetrics(
          coverageAvailable: false,
          overallLineCoveragePct: 0,
          perFile: [],
          filesAbove80Pct: 0,
          filesBelow50Pct: 0,
          apiMethodsTotal: 0,
          apiMethodsTested: 0,
          ffiBindingsTotal: 0,
          ffiBindingsExercised: 0,
          notes: '',
        ),
      );

      expect(report.cipherSuiteComparison, isNotNull);
      expect(report.cipherSuiteComparison!.perCipher.length, 4);
      expect(report.tlsSimulation, isNotNull);
      expect(report.tlsSimulation!.cipherSuite, 'TLS_AES_128_GCM_SHA256');
      expect(report.tlsSimulation!.totalSessionMs, greaterThan(0));

      final json = report.toJson();
      expect(json['cipher_suite_comparison'], isNotNull);
      expect(json['tls_simulation'], isNotNull);

      final restored = MetricsReport.fromJson(json);
      expect(restored.cipherSuiteComparison, isNotNull);
      expect(restored.tlsSimulation, isNotNull);
      expect(restored.cipherSuiteComparison!.perCipher.length, 4);
      expect(restored.tlsSimulation!.cipherSuite, 'TLS_AES_128_GCM_SHA256');
    });
  });
}
