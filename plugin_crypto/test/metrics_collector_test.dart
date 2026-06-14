library;

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

void main() {

  group('MetricsCollector lifecycle', () {
    late MetricsCollector collector;

    setUp(() {
      MetricsCollector.create();
      collector = MetricsCollector.instance!;
    });

    tearDown(() {
      MetricsCollector.create();
    });

    test('singleton is created and accessible', () {
      expect(MetricsCollector.instance, isNotNull);
      expect(identical(MetricsCollector.instance, collector), isTrue);
    });

    test('suite elapsed time increases', () async {
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(collector.suiteElapsedMs, greaterThan(0));
    });

    test('startZone and endZone accumulate zone records', () {
      collector.startZone('zone01', 'Native Loader');
      collector.endZone();
      collector.startZone('zone02', 'Hash');
      collector.endZone();

      final durations = collector.perZoneDurationMs;
      expect(durations.containsKey('zone01'), isTrue);
      expect(durations.containsKey('zone02'), isTrue);
      expect(durations['zone01']!, greaterThan(0));
      expect(durations['zone02']!, greaterThan(0));
    });

    test('recordTestResult accumulates test results', () {
      collector.recordTestResult('test_one', 'passed', 5);
      collector.recordTestResult('test_two', 'failed', 12);
      collector.recordTestResult('test_three', 'skipped', 0);

      expect(collector.totalTestsRun, 3);
      expect(collector.totalTestsPassed, 1);
      expect(collector.totalTestsFailed, 1);
      expect(collector.totalTestsSkipped, 1);
    });

    test('recordOperationTiming accumulates timings', () {
      collector.recordOperationTiming(
        OperationTiming(
          operation: 'sha256',
          category: 'hash',
          inputSizeBytes: 1048576,
          coldMs: 2.5,
          warmMs: 1.8,
          throughputMbps: 580.0,
          iterationsWarm: 95,
        ),
      );

      expect(collector.operationTimings.length, 1);
      expect(collector.totalBytesProcessed, 1048576);
    });

    test('recordMemorySample stores RSS values', () {
      collector.recordMemorySample('baseline', 50000);
      collector.recordMemorySample('peak', 75000);

      expect(collector.memorySamples['baseline'], 50000);
      expect(collector.memorySamples['peak'], 75000);
    });

    test('recordSecurityCheck stores security results', () {
      collector.recordSecurityCheck('entropy', true, {'value': 7.98});
      collector.recordSecurityCheck('chi_squared', false, {'p_value': 0.001});

      final checks = collector.securityChecks;
      expect(checks['entropy']!.passed, isTrue);
      expect(checks['chi_squared']!.passed, isFalse);
    });

    test('endSuite stops the stopwatch', () {
      collector.endSuite();
      final t1 = collector.suiteElapsedMs;
      final t2 = collector.suiteElapsedMs;
      expect(t1, equals(t2));
    });

    test('buildReport produces a valid MetricsReport', () {
      collector.endSuite();
      final report = collector.buildReport(
        TimingMetrics(
          operations: [],
          cryptoApiLoadMs: 0,
          totalBenchmarkTimeMs: 0,
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

      expect(report.schemaVersion, '1.2.0');
      expect(report.projectName, 'plugin_crypto');
      expect(report.generatedAt, isNotEmpty);
    });
  });


  group('JSON round-trip: OperationTiming', () {
    test('serializes and deserializes correctly', () {
      final original = OperationTiming(
        operation: 'sha256',
        category: 'hash',
        inputSizeBytes: 1048576,
        coldMs: 2.31,
        warmMs: 1.89,
        throughputMbps: 554.2,
        iterationsWarm: 95,
      );

      final json = original.toJson();
      final restored = OperationTiming.fromJson(json);

      expect(restored.operation, original.operation);
      expect(restored.category, original.category);
      expect(restored.inputSizeBytes, original.inputSizeBytes);
      expect(restored.coldMs, original.coldMs);
      expect(restored.warmMs, original.warmMs);
      expect(restored.throughputMbps, original.throughputMbps);
      expect(restored.iterationsWarm, original.iterationsWarm);
    });
  });

  group('JSON round-trip: full MetricsReport', () {
    test('empty report round-trips through JSON', () {
      final collector = MetricsCollector.instance!;
      collector.endSuite();

      final report = collector.buildReport(
        TimingMetrics(
          operations: [],
          cryptoApiLoadMs: 0,
          totalBenchmarkTimeMs: 0,
        ),
        MemoryMetrics(
          baselineRssKb: 100,
          afterApiLoadRssKb: 200,
          peakRssKb: 300,
          afterStressRssKb: 250,
          finalRssKb: 150,
          rssDeltaKb: 50,
          leakDetected: false,
          perOperationAllocations: {'sha256': 2, 'aesCbcEncrypt': 4},
          notes: 'test',
        ),
        ThroughputMetrics(
          sha256Mbps: 554.2,
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
          entropyRandomBytes1024: 7.98,
          entropyPassed: true,
          chiSquared: 245.3,
          chiSquaredPValue: 0.52,
          chiSquaredPassed: true,
          rsaKeyUniquenessRate: 1.0,
          ecKeyUniquenessRate: 1.0,
          signatureNondeterminismRsa: true,
          signatureNondeterminismEcdsa: true,
          ivUniquenessRate: 1.0,
          gcmTagAuthEnforced: true,
          gcmAadBindingEnforced: true,
          crossKeyRejection: true,
          summary: 'All passed',
        ),
        ResourceMetrics(
          totalSuiteTimeMs: 5000,
          perZoneDurationMs: {'zone01': 100.0, 'zone02': 200.0},
          slowestTests: [
            TestResult(name: 'slow', status: 'passed', durationMs: 500),
          ],
          fastestTests: [
            TestResult(name: 'fast', status: 'passed', durationMs: 1),
          ],
          totalTestsRun: 168,
          totalTestsPassed: 167,
          totalTestsFailed: 0,
          totalTestsSkipped: 1,
          nativeLoadTimeMs: 45.0,
          openSslVersion: 'OpenSSL 4.0.0',
          dartVersion: '3.x',
          platformOs: 'linux',
          processorCount: 8,
          ldLibraryPath: '/path/to/libs',
        ),
        CoverageMetrics(
          coverageAvailable: true,
          overallLineCoveragePct: 85.5,
          perFile: [
            FileCoverage(
              filePath: 'a.dart',
              totalLines: 100,
              coveredLines: 85,
              coveragePct: 85.0,
            ),
          ],
          filesAbove80Pct: 1,
          filesBelow50Pct: 0,
          apiMethodsTotal: 30,
          apiMethodsTested: 30,
          ffiBindingsTotal: 92,
          ffiBindingsExercised: 92,
          notes: '',
        ),
      );

      final jsonString = jsonEncode(report.toJson());
      final decoded = jsonDecode(jsonString) as Map<String, dynamic>;
      final restored = MetricsReport.fromJson(decoded);

      expect(restored.schemaVersion, '1.2.0');
      expect(restored.projectName, 'plugin_crypto');
      expect(restored.memory.baselineRssKb, 100);
      expect(restored.throughput.sha256Mbps, 554.2);
      expect(restored.security.entropyRandomBytes1024, 7.98);
      expect(restored.resource.totalTestsRun, 168);
      expect(restored.coverage.overallLineCoveragePct, 85.5);
      expect(restored.timing.histograms, isEmpty);
      expect(restored.timing.rawSamples, isEmpty);
      expect(restored.timing.categorySummaries, isEmpty);
      expect(restored.security.safeCurveChecklist, isEmpty);
    });
  });


  group('JSON round-trip: HistogramSnapshot', () {
    test('serializes and deserializes all 14 fields correctly', () {
      final original = HistogramSnapshot(
        operation: 'sha256',
        category: 'hash',
        inputSizeBytes: 1048576,
        sampleCount: 25,
        minMs: 1.82,
        p5Ms: 1.83,
        p25Ms: 1.86,
        medianMs: 1.89,
        p75Ms: 1.92,
        p95Ms: 1.97,
        p99Ms: 1.99,
        maxMs: 2.05,
        meanMs: 1.90,
        stddevMs: 0.045,
      );

      final json = original.toJson();
      final restored = HistogramSnapshot.fromJson(json);

      expect(restored.operation, original.operation);
      expect(restored.category, original.category);
      expect(restored.inputSizeBytes, original.inputSizeBytes);
      expect(restored.sampleCount, original.sampleCount);
      expect(restored.minMs, original.minMs);
      expect(restored.p5Ms, original.p5Ms);
      expect(restored.p25Ms, original.p25Ms);
      expect(restored.medianMs, original.medianMs);
      expect(restored.p75Ms, original.p75Ms);
      expect(restored.p95Ms, original.p95Ms);
      expect(restored.p99Ms, original.p99Ms);
      expect(restored.maxMs, original.maxMs);
      expect(restored.meanMs, original.meanMs);
      expect(restored.stddevMs, original.stddevMs);
    });
  });

  group('JSON round-trip: RawTimingSample', () {
    test('cold phase round-trips correctly', () {
      final original = RawTimingSample(
        operation: 'sha256',
        category: 'hash',
        inputSizeBytes: 1048576,
        phase: 'cold',
        sampleIndex: 0,
        elapsedMs: 2.31,
        isWarmup: false,
      );

      final json = original.toJson();
      final restored = RawTimingSample.fromJson(json);

      expect(restored.operation, original.operation);
      expect(restored.category, original.category);
      expect(restored.inputSizeBytes, original.inputSizeBytes);
      expect(restored.phase, 'cold');
      expect(restored.sampleIndex, 0);
      expect(restored.elapsedMs, original.elapsedMs);
      expect(restored.isWarmup, isFalse);
    });

    test('warm phase round-trips correctly', () {
      final original = RawTimingSample(
        operation: 'aes128CbcEncrypt',
        category: 'cipher',
        inputSizeBytes: 65536,
        phase: 'warm',
        sampleIndex: 42,
        elapsedMs: 0.124,
        isWarmup: false,
      );

      final json = original.toJson();
      final restored = RawTimingSample.fromJson(json);

      expect(restored.operation, original.operation);
      expect(restored.phase, 'warm');
      expect(restored.sampleIndex, 42);
      expect(restored.elapsedMs, original.elapsedMs);
      expect(restored.isWarmup, isFalse);
    });

    test('isWarmup: true survives round-trip', () {
      final original = RawTimingSample(
        operation: 'sha256',
        category: 'hash',
        inputSizeBytes: 1024,
        phase: 'warm',
        sampleIndex: 0,
        elapsedMs: 1.0,
        isWarmup: true,
      );

      final json = original.toJson();
      final restored = RawTimingSample.fromJson(json);

      expect(restored.isWarmup, isTrue);
    });
  });

  group('JSON round-trip: CategorySummary', () {
    test('hash category round-trips correctly', () {
      final original = CategorySummary(
        category: 'hash',
        operationCount: 4,
        totalMeasurements: 100,
        totalWarmTimeMs: 7.56,
        totalColdTimeMs: 9.88,
        meanThroughputMbps: 478.5,
        maxThroughputMbps: 554.2,
        minThroughputMbps: 398.1,
        weightedThroughputMbps: 502.3,
      );

      final json = original.toJson();
      final restored = CategorySummary.fromJson(json);

      expect(restored.category, 'hash');
      expect(restored.operationCount, 4);
      expect(restored.totalMeasurements, 100);
      expect(restored.totalWarmTimeMs, 7.56);
      expect(restored.totalColdTimeMs, 9.88);
      expect(restored.meanThroughputMbps, 478.5);
      expect(restored.maxThroughputMbps, 554.2);
      expect(restored.minThroughputMbps, 398.1);
      expect(restored.weightedThroughputMbps, 502.3);
    });

    test('keygen category round-trips correctly', () {
      final original = CategorySummary(
        category: 'keygen',
        operationCount: 5,
        totalMeasurements: 31,
        totalWarmTimeMs: 1200.0,
        totalColdTimeMs: 3500.0,
        meanThroughputMbps: 0.0,
        maxThroughputMbps: 0.0,
        minThroughputMbps: 0.0,
        weightedThroughputMbps: 0.0,
      );

      final json = original.toJson();
      final restored = CategorySummary.fromJson(json);

      expect(restored.category, 'keygen');
      expect(restored.operationCount, 5);
      expect(restored.weightedThroughputMbps, 0.0);
    });
  });

  group('JSON round-trip: SafeCurveChecklist', () {
    test('P-256 checklist round-trips correctly', () {
      final original = SafeCurveChecklist(
        curveName: 'prime256v1',
        fieldSizeBits: 256,
        hasPrimeOrder: true,
        cofactorIsOne: true,
        embeddingDegree: 192,
        embeddingDegreeSafe: true,
        twistSecure: true,
        twistOrderChecked: false,
        notes: 'NIST P-256 verified.',
      );

      final json = original.toJson();
      final restored = SafeCurveChecklist.fromJson(json);

      expect(restored.curveName, 'prime256v1');
      expect(restored.fieldSizeBits, 256);
      expect(restored.hasPrimeOrder, isTrue);
      expect(restored.cofactorIsOne, isTrue);
      expect(restored.embeddingDegree, 192);
      expect(restored.embeddingDegreeSafe, isTrue);
      expect(restored.twistSecure, isTrue);
      expect(restored.twistOrderChecked, isFalse);
      expect(restored.notes, 'NIST P-256 verified.');
    });

    test('P-384 checklist round-trips correctly', () {
      final original = SafeCurveChecklist(
        curveName: 'secp384r1',
        fieldSizeBits: 384,
        hasPrimeOrder: true,
        cofactorIsOne: true,
        embeddingDegree: 192,
        embeddingDegreeSafe: true,
        twistSecure: true,
        twistOrderChecked: false,
        notes: 'NIST P-384 verified.',
      );

      final json = original.toJson();
      final restored = SafeCurveChecklist.fromJson(json);

      expect(restored.curveName, 'secp384r1');
      expect(restored.fieldSizeBits, 384);
    });

    test('P-521 checklist round-trips correctly', () {
      final original = SafeCurveChecklist(
        curveName: 'secp521r1',
        fieldSizeBits: 521,
        hasPrimeOrder: true,
        cofactorIsOne: true,
        embeddingDegree: 192,
        embeddingDegreeSafe: true,
        twistSecure: true,
        twistOrderChecked: false,
        notes: 'NIST P-521 verified.',
      );

      final json = original.toJson();
      final restored = SafeCurveChecklist.fromJson(json);

      expect(restored.curveName, 'secp521r1');
      expect(restored.fieldSizeBits, 521);
    });
  });

  test('MetricsReport v1.0.0 backward compatibility', () {
    const v1JsonString =
        '{"schema_version":"1.0.0","generated_at":"2025-01-01T00:00:00Z",'
        '"project_name":"plugin_crypto",'
        '"timing":{"operations":[],"crypto_api_load_ms":0,"total_benchmark_time_ms":0},'
        '"memory":{"baseline_rss_kb":0,"after_api_load_rss_kb":0,"peak_rss_kb":0,'
        '"after_stress_rss_kb":0,"final_rss_kb":0,"rss_delta_kb":0,"leak_detected":false,'
        '"per_operation_allocations":{},"notes":""},'
        '"throughput":{"sha256_mbps":0,"sha384_mbps":0,"sha512_mbps":0,'
        '"sha3_256_mbps":0,"sha3_512_mbps":0,"aes128_cbc_encrypt_mbps":0,'
        '"aes128_cbc_decrypt_mbps":0,"aes256_cbc_encrypt_mbps":0,'
        '"aes256_cbc_decrypt_mbps":0,"aes128_gcm_encrypt_mbps":0,'
        '"aes128_gcm_decrypt_mbps":0,"aes256_gcm_encrypt_mbps":0,'
        '"aes256_gcm_decrypt_mbps":0,"rsa_2048_keygen_ops_per_min":0,'
        '"rsa_4096_keygen_ops_per_min":0,"ec_prime256v1_keygen_ops_per_min":0,'
        '"ec_secp384r1_keygen_ops_per_min":0,"ec_secp521r1_keygen_ops_per_min":0,'
        '"rsa_sign_per_sec":0,"rsa_verify_per_sec":0,"ec_sign_per_sec":0,'
        '"ec_verify_per_sec":0,"total_bytes_processed":0},'
        '"security":{"entropy_random_bytes_1024":0,"entropy_passed":false,'
        '"chi_squared":0,"chi_squared_p_value":0,"chi_squared_passed":false,'
        '"rsa_key_uniqueness_rate":0,"ec_key_uniqueness_rate":0,'
        '"signature_nondeterminism_rsa":false,"signature_nondeterminism_ecdsa":false,'
        '"iv_uniqueness_rate":0,"gcm_tag_auth_enforced":false,'
        '"gcm_aad_binding_enforced":false,"cross_key_rejection":false,"summary":""},'
        '"resource":{"total_suite_time_ms":0,"per_zone_duration_ms":{},'
        '"slowest_tests":[],"fastest_tests":[],"total_tests_run":0,'
        '"total_tests_passed":0,"total_tests_failed":0,"total_tests_skipped":0,'
        '"native_load_time_ms":0,"open_ssl_version":"","dart_version":"",'
        '"platform_os":"","processor_count":0,"ld_library_path":""},'
        '"coverage":{"coverage_available":false,"overall_line_coverage_pct":0,'
        '"per_file":[],"files_above_80pct":0,"files_below_50pct":0,'
        '"api_methods_total":0,"api_methods_tested":0,"ffi_bindings_total":0,'
        '"ffi_bindings_exercised":0,"notes":""}}';

    final decoded = jsonDecode(v1JsonString) as Map<String, dynamic>;
    final report = MetricsReport.fromJson(decoded);

    expect(report.timing.histograms, isEmpty);
    expect(report.timing.rawSamples, isEmpty);
    expect(report.timing.categorySummaries, isEmpty);
    expect(report.security.safeCurveChecklist, isEmpty);

    expect(report.schemaVersion, '1.0.0');
    expect(report.projectName, 'plugin_crypto');
  });

  test('MetricsReport JSON round-trip', () {
    final original = MetricsReport(
      schemaVersion: '1.0.0',
      generatedAt: '2025-01-01T00:00:00Z',
      projectName: 'plugin_crypto',
      timing: TimingMetrics(
        operations: [],
        cryptoApiLoadMs: 0,
        totalBenchmarkTimeMs: 0,
      ),
      memory: MemoryMetrics(
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
      throughput: ThroughputMetrics(
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
      security: SecurityMetrics(
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
      resource: ResourceMetrics(
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
      coverage: CoverageMetrics(
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

    final jsonString = jsonEncode(original.toJson());
    final decoded = jsonDecode(jsonString) as Map<String, dynamic>;
    final restored = MetricsReport.fromJson(decoded);

    expect(restored.schemaVersion, equals(original.schemaVersion));
    expect(restored.generatedAt, equals(original.generatedAt));
    expect(restored.projectName, equals(original.projectName));
  });
}
