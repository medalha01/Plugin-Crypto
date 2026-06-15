@TestOn('linux')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/key_creator_factory.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_kem_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_dsa_key_creator.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/timing.dart';
import 'package:plugin_crypto/src/metrics/memory_tracker.dart';
import 'package:plugin_crypto/src/metrics/security_metrics.dart';

import 'fixtures/helpers.dart' as helpers;
import 'fixtures/pq_key_creation_fixtures.dart' as pqFixtures;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();
  final bench = CryptoMicroBenchmark();
  final benchDiag = CryptoMicroBenchmark(
    collectPerIterationStats: true,
    collectRawSamples: true,
  );
  final memoryTracker = MemoryTracker();

  late OpenSslBindings bindings;
  late MlKemKeyCreator mlKemCreator;
  late MlDsaKeyCreator mlDsaCreator;
  late KeyCreatorFactory factory;

  setUpAll(() {
    memoryTracker.sampleBytes('pq_baseline');
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    mlKemCreator = MlKemKeyCreator(bindings);
    mlDsaCreator = MlDsaKeyCreator(bindings);
    factory = KeyCreatorFactory(bindings);
    api.sha256(Uint8List(0));
    memoryTracker.sampleBytes('pq_api_init');
  });

  setUp(() {
    _collector.recordTestResult('benchmark_pq', 'start', 0);
  });

  tearDown(() {
    _collector.recordTestResult('benchmark_pq', 'passed', 0);
  });

  group('ML-KEM keygen benchmarks', () {
    void benchMlKemKeygen(String variant, MlKemKeySpec spec) {
      final opName = 'generateMlKemKeyPair_$variant';
      final cold = bench.measureCold(
        '${opName}_cold',
        () => mlKemCreator.create(spec),
      );
      for (var i = 0; i < 3; i++) {
        mlKemCreator.create(spec);
      }
      final warmTotal = <double>[];
      const iterations = 5;
      for (var i = 0; i < iterations; i++) {
        final sw = Stopwatch()..start();
        mlKemCreator.create(spec);
        sw.stop();
        warmTotal.add(sw.elapsedMicroseconds / 1000.0);
      }
      final avgWarmMs =
          warmTotal.reduce((a, b) => a + b) / warmTotal.length;
      final record = OperationTiming(
        operation: opName,
        category: 'keygen_pq',
        inputSizeBytes: 0,
        coldMs: cold.elapsedMs,
        warmMs: avgWarmMs,
        throughputMbps: 0,
        iterationsWarm: iterations,
      );
      _collector.recordOperationTiming(record);
      expect(avgWarmMs, greaterThan(0));
    }

    test('generateMlKemKeyPair mlKem512', () {
      benchMlKemKeygen('mlKem512', pqFixtures.validMlKem512Spec);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('generateMlKemKeyPair mlKem768', () {
      benchMlKemKeygen('mlKem768', pqFixtures.validMlKem768Spec);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('generateMlKemKeyPair mlKem1024', () {
      benchMlKemKeygen('mlKem1024', pqFixtures.validMlKem1024Spec);
    }, timeout: const Timeout(Duration(minutes: 3)));
  });

  memoryTracker.sampleBytes('after_mlkem_keygen');

  group('ML-DSA keygen benchmarks', () {
    void benchMlDsaKeygen(String variant, MlDsaKeySpec spec) {
      final opName = 'generateMlDsaKeyPair_$variant';
      final cold = bench.measureCold(
        '${opName}_cold',
        () => mlDsaCreator.create(spec),
      );
      for (var i = 0; i < 3; i++) {
        mlDsaCreator.create(spec);
      }
      final warmTotal = <double>[];
      const iterations = 5;
      for (var i = 0; i < iterations; i++) {
        final sw = Stopwatch()..start();
        mlDsaCreator.create(spec);
        sw.stop();
        warmTotal.add(sw.elapsedMicroseconds / 1000.0);
      }
      final avgWarmMs =
          warmTotal.reduce((a, b) => a + b) / warmTotal.length;
      final record = OperationTiming(
        operation: opName,
        category: 'keygen_pq',
        inputSizeBytes: 0,
        coldMs: cold.elapsedMs,
        warmMs: avgWarmMs,
        throughputMbps: 0,
        iterationsWarm: iterations,
      );
      _collector.recordOperationTiming(record);
      expect(avgWarmMs, greaterThan(0));
    }

    test('generateMlDsaKeyPair mlDsa44', () {
      benchMlDsaKeygen('mlDsa44', pqFixtures.validMlDsa44Spec);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('generateMlDsaKeyPair mlDsa65', () {
      benchMlDsaKeygen('mlDsa65', pqFixtures.validMlDsa65Spec);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('generateMlDsaKeyPair mlDsa87', () {
      benchMlDsaKeygen('mlDsa87', pqFixtures.validMlDsa87Spec);
    }, timeout: const Timeout(Duration(minutes: 3)));
  });

  memoryTracker.sampleBytes('after_mldsa_keygen');

  group('ML-KEM encaps/decaps benchmarks', () {
    void benchMlKemEncapsDecaps(String variant, MlKemKeySpec spec) {
      final result = mlKemCreator.create(spec);
      if (result is! CryptoSuccess<KeyPair>) {
        fail('Failed to create ML-KEM $variant key: $result');
      }
      final kp = result.value;
      final pubPem = helpers.pem(kp.publicKeyPem);
      final privPem = helpers.pem(kp.privateKeyPem);

      {
        final opName = 'mlKemEncapsulate_$variant';
        final cold = bench.measureCold(
          '${opName}_cold',
          () => api.mlKemEncapsulate(pubPem),
        );
        final warm = bench.measureWarm(
          '${opName}_warm',
          () => api.mlKemEncapsulate(pubPem),
          dataSizeBytes: 0,
          iterations: 50,
        );
        final record = bench.toOperationTiming(opName, 'kem', cold, warm);
        _collector.recordOperationTiming(record);
      }

      {
        final opName = 'mlKemDecapsulate_$variant';
        final capsule = api.mlKemEncapsulate(pubPem);
        final cold = bench.measureCold(
          '${opName}_cold',
          () => api.mlKemDecapsulate(privPem, capsule.ciphertext),
        );
        final warm = bench.measureWarm(
          '${opName}_warm',
          () => api.mlKemDecapsulate(privPem, capsule.ciphertext),
          dataSizeBytes: capsule.ciphertext.length,
          iterations: 50,
        );
        final record = bench.toOperationTiming(opName, 'kem', cold, warm);
        _collector.recordOperationTiming(record);
      }
    }

    test('mlKemEncaps + mlKemDecaps mlKem512', () {
      benchMlKemEncapsDecaps('mlKem512', pqFixtures.validMlKem512Spec);
    });

    test('mlKemEncaps + mlKemDecaps mlKem768', () {
      benchMlKemEncapsDecaps('mlKem768', pqFixtures.validMlKem768Spec);
    });

    test('mlKemEncaps + mlKemDecaps mlKem1024', () {
      benchMlKemEncapsDecaps('mlKem1024', pqFixtures.validMlKem1024Spec);
    });

    test('mlKem round-trip shared secret correctness mlKem768', () {
      final result = mlKemCreator.create(pqFixtures.validMlKem768Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);
      final privPem = helpers.pem(kp.privateKeyPem);

      for (var i = 0; i < 20; i++) {
        final capsule = api.mlKemEncapsulate(pubPem);
        final recovered = api.mlKemDecapsulate(privPem, capsule.ciphertext);
        expect(recovered, equals(capsule.sharedSecret),
            reason: 'ML-KEM-768 round-trip $i: shared secret mismatch');
        expect(capsule.ciphertext, isNotEmpty);
        expect(capsule.sharedSecret, isNotEmpty);
      }
    });
  });

  memoryTracker.sampleBytes('after_mlkem_ops');

  group('ML-DSA sign/verify benchmarks', () {
    void benchMlDsaSignVerify(String variant, MlDsaKeySpec spec) {
      final result = mlDsaCreator.create(spec);
      if (result is! CryptoSuccess<KeyPair>) {
        fail('Failed to create ML-DSA $variant key: $result');
      }
      final kp = result.value;
      final pubPem = helpers.pem(kp.publicKeyPem);
      final privPem = helpers.pem(kp.privateKeyPem);
      final message = api.randomBytes(32);

      {
        final opName = 'mlDsaSign_$variant';
        final cold = bench.measureCold(
          '${opName}_cold',
          () => api.sign(message, privPem),
        );
        api.sign(message, privPem);
        final warm = bench.measureWarm(
          '${opName}_warm',
          () => api.sign(message, privPem),
          dataSizeBytes: message.length,
          iterations: 50,
        );
        final record =
            bench.toOperationTiming(opName, 'sign_pq', cold, warm);
        _collector.recordOperationTiming(record);
      }

      {
        final opName = 'mlDsaVerify_$variant';
        final signature = api.sign(message, privPem);
        final cold = bench.measureCold(
          '${opName}_cold',
          () => api.verify(message, pubPem, signature),
        );
        api.verify(message, pubPem, signature);
        final warm = bench.measureWarm(
          '${opName}_warm',
          () => api.verify(message, pubPem, signature),
          dataSizeBytes: message.length,
          iterations: 50,
        );
        final record =
            bench.toOperationTiming(opName, 'verify_pq', cold, warm);
        _collector.recordOperationTiming(record);
      }
    }

    test('mlDsaSign + mlDsaVerify mlDsa44', () {
      benchMlDsaSignVerify('mlDsa44', pqFixtures.validMlDsa44Spec);
    });

    test('mlDsaSign + mlDsaVerify mlDsa65', () {
      benchMlDsaSignVerify('mlDsa65', pqFixtures.validMlDsa65Spec);
    });

    test('mlDsaSign + mlDsaVerify mlDsa87', () {
      benchMlDsaSignVerify('mlDsa87', pqFixtures.validMlDsa87Spec);
    });

    test('ML-DSA sign/verify round-trip (20 iterations mlDsa44)', () {
      final result = mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);
      final privPem = helpers.pem(kp.privateKeyPem);

      for (var i = 0; i < 20; i++) {
        final message = api.randomBytes(64);
        final signature = api.sign(message, privPem);
        final verified = api.verify(message, pubPem, signature);
        expect(verified, isTrue,
            reason: 'ML-DSA-44 round-trip failed at iteration $i');
        expect(signature, isNotEmpty);
      }
    });
  });

  memoryTracker.sampleBytes('after_mldsa_ops');

  group('PQ Histogram & Raw Samples', () {
    test('mlKemEncaps mlKem768 — histogram distribution', () {
      final result = mlKemCreator.create(pqFixtures.validMlKem768Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);

      final warm = benchDiag.measureWarm(
        'mlKemEncaps_mlKem768_diag',
        () => api.mlKemEncapsulate(pubPem),
        dataSizeBytes: 0,
        iterations: 100,
        category: 'kem',
      );
      final histogram = benchDiag.computeHistogram(
        operation: 'mlKemEncapsulate',
        category: 'kem',
        warm: warm,
        perIterationTimes: warm.iterationTimesMs,
      );
      _collector.recordHistogram(histogram);

      expect(histogram.sampleCount, greaterThan(0));
      expect(histogram.minMs, lessThanOrEqualTo(histogram.p25Ms));
      expect(histogram.p25Ms, lessThanOrEqualTo(histogram.medianMs));
      expect(histogram.medianMs, lessThanOrEqualTo(histogram.p75Ms));
      expect(histogram.p75Ms, lessThanOrEqualTo(histogram.maxMs));
      expect(histogram.minMs, lessThanOrEqualTo(histogram.p5Ms));
      expect(histogram.p5Ms, lessThanOrEqualTo(histogram.p95Ms));
      expect(histogram.p95Ms, lessThanOrEqualTo(histogram.p99Ms));
      expect(histogram.p99Ms, lessThanOrEqualTo(histogram.maxMs));
      expect(histogram.meanMs, greaterThanOrEqualTo(histogram.minMs));
      expect(histogram.meanMs, lessThanOrEqualTo(histogram.maxMs));
      expect(histogram.stddevMs, greaterThanOrEqualTo(0));
    });

    test('mlDsaSign mlDsa44 — histogram distribution', () {
      final result = mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final privPem = helpers.pem(kp.privateKeyPem);
      final message = api.randomBytes(32);

      final warm = benchDiag.measureWarm(
        'mlDsaSign_mlDsa44_diag',
        () => api.sign(message, privPem),
        dataSizeBytes: message.length,
        iterations: 100,
        category: 'sign_pq',
      );
      final histogram = benchDiag.computeHistogram(
        operation: 'mlDsaSign',
        category: 'sign_pq',
        warm: warm,
        perIterationTimes: warm.iterationTimesMs,
      );
      _collector.recordHistogram(histogram);

      expect(histogram.sampleCount, greaterThan(0));
      expect(histogram.minMs, lessThanOrEqualTo(histogram.p25Ms));
      expect(histogram.p25Ms, lessThanOrEqualTo(histogram.medianMs));
      expect(histogram.medianMs, lessThanOrEqualTo(histogram.p75Ms));
      expect(histogram.meanMs, greaterThanOrEqualTo(histogram.minMs));
      expect(histogram.stddevMs, greaterThanOrEqualTo(0));
    });

    test('mlDsaVerify mlDsa44 — raw samples present', () {
      final result = mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);
      final privPem = helpers.pem(kp.privateKeyPem);
      final message = api.randomBytes(32);
      final signature = api.sign(message, privPem);

      benchDiag.measureWarm(
        'mlDsaVerify_mlDsa44_diag',
        () => api.verify(message, pubPem, signature),
        dataSizeBytes: message.length,
        iterations: 50,
        category: 'verify_pq',
      );

      final verifySamples = benchDiag.rawSamples
          .where((s) =>
              s.operation == 'mlDsaVerify_mlDsa44_diag' &&
              s.phase == 'warm')
          .toList();
      expect(verifySamples, isNotEmpty);
      expect(verifySamples.every((s) => s.elapsedMs > 0), isTrue);
    });
  });

  group('PQ security validation', () {
    test('ML-KEM key uniqueness (100 keys, mlKem768)', () {
      final pubKeys = <Uint8List>[];
      for (var i = 0; i < 100; i++) {
        final result = mlKemCreator.create(pqFixtures.validMlKem768Spec);
        final kp = (result as CryptoSuccess<KeyPair>).value;
        pubKeys.add(helpers.pem(kp.publicKeyPem));
      }
      final uniqueness = checkUniqueness(pubKeys);
      _collector.recordSecurityCheck(
        'mlkem_key_uniqueness',
        uniqueness == 1.0,
        {'uniqueness_rate': uniqueness, 'iterations': 100, 'variant': 'mlKem768'},
      );
      expect(uniqueness, equals(1.0),
          reason: 'All 100 ML-KEM-768 keys must be unique');
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('ML-DSA key uniqueness (100 keys, mlDsa44)', () {
      final pubKeys = <Uint8List>[];
      for (var i = 0; i < 100; i++) {
        final result = mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
        final kp = (result as CryptoSuccess<KeyPair>).value;
        pubKeys.add(helpers.pem(kp.publicKeyPem));
      }
      final uniqueness = checkUniqueness(pubKeys);
      _collector.recordSecurityCheck(
        'mldsa_key_uniqueness',
        uniqueness == 1.0,
        {'uniqueness_rate': uniqueness, 'iterations': 100, 'variant': 'mlDsa44'},
      );
      expect(uniqueness, equals(1.0),
          reason: 'All 100 ML-DSA-44 keys must be unique');
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('ML-DSA signature non-determinism (FIPS 204)', () {
      final result = mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final privPem = helpers.pem(kp.privateKeyPem);
      final pubPem = helpers.pem(kp.publicKeyPem);
      final message = api.randomBytes(32);

      final sig1 = api.sign(message, privPem);
      final sig2 = api.sign(message, privPem);

      expect(api.verify(message, pubPem, sig1), isTrue);
      expect(api.verify(message, pubPem, sig2), isTrue);

      final bothVerify = api.verify(message, pubPem, sig1) &&
          api.verify(message, pubPem, sig2);
      final areDifferent =
          sig1.length != sig2.length || !_listEqual(sig1, sig2);
      _collector.recordSecurityCheck(
        'mldsa_signature_nondeterminism',
        bothVerify && areDifferent,
        {
          'both_verify': bothVerify,
          'signatures_differ': areDifferent,
          'sig_len': sig1.length,
          'standard': 'FIPS 204',
        },
      );
      expect(bothVerify, isTrue,
          reason: 'Both ML-DSA-44 signatures must verify with the same public key');
      expect(areDifferent, isTrue,
          reason: 'ML-DSA-44 signatures must be non-deterministic (FIPS 204 hedged mode)');
    });

    test('ML-KEM shared secret independence', () {
      final result = mlKemCreator.create(pqFixtures.validMlKem768Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);

      final secrets = <Uint8List>[];
      for (var i = 0; i < 50; i++) {
        final capsule = api.mlKemEncapsulate(pubPem);
        secrets.add(capsule.sharedSecret);
      }
      final uniqueness = checkUniqueness(secrets);
      _collector.recordSecurityCheck(
        'mlkem_shared_secret_independence',
        uniqueness == 1.0,
        {
          'uniqueness_rate': uniqueness,
          'iterations': 50,
          'variant': 'mlKem768',
        },
      );
      expect(uniqueness, equals(1.0),
          reason: 'All 50 ML-KEM shared secrets must be unique');
    });

    test('ML-KEM ciphertext independence', () {
      final result = mlKemCreator.create(pqFixtures.validMlKem768Spec);
      final kp = (result as CryptoSuccess<KeyPair>).value;
      final pubPem = helpers.pem(kp.publicKeyPem);

      final ciphertexts = <Uint8List>[];
      for (var i = 0; i < 50; i++) {
        final capsule = api.mlKemEncapsulate(pubPem);
        ciphertexts.add(capsule.ciphertext);
      }
      final uniqueness = checkUniqueness(ciphertexts);
      _collector.recordSecurityCheck(
        'mlkem_ciphertext_independence',
        uniqueness == 1.0,
        {
          'uniqueness_rate': uniqueness,
          'iterations': 50,
          'variant': 'mlKem768',
        },
      );
      expect(uniqueness, equals(1.0),
          reason: 'All 50 ML-KEM ciphertexts must be unique');
    });

    test('ML-KEM cross-key rejection', () {
      final kpA = (mlKemCreator.create(pqFixtures.validMlKem768Spec)
          as CryptoSuccess<KeyPair>)
          .value;
      final kpB = (mlKemCreator.create(pqFixtures.validMlKem768Spec)
          as CryptoSuccess<KeyPair>)
          .value;

      final pubA = helpers.pem(kpA.publicKeyPem);
      final privA = helpers.pem(kpA.privateKeyPem);
      final privB = helpers.pem(kpB.privateKeyPem);

      final capsule = api.mlKemEncapsulate(pubA);
      final secretA = api.mlKemDecapsulate(privA, capsule.ciphertext);
      final secretB = api.mlKemDecapsulate(privB, capsule.ciphertext);

      final rejected = !_listEqual(secretA, secretB);
      _collector.recordSecurityCheck('mlkem_cross_key_rejection', rejected, {
        'secret_a_len': secretA.length,
        'secret_b_len': secretB.length,
        'variant': 'mlKem768',
      });
      expect(rejected, isTrue,
          reason: 'Ciphertext for key A must not produce same shared secret with key B');
    });

    test('ML-DSA cross-key signature rejection', () {
      final kpA = (mlDsaCreator.create(pqFixtures.validMlDsa44Spec)
          as CryptoSuccess<KeyPair>)
          .value;
      final kpB = (mlDsaCreator.create(pqFixtures.validMlDsa44Spec)
          as CryptoSuccess<KeyPair>)
          .value;

      final privA = helpers.pem(kpA.privateKeyPem);
      final pubB = helpers.pem(kpB.publicKeyPem);
      final message = api.randomBytes(32);

      final signature = api.sign(message, privA);
      final verifiedWithB = api.verify(message, pubB, signature);

      _collector.recordSecurityCheck(
        'mldsa_cross_key_rejection',
        !verifiedWithB,
        {'verified_with_wrong_key': verifiedWithB, 'variant': 'mlDsa44'},
      );
      expect(verifiedWithB, isFalse,
          reason: 'ML-DSA signature from key A must not verify with key B');
    });

    test('PQ cross-algorithm rejection (ML-KEM vs ML-DSA)', () {
      final kemResult =
          mlKemCreator.create(pqFixtures.validMlKem768Spec);
      final kemKp = (kemResult as CryptoSuccess<KeyPair>).value;
      final dsaResult =
          mlDsaCreator.create(pqFixtures.validMlDsa44Spec);
      final dsaKp = (dsaResult as CryptoSuccess<KeyPair>).value;

      final kemCapsule =
          api.mlKemEncapsulate(helpers.pem(kemKp.publicKeyPem));
      final dsaPub = helpers.pem(dsaKp.publicKeyPem);

      bool crossRejected;
      try {
        final wrong = api.verify(
          kemCapsule.ciphertext,
          dsaPub,
          kemCapsule.ciphertext,
        );
        crossRejected = !wrong;
      } catch (_) {
        crossRejected = true;
      }
      _collector.recordSecurityCheck(
        'pq_cross_algorithm_rejection',
        crossRejected,
        {'kem_variant': 'mlKem768', 'dsa_variant': 'mlDsa44'},
      );
      expect(crossRejected, isTrue,
          reason: 'ML-KEM ciphertext must be rejected by ML-DSA verify');
    });
  });

  memoryTracker.sampleBytes('after_pq_security');

  group('Memory sampling', () {
    test('record after_pq_stress memory sample', () {
      memoryTracker.sampleBytes('after_pq_stress');
    });

    test('record pq_final memory sample', () {
      memoryTracker.sampleBytes('pq_final');
    });
  });

  group('KeyCreatorFactory PQ dispatch', () {
    test('factory dispatches MlKemKeyCreator for all ML-KEM variants', () {
      for (final spec in pqFixtures.allValidMlKemSpecs) {
        final creator = factory.create(spec);
        expect(creator, isA<MlKemKeyCreator>(),
            reason: 'Factory must dispatch MlKemKeyCreator for $spec');
        final result = creator!.create(spec);
        expect(result, isA<CryptoSuccess<KeyPair>>(),
            reason: 'MlKemKeyCreator from factory must create valid key for $spec');
      }
    });

    test('factory dispatches MlDsaKeyCreator for all ML-DSA variants', () {
      for (final spec in pqFixtures.allValidMlDsaSpecs) {
        final creator = factory.create(spec);
        expect(creator, isA<MlDsaKeyCreator>(),
            reason: 'Factory must dispatch MlDsaKeyCreator for $spec');
        final result = creator!.create(spec);
        expect(result, isA<CryptoSuccess<KeyPair>>(),
            reason: 'MlDsaKeyCreator from factory must create valid key for $spec');
      }
    });
  });

  tearDownAll(() async {
    final metricsOutput = Platform.environment['TCC_METRICS_OUTPUT'];
    if (metricsOutput == null || metricsOutput.isEmpty) return;

    final timings = _collector.operationTimings;
    _collector.computeCategorySummaries();
    final histograms = _collector.histograms;
    final rawSamples = _collector.rawSamples;

    final Map<String, dynamic> json = {
      'schema_version': 'pq_1.0.0',
      'generated_at': DateTime.now().toUtc().toIso8601String(),
      'platform': 'linux_x86_64',
      'timing': {
        'operations': timings
            .where((t) =>
                t.category == 'keygen_pq' ||
                t.category == 'kem' ||
                t.category == 'sign_pq' ||
                t.category == 'verify_pq')
            .map((t) => t.toJson())
            .toList(),
        'total_benchmark_time_ms': _collector.suiteElapsedMs,
        'histograms': histograms.map((h) => h.toJson()).toList(),
        'raw_samples': rawSamples.map((r) => r.toJson()).toList(),
        'category_summaries': _collector.categorySummaries
            .where((c) =>
                c.category == 'keygen_pq' ||
                c.category == 'kem' ||
                c.category == 'sign_pq' ||
                c.category == 'verify_pq')
            .map((c) => c.toJson())
            .toList(),
      },
      'security_checks': {
        for (final entry in _collector.securityChecks.entries)
          entry.key: {
            'passed': entry.value.passed,
            'evidence': entry.value.evidence,
          },
      },
      'memory_samples': {
        for (final entry in memoryTracker.samples.entries)
          entry.key: entry.value,
      },
      'test_results': {
        'total': _collector.totalTestsRun,
        'passed': _collector.totalTestsPassed,
        'failed': _collector.totalTestsFailed,
      },
    };

    final encoder = JsonEncoder.withIndent('  ');
    try {
      final pqPath = metricsOutput.replaceAll('.json', '_pq.json');
      await File(pqPath).writeAsString(encoder.convert(json));
      stderr.writeln('[metrics_pq] PQ metrics report written to $pqPath');
    } catch (e) {
      stderr.writeln('[metrics_pq] Report write failed: $e');
    }
  });
}

bool _listEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
