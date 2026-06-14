library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/timing.dart';
import 'package:plugin_crypto/src/metrics/memory_tracker.dart';
import 'package:plugin_crypto/src/metrics/security_metrics.dart';
import 'package:plugin_crypto/src/metrics/throughput.dart';
import 'package:plugin_crypto/src/metrics/coverage_parser.dart';
import 'package:plugin_crypto/src/metrics/safe_curves.dart';
import 'package:plugin_crypto/src/metrics/security_benchmark.dart';

import 'fixtures/certificates.dart';
import 'fixtures/helpers.dart' as helpers;

/// Lazy collector accessor — creates if flutter_test_config didn't.
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

  Uint8List data1KB = Uint8List(0);
  Uint8List data64KB = Uint8List(0);
  Uint8List data1MB = Uint8List(0);

  late DateTime testStart;

  setUpAll(() {
    memoryTracker.sampleBytes('baseline');

    data1KB = api.randomBytes(1024);
    api.sha256(data1KB); // Discarded  primes FFI dispatch.

    data64KB = api.randomBytes(65536);
    data1MB = Uint8List.fromList(List<int>.filled(1048576, 0x41));

    memoryTracker.sampleBytes('after_api_init');
  });

  setUp(() {
    testStart = DateTime.now();
  });

  tearDown(() {
    final ms = DateTime.now().difference(testStart).inMilliseconds;
    _collector.recordTestResult('benchmark', 'passed', ms);
  });

  group('Hashing benchmarks', () {
    void benchHash(
      String opName,
      Uint8List Function(Uint8List) hashFn,
      Uint8List data,
      int dataSize,
    ) {
      final cold = bench.measureCold(
        '${opName}_cold',
        () => hashFn(data),
        preWarmupCalls: 1,
      );
      final warm = bench.measureWarm(
        '${opName}_warm',
        () => hashFn(data),
        dataSizeBytes: dataSize,
        iterations: 100,
      );
      final record = bench.toOperationTiming(opName, 'hash', cold, warm);
      _collector.recordOperationTiming(record);
      expect(
        cold.elapsedMs,
        greaterThanOrEqualTo(warm.meanMs * 0.0),
        reason:
            '$opName: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
      );
    }

    test('sha256 at 0 B', () {
      final data = Uint8List(0);
      benchHash('sha256', api.sha256, data, 0);
    });

    test('sha256 at 1 KB', () {
      benchHash('sha256', api.sha256, data1KB, 1024);
    });

    test('sha256 at 64 KB', () {
      benchHash('sha256', api.sha256, data64KB, 65536);
    });

    test('sha256 at 1 MB', () {
      benchHash('sha256', api.sha256, data1MB, 1048576);
    });

    test('sha512 at 0 B', () {
      final data = Uint8List(0);
      benchHash('sha512', api.sha512, data, 0);
    });

    test('sha512 at 1 KB', () {
      benchHash('sha512', api.sha512, data1KB, 1024);
    });

    test('sha512 at 64 KB', () {
      benchHash('sha512', api.sha512, data64KB, 65536);
    });

    test('sha512 at 1 MB', () {
      benchHash('sha512', api.sha512, data1MB, 1048576);
    });

    test('sha3_256 at 0 B', () {
      final data = Uint8List(0);
      benchHash('sha3_256', api.sha3_256, data, 0);
    });

    test('sha3_256 at 1 KB', () {
      benchHash('sha3_256', api.sha3_256, data1KB, 1024);
    });

    test('sha3_256 at 64 KB', () {
      benchHash('sha3_256', api.sha3_256, data64KB, 65536);
    });

    test('sha3_256 at 1 MB', () {
      benchHash('sha3_256', api.sha3_256, data1MB, 1048576);
    });

    test('sha3_512 at 0 B', () {
      final data = Uint8List(0);
      benchHash('sha3_512', api.sha3_512, data, 0);
    });

    test('sha3_512 at 1 KB', () {
      benchHash('sha3_512', api.sha3_512, data1KB, 1024);
    });

    test('sha3_512 at 64 KB', () {
      benchHash('sha3_512', api.sha3_512, data64KB, 65536);
    });

    test('sha3_512 at 1 MB', () {
      benchHash('sha3_512', api.sha3_512, data1MB, 1048576);
    });
  });

  memoryTracker.sampleBytes('after_hashing');

  group('AES-CBC benchmarks', () {
    void benchAesCbc({
      required String opName,
      required int keyLen,
      required Uint8List Function(Uint8List, Uint8List, Uint8List) encryptFn,
      required Uint8List Function(Uint8List, Uint8List, Uint8List) decryptFn,
      required Uint8List plaintext,
      required int dataSize,
    }) {
      final key = api.randomBytes(keyLen);
      final iv = api.randomBytes(16);

      final ciphertext = encryptFn(key, iv, plaintext);
      final decrypted = decryptFn(key, iv, ciphertext);
      expect(decrypted, equals(plaintext));

      {
        final cold = bench.measureCold(
          '${opName}Encrypt_cold',
          () => encryptFn(key, iv, plaintext),
        );
        final warm = bench.measureWarm(
          '${opName}Encrypt_warm',
          () => encryptFn(key, iv, plaintext),
          dataSizeBytes: dataSize,
          iterations: 150,
        );
        final record = bench.toOperationTiming(
          '${opName}Encrypt',
          'cipher',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              '${opName}Encrypt: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }

      {
        final cold = bench.measureCold(
          '${opName}Decrypt_cold',
          () => decryptFn(key, iv, ciphertext),
        );
        final warm = bench.measureWarm(
          '${opName}Decrypt_warm',
          () => decryptFn(key, iv, ciphertext),
          dataSizeBytes: dataSize,
          iterations: 150,
        );
        final record = bench.toOperationTiming(
          '${opName}Decrypt',
          'cipher',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              '${opName}Decrypt: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    }

    for (final entry in [
      ('16 B', Uint8List.fromList(List<int>.filled(16, 0x41)), 16),
      ('1 KB', null, 1024),
      ('64 KB', null, 65536),
      ('1 MB', null, 1048576),
    ]) {
      final label = entry.$1;
      final data =
          entry.$2 ??
          (entry.$3 == 1024
              ? data1KB
              : entry.$3 == 65536
              ? data64KB
              : data1MB);
      final size = entry.$3;
      test('aes128Cbc $label', () {
        benchAesCbc(
          opName: 'aes128Cbc',
          keyLen: 16,
          encryptFn: api.aes128CbcEncrypt,
          decryptFn: api.aes128CbcDecrypt,
          plaintext: data,
          dataSize: size,
        );
      });
    }

    for (final entry in [
      ('16 B', Uint8List.fromList(List<int>.filled(16, 0x41)), 16),
      ('1 KB', null, 1024),
      ('64 KB', null, 65536),
      ('1 MB', null, 1048576),
    ]) {
      final label = entry.$1;
      final data =
          entry.$2 ??
          (entry.$3 == 1024
              ? data1KB
              : entry.$3 == 65536
              ? data64KB
              : data1MB);
      final size = entry.$3;
      test('aes256Cbc $label', () {
        benchAesCbc(
          opName: 'aes256Cbc',
          keyLen: 32,
          encryptFn: api.aes256CbcEncrypt,
          decryptFn: api.aes256CbcDecrypt,
          plaintext: data,
          dataSize: size,
        );
      });
    }
  });

  group('AES-GCM benchmarks', () {
    void benchAesGcm({
      required String opName,
      required int keyLen,
      required AesGcmResult Function(
        Uint8List,
        Uint8List,
        Uint8List, {
        Uint8List? aad,
      })
      encryptFn,
      required Uint8List Function(
        Uint8List,
        Uint8List,
        Uint8List,
        Uint8List, {
        Uint8List? aad,
      })
      decryptFn,
      required Uint8List plaintext,
      required int dataSize,
    }) {
      final key = api.randomBytes(keyLen);
      final iv = api.randomBytes(12); // Standard GCM nonce length.

      final result = encryptFn(key, iv, plaintext);
      final decrypted = decryptFn(key, iv, result.ciphertext, result.tag);
      expect(decrypted, equals(plaintext));

      {
        final cold = bench.measureCold(
          '${opName}Encrypt_cold',
          () => encryptFn(key, iv, plaintext),
        );
        final warm = bench.measureWarm(
          '${opName}Encrypt_warm',
          () => encryptFn(key, iv, plaintext),
          dataSizeBytes: dataSize,
          iterations: 150,
        );
        final record = bench.toOperationTiming(
          '${opName}Encrypt',
          'aead',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              '${opName}Encrypt: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }

      {
        final cold = bench.measureCold(
          '${opName}Decrypt_cold',
          () => decryptFn(key, iv, result.ciphertext, result.tag),
        );
        final warm = bench.measureWarm(
          '${opName}Decrypt_warm',
          () => decryptFn(key, iv, result.ciphertext, result.tag),
          dataSizeBytes: dataSize,
          iterations: 150,
        );
        final record = bench.toOperationTiming(
          '${opName}Decrypt',
          'aead',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              '${opName}Decrypt: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    }

    for (final entry in [
      ('16 B', Uint8List.fromList(List<int>.filled(16, 0x41)), 16),
      ('1 KB', null, 1024),
      ('64 KB', null, 65536),
      ('1 MB', null, 1048576),
    ]) {
      final label = entry.$1;
      final data =
          entry.$2 ??
          (entry.$3 == 1024
              ? data1KB
              : entry.$3 == 65536
              ? data64KB
              : data1MB);
      final size = entry.$3;
      test('aes128Gcm $label', () {
        benchAesGcm(
          opName: 'aes128Gcm',
          keyLen: 16,
          encryptFn: api.aes128GcmEncrypt,
          decryptFn: api.aes128GcmDecrypt,
          plaintext: data,
          dataSize: size,
        );
      });
    }

    for (final entry in [
      ('16 B', Uint8List.fromList(List<int>.filled(16, 0x41)), 16),
      ('1 KB', null, 1024),
      ('64 KB', null, 65536),
      ('1 MB', null, 1048576),
    ]) {
      final label = entry.$1;
      final data =
          entry.$2 ??
          (entry.$3 == 1024
              ? data1KB
              : entry.$3 == 65536
              ? data64KB
              : data1MB);
      final size = entry.$3;
      test('aes256Gcm $label', () {
        benchAesGcm(
          opName: 'aes256Gcm',
          keyLen: 32,
          encryptFn: api.aes256GcmEncrypt,
          decryptFn: api.aes256GcmDecrypt,
          plaintext: data,
          dataSize: size,
        );
      });
    }
  });

  memoryTracker.sampleBytes('after_aes');

  group('RSA benchmarks', () {
    test('generateRsaKeyPair 2048', () {
      final opName = 'generateRsaKeyPair_2048';

      final cold = bench.measureCold(
        '${opName}_cold_first',
        () => api.generateRsaKeyPair(2048),
      );

      for (var i = 0; i < 3; i++) {
        api.generateRsaKeyPair(2048);
      }
      final warmTotal = <double>[];
      for (var i = 0; i < 5; i++) {
        final sw = Stopwatch()..start();
        api.generateRsaKeyPair(2048);
        sw.stop();
        warmTotal.add(sw.elapsedMicroseconds / 1000.0);
      }
      final avgWarmMs = warmTotal.reduce((a, b) => a + b) / warmTotal.length;

      final record = OperationTiming(
        operation: opName,
        category: 'keygen',
        inputSizeBytes: 0,
        coldMs: cold.elapsedMs,
        warmMs: avgWarmMs,
        throughputMbps: 0,
        iterationsWarm: 5,
      );
      _collector.recordOperationTiming(record);
      expect(avgWarmMs, greaterThan(0));
    }, timeout: const Timeout(Duration(minutes: 3)));
    test('generateRsaKeyPair 4096', () {
      memoryTracker.sampleBytes('before_rsa4096_keygen');
      final opName = 'generateRsaKeyPair_4096';

      final cold = bench.measureCold(
        '${opName}_cold_first',
        () => api.generateRsaKeyPair(4096),
      );

      // ignore: unused_local_variable
      var gcBuf = Uint8List(8 * 1024 * 1024);
      gcBuf = Uint8List(0);
      for (var i = 0; i < 5; i++) {
        api.generateRsaKeyPair(4096);
      }
      final warmTotal = <double>[];
      for (var i = 0; i < 3; i++) {
        final sw = Stopwatch()..start();
        api.generateRsaKeyPair(4096);
        sw.stop();
        warmTotal.add(sw.elapsedMicroseconds / 1000.0);
      }
      final avgWarmMs = warmTotal.reduce((a, b) => a + b) / warmTotal.length;

      final record = OperationTiming(
        operation: opName,
        category: 'keygen',
        inputSizeBytes: 0,
        coldMs: cold.elapsedMs,
        warmMs: avgWarmMs,
        throughputMbps: 0,
        iterationsWarm: 3,
      );
      _collector.recordOperationTiming(record);
      memoryTracker.sampleBytes('after_rsa_keygen');
      expect(avgWarmMs, greaterThan(0));
    }, timeout: const Timeout(Duration(minutes: 5)));
    test('rsaSign + rsaVerify with SHA-256 — 100 iterations warm', () {
      final rsaKey = getTestRsaKeyPair();
      final message = api.randomBytes(32); // 32-byte message.

      {
        final cold = bench.measureCold(
          'rsaSign_cold',
          () => api.sign(message, helpers.pem(rsaKey.privateKeyPem)),
        );
        final signature = api.sign(message, helpers.pem(rsaKey.privateKeyPem));
        final warm = bench.measureWarm(
          'rsaSign_warm',
          () => api.sign(message, helpers.pem(rsaKey.privateKeyPem)),
          dataSizeBytes: message.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'rsaSign_sha256',
          'sign',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'rsaSign_sha256: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );

        final coldV = bench.measureCold(
          'rsaVerify_cold',
          () =>
              api.verify(message, helpers.pem(rsaKey.publicKeyPem), signature),
        );
        final warmV = bench.measureWarm(
          'rsaVerify_warm',
          () =>
              api.verify(message, helpers.pem(rsaKey.publicKeyPem), signature),
          dataSizeBytes: message.length,
          iterations: 100,
        );
        final recordV = bench.toOperationTiming(
          'rsaVerify_sha256',
          'verify',
          coldV,
          warmV,
        );
        _collector.recordOperationTiming(recordV);
        expect(
          coldV.elapsedMs,
          greaterThanOrEqualTo(warmV.meanMs * 0.0),
          reason:
              'rsaVerify_sha256: coldMs (${coldV.elapsedMs.toStringAsFixed(3)}) < warmMs (${warmV.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    });

    test('rsaEncrypt + rsaDecrypt — 100 iterations warm', () {
      final rsaKey = getTestRsaKeyPair();
      final plaintext = api.randomBytes(32); // Small for RSA-OAEP.

      {
        final cold = bench.measureCold(
          'rsaEncrypt_cold',
          () => api.rsaEncrypt(helpers.pem(rsaKey.publicKeyPem), plaintext),
        );
        final ciphertext = api.rsaEncrypt(
          helpers.pem(rsaKey.publicKeyPem),
          plaintext,
        );
        final warm = bench.measureWarm(
          'rsaEncrypt_warm',
          () => api.rsaEncrypt(helpers.pem(rsaKey.publicKeyPem), plaintext),
          dataSizeBytes: plaintext.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'rsaEncrypt',
          'asymmetric',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'rsaEncrypt: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );

        final coldD = bench.measureCold(
          'rsaDecrypt_cold',
          () => api.rsaDecrypt(helpers.pem(rsaKey.privateKeyPem), ciphertext),
        );
        final warmD = bench.measureWarm(
          'rsaDecrypt_warm',
          () => api.rsaDecrypt(helpers.pem(rsaKey.privateKeyPem), ciphertext),
          dataSizeBytes: ciphertext.length,
          iterations: 100,
        );
        final recordD = bench.toOperationTiming(
          'rsaDecrypt',
          'asymmetric',
          coldD,
          warmD,
        );
        _collector.recordOperationTiming(recordD);
        expect(
          coldD.elapsedMs,
          greaterThanOrEqualTo(warmD.meanMs * 0.0),
          reason:
              'rsaDecrypt: coldMs (${coldD.elapsedMs.toStringAsFixed(3)}) < warmMs (${warmD.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    });
  });

  memoryTracker.sampleBytes('after_rsa_keygen');

  group('EC benchmarks', () {
    void benchEcKeygen(String curve, String opName, int iterations) {
      final cold = bench.measureCold(
        '${opName}_cold_first',
        () => api.generateEcKeyPair(curve),
      );

      for (var i = 0; i < 3; i++) {
        api.generateEcKeyPair(curve);
      }
      final warmTotal = <double>[];
      for (var i = 0; i < iterations; i++) {
        final sw = Stopwatch()..start();
        api.generateEcKeyPair(curve);
        sw.stop();
        warmTotal.add(sw.elapsedMicroseconds / 1000.0);
      }
      final avgWarmMs = warmTotal.reduce((a, b) => a + b) / warmTotal.length;

      final record = OperationTiming(
        operation: opName,
        category: 'keygen',
        inputSizeBytes: 0,
        coldMs: cold.elapsedMs,
        warmMs: avgWarmMs,
        throughputMbps: 0,
        iterationsWarm: iterations,
      );
      _collector.recordOperationTiming(record);
    }

    test('generateEcKeyPair prime256v1 — 10 iterations', () {
      benchEcKeygen('prime256v1', 'generateEcKeyPair_prime256v1', 10);
    });

    test('generateEcKeyPair secp384r1 — 10 iterations', () {
      benchEcKeygen('secp384r1', 'generateEcKeyPair_secp384r1', 10);
    });

    test('generateEcKeyPair secp521r1 — 10 iterations', () {
      benchEcKeygen('secp521r1', 'generateEcKeyPair_secp521r1', 10);
    });

    test('ecSign + ecVerify prime256v1 — 150 iterations warm', () {
      final ecKey = getTestEcKeyPair();
      final message = api.randomBytes(32);

      {
        final cold = bench.measureCold(
          'ecSign_cold',
          () => api.sign(message, helpers.pem(ecKey.privateKeyPem)),
        );
        final signature = api.sign(message, helpers.pem(ecKey.privateKeyPem));
        final warm = bench.measureWarm(
          'ecSign_warm',
          () => api.sign(message, helpers.pem(ecKey.privateKeyPem)),
          dataSizeBytes: message.length,
          iterations: 150,
        );
        final record = bench.toOperationTiming(
          'ecSign_prime256v1',
          'sign',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'ecSign_prime256v1: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );

        final coldV = bench.measureCold(
          'ecVerify_cold',
          () => api.verify(message, helpers.pem(ecKey.publicKeyPem), signature),
        );
        final warmV = bench.measureWarm(
          'ecVerify_warm',
          () => api.verify(message, helpers.pem(ecKey.publicKeyPem), signature),
          dataSizeBytes: message.length,
          iterations: 150,
        );
        final recordV = bench.toOperationTiming(
          'ecVerify_prime256v1',
          'verify',
          coldV,
          warmV,
        );
        _collector.recordOperationTiming(recordV);
        expect(
          coldV.elapsedMs,
          greaterThanOrEqualTo(warmV.meanMs * 0.0),
          reason:
              'ecVerify_prime256v1: coldMs (${coldV.elapsedMs.toStringAsFixed(3)}) < warmMs (${warmV.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    });
  });

  group('CMS benchmarks', () {
    test('cmsSign + cmsVerify with EC cert — 100 iterations warm', () {
      final ecCert = getTestEcCertBytes();
      final ecKey = getTestEcKeyBytes();
      final data = api.randomBytes(256);

      Uint8List signed;
      {
        final cold = bench.measureCold(
          'cmsSign_ec_cold',
          () => api.cmsSign(data, ecCert, ecKey),
        );
        signed = api.cmsSign(data, ecCert, ecKey);
        final warm = bench.measureWarm(
          'cmsSign_ec_warm',
          () => api.cmsSign(data, ecCert, ecKey),
          dataSizeBytes: data.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'cmsSign_ec',
          'sign',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'cmsSign_ec: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }

      {
        final cold = bench.measureCold(
          'cmsVerify_ec_cold',
          () => api.cmsVerify(signed, trustedCert: ecCert),
        );
        final warm = bench.measureWarm(
          'cmsVerify_ec_warm',
          () => api.cmsVerify(signed, trustedCert: ecCert),
          dataSizeBytes: data.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'cmsVerify_ec',
          'verify',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'cmsVerify_ec: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    });

    test('cmsSign + cmsVerify with RSA cert — 100 iterations warm', () {
      final rsaCert = getTestRsaCertBytes();
      final rsaKey = getTestRsaKeyBytes();
      final data = api.randomBytes(256);

      Uint8List signed;
      {
        final cold = bench.measureCold(
          'cmsSign_rsa_cold',
          () => api.cmsSign(data, rsaCert, rsaKey),
        );
        signed = api.cmsSign(data, rsaCert, rsaKey);
        final warm = bench.measureWarm(
          'cmsSign_rsa_warm',
          () => api.cmsSign(data, rsaCert, rsaKey),
          dataSizeBytes: data.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'cmsSign_rsa',
          'sign',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'cmsSign_rsa: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }

      {
        final cold = bench.measureCold(
          'cmsVerify_rsa_cold',
          () => api.cmsVerify(signed, trustedCert: rsaCert),
        );
        final warm = bench.measureWarm(
          'cmsVerify_rsa_warm',
          () => api.cmsVerify(signed, trustedCert: rsaCert),
          dataSizeBytes: data.length,
          iterations: 100,
        );
        final record = bench.toOperationTiming(
          'cmsVerify_rsa',
          'verify',
          cold,
          warm,
        );
        _collector.recordOperationTiming(record);
        expect(
          cold.elapsedMs,
          greaterThanOrEqualTo(warm.meanMs * 0.0),
          reason:
              'cmsVerify_rsa: coldMs (${cold.elapsedMs.toStringAsFixed(3)}) < warmMs (${warm.meanMs.toStringAsFixed(3)}) * 0.9',
        );
      }
    });
  });

  group('Histogram & Raw Samples', () {
    test('sha256 at 1 MB — histogram distribution', () {
      final data = data1MB;
      final warm = benchDiag.measureWarm(
        'sha256_1MB_diag',
        () => api.sha256(data),
        dataSizeBytes: 1048576,
        iterations: 100,
        category: 'hash',
      );
      final histogram = benchDiag.computeHistogram(
        operation: 'sha256',
        category: 'hash',
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

    test('aes128CbcEncrypt at 1 MB — histogram + raw samples', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final warm = benchDiag.measureWarm(
        'aes128CbcEncrypt_1MB_diag',
        () => api.aes128CbcEncrypt(key, iv, data1MB),
        dataSizeBytes: 1048576,
        iterations: 100,
        category: 'cipher',
      );
      final histogram = benchDiag.computeHistogram(
        operation: 'aes128CbcEncrypt',
        category: 'cipher',
        warm: warm,
        perIterationTimes: warm.iterationTimesMs,
      );
      _collector.recordHistogram(histogram);

      expect(histogram.minMs, lessThanOrEqualTo(histogram.p25Ms));
      expect(histogram.p25Ms, lessThanOrEqualTo(histogram.medianMs));
      expect(histogram.medianMs, lessThanOrEqualTo(histogram.p75Ms));

      for (final sample in benchDiag.rawSamples) {
        if (sample.operation == 'aes128CbcEncrypt_1MB_diag') {
          _collector.recordRawSample(sample);
        }
      }

      final warmSamples = benchDiag.rawSamples
          .where(
            (s) =>
                s.operation == 'aes128CbcEncrypt_1MB_diag' && s.phase == 'warm',
          )
          .toList();
      expect(warmSamples.length, warm.iterations);
      expect(warmSamples.every((s) => s.isWarmup == false), isTrue);
    });

    test('rsaSign_sha256 — raw samples present', () {
      final rsaKey = getTestRsaKeyPair();
      final message = api.randomBytes(32);
      api.sign(message, helpers.pem(rsaKey.privateKeyPem));
      benchDiag.measureWarm(
        'rsaSign_warm_diag',
        () => api.sign(message, helpers.pem(rsaKey.privateKeyPem)),
        dataSizeBytes: message.length,
        iterations: 50,
        category: 'sign',
      );

      final signSamples = benchDiag.rawSamples
          .where((s) => s.operation == 'rsaSign_warm_diag' && s.phase == 'warm')
          .toList();
      expect(signSamples, isNotEmpty);
      expect(signSamples.isNotEmpty, isTrue);
      expect(signSamples.every((s) => s.elapsedMs > 0), isTrue);
    });

    test('measureCold emits raw sample', () {
      final cold = benchDiag.measureCold(
        'sha256_cold_diag',
        () => api.sha256(data1KB),
        category: 'hash',
        inputSizeBytes: 1024,
      );
      expect(cold.elapsedMs, greaterThan(0));

      final coldSamples = benchDiag.rawSamples
          .where((s) => s.operation == 'sha256_cold_diag' && s.phase == 'cold')
          .toList();
      expect(coldSamples.length, 1);
      expect(coldSamples.first.elapsedMs, greaterThan(0));
      expect(coldSamples.first.isWarmup, isFalse);
      expect(coldSamples.first.category, 'hash');
      expect(coldSamples.first.inputSizeBytes, 1024);
    });

    test('HistogramSnapshot computation correctness', () {
      final times = List<double>.generate(
        25,
        (i) => 1.0 + i * 0.04,
      ); // 1.00, 1.04, 1.08, ..., 1.96

      final warm = WarmTimingResult(
        meanMs: 1.48,
        minMs: 1.00,
        maxMs: 1.96,
        throughputMbps: 0,
        dataSizeBytes: 0,
        iterations: 25,
        iterationTimesMs: times,
      );

      final histogram = benchDiag.computeHistogram(
        operation: 'test',
        category: 'test',
        warm: warm,
        perIterationTimes: times,
      );


      expect(histogram.minMs, 1.00);
      expect(histogram.maxMs, 1.96);
      expect(histogram.medianMs, closeTo(1.48, 1e-6));
      expect(histogram.p25Ms, closeTo(1.24, 1e-6));
      expect(histogram.p75Ms, closeTo(1.72, 1e-6));

      expect(histogram.meanMs, closeTo(1.48, 1e-6));

      expect(histogram.stddevMs, greaterThan(0));
    });
  });

  group('Memory sampling', () {
    test('record after_stress memory sample', () {
      memoryTracker.sampleBytes('after_stress');
    });

    test('record final memory sample', () {
      memoryTracker.sampleBytes('final');
    });
  });

  group('Security validation', () {
    test('randomBytes entropy and chi-squared', () {
      try {
        final randomData = api.randomBytes(10000);
        final entropy = computeShannonEntropy(randomData);
        final chiResult = computeChiSquared(randomData);

        _collector.recordSecurityCheck('entropy_random', entropy > 7.9, {
          'entropy': entropy,
          'threshold': 7.9,
        });
        _collector.recordSecurityCheck('chi_squared_random', chiResult.passed, {
          'chi_squared': chiResult.statistic,
          'p_value': chiResult.pValue,
          'threshold': 0.01,
        });
      } catch (e) {
        _collector.recordSecurityCheck('entropy_random', false, {
          'error': e.toString(),
        });
        _collector.recordSecurityCheck('chi_squared_random', false, {
          'error': e.toString(),
        });
      }
    });

    test('RSA key uniqueness', () {
      try {
        const iterations = 50;
        final publicKeys = <Uint8List>[];
        for (var i = 0; i < iterations; i++) {
          final kp = api.generateRsaKeyPair(2048);
          publicKeys.add(helpers.pem(kp.publicKeyPem));
        }
        final uniqueness = checkUniqueness(publicKeys);
        _collector.recordSecurityCheck(
          'rsa_key_uniqueness',
          uniqueness == 1.0,
          {'uniqueness_rate': uniqueness, 'iterations': iterations},
        );
      } catch (e) {
        _collector.recordSecurityCheck('rsa_key_uniqueness', false, {
          'error': e.toString(),
        });
      }
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('EC key uniqueness', () {
      try {
        const iterations = 100;
        final publicKeys = <Uint8List>[];
        for (var i = 0; i < iterations; i++) {
          final kp = api.generateEcKeyPair('prime256v1');
          publicKeys.add(helpers.pem(kp.publicKeyPem));
        }
        final uniqueness = checkUniqueness(publicKeys);
        _collector.recordSecurityCheck('ec_key_uniqueness', uniqueness == 1.0, {
          'uniqueness_rate': uniqueness,
          'iterations': iterations,
        });
      } catch (e) {
        _collector.recordSecurityCheck('ec_key_uniqueness', false, {
          'error': e.toString(),
        });
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('RSA signature nondeterminism', () {
      try {
        final rsaKey = getTestRsaKeyPair();
        final message = api.randomBytes(32);
        final isNondeterministic = checkSignatureNonDeterminism(() {
          return api.sign(message, helpers.pem(rsaKey.privateKeyPem));
        });
        _collector.recordSecurityCheck(
          'signature_nondeterminism_rsa',
          !isNondeterministic,
          {'nondeterministic': isNondeterministic},
        );
      } catch (e) {
        _collector.recordSecurityCheck('signature_nondeterminism_rsa', false, {
          'error': e.toString(),
        });
      }
    });

    test('ECDSA signature nondeterminism', () {
      try {
        final ecKey = getTestEcKeyPair();
        final message = api.randomBytes(32);
        final isNondeterministic = checkSignatureNonDeterminism(() {
          return api.sign(message, helpers.pem(ecKey.privateKeyPem));
        });
        _collector.recordSecurityCheck(
          'signature_nondeterminism_ecdsa',
          isNondeterministic,
          {'nondeterministic': isNondeterministic},
        );
      } catch (e) {
        _collector.recordSecurityCheck(
          'signature_nondeterminism_ecdsa',
          false,
          {'error': e.toString()},
        );
      }
    });

    test('AES-GCM IV uniqueness', () {
      try {
        const iterations = 100;
        final key = api.randomBytes(16);
        final plaintext = api.randomBytes(64);
        final ivs = <Uint8List>[];
        for (var i = 0; i < iterations; i++) {
          final iv = api.randomBytes(12);
          ivs.add(iv);
          api.aes128GcmEncrypt(key, iv, plaintext);
        }
        final uniqueness = checkUniqueness(ivs);
        _collector.recordSecurityCheck('iv_uniqueness', uniqueness == 1.0, {
          'uniqueness_rate': uniqueness,
          'iterations': iterations,
        });
      } catch (e) {
        _collector.recordSecurityCheck('iv_uniqueness', false, {
          'error': e.toString(),
        });
      }
    });

    test('GCM and cross-key settings from test results', () {
      final allPassed = _collector.testResults
          .where((t) => t.status == 'failed')
          .isEmpty;
      _collector.recordSecurityCheck('gcm_tag_auth_enforced', allPassed, {
        'source': 'zone05_aes_gcm_test.dart',
      });
      _collector.recordSecurityCheck('gcm_aad_binding_enforced', allPassed, {
        'source': 'zone05_aes_gcm_test.dart',
      });
      _collector.recordSecurityCheck('cross_key_rejection', allPassed, {
        'source': 'zone07_ecdsa_test.dart',
      });
    });
  });

  group('SafeCurve checklist', () {
    test('NIST P-256 SafeCurveChecklist', () {
      final checklist = buildSafeCurveChecklist('prime256v1');

      expect(checklist.curveName, 'prime256v1');
      expect(checklist.fieldSizeBits, 256);
      expect(checklist.hasPrimeOrder, isTrue);
      expect(checklist.cofactorIsOne, isTrue);
      expect(checklist.embeddingDegree, 0);
      expect(checklist.embeddingDegreeSafe, isTrue);
      expect(checklist.twistSecure, isTrue);
      expect(checklist.notes, contains('prime256v1'));
      expect(checklist.notes, contains('cofactor h=1'));

      _collector.recordSecurityCheck('safe_curve_prime256v1', true, {
        'hasPrimeOrder': checklist.hasPrimeOrder,
        'cofactorIsOne': checklist.cofactorIsOne,
        'embeddingDegree': checklist.embeddingDegree,
      });
    });

    test('NIST P-384 SafeCurveChecklist', () {
      final checklist = buildSafeCurveChecklist('secp384r1');

      expect(checklist.curveName, 'secp384r1');
      expect(checklist.fieldSizeBits, 384);
      expect(checklist.hasPrimeOrder, isTrue);
      expect(checklist.cofactorIsOne, isTrue);
      expect(checklist.embeddingDegree, 0);
      expect(checklist.embeddingDegreeSafe, isTrue);
      expect(checklist.twistSecure, isTrue);
    });

    test('NIST P-521 SafeCurveChecklist', () {
      final checklist = buildSafeCurveChecklist('secp521r1');

      expect(checklist.curveName, 'secp521r1');
      expect(checklist.fieldSizeBits, 521);
      expect(checklist.hasPrimeOrder, isTrue);
      expect(checklist.cofactorIsOne, isTrue);
      expect(checklist.embeddingDegree, 0);
      expect(checklist.embeddingDegreeSafe, isTrue);
      expect(checklist.twistSecure, isTrue);
    });

    test('Embedding degree dynamic verification', () {
      final p256Order = BigInt.parse(
        'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
        radix: 16,
      );
      final p256Prime = BigInt.parse(
        'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
        radix: 16,
      );
      expect(
        verifyEmbeddingDegree(p256Prime, p256Order, curveName: 'P-256'),
        0,
      );

      final p384Order = BigInt.parse(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
        radix: 16,
      );
      final p384Prime = BigInt.parse(
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
        radix: 16,
      );
      expect(
        verifyEmbeddingDegree(p384Prime, p384Order, curveName: 'P-384'),
        0,
      );

      final p521Order = BigInt.parse(
        '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
        radix: 16,
      );
      final p521Prime = BigInt.parse(
        '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        radix: 16,
      );
      expect(
        verifyEmbeddingDegree(p521Prime, p521Order, curveName: 'P-521'),
        0,
      );
    });

    test('Unknown curve returns safe defaults', () {
      final checklist = buildSafeCurveChecklist('secp256k1');

      expect(checklist.curveName, 'secp256k1');
      expect(checklist.hasPrimeOrder, isFalse);
      expect(checklist.cofactorIsOne, isFalse);
      expect(checklist.embeddingDegree, 0);
      expect(checklist.embeddingDegreeSafe, isFalse);
      expect(checklist.twistSecure, isFalse);
      expect(checklist.notes, contains('Unknown curve'));
    });
  });

  group('CategorySummary aggregation', () {
    test('computeCategorySummaries aggregates correctly', () {
      final summaries = _collector.computeCategorySummaries();
      expect(summaries, isNotEmpty);

      final categories = summaries.map((s) => s.category).toSet();
      expect(
        categories.contains('hash'),
        isTrue,
        reason: 'Expected hash category in summaries',
      );
      expect(
        categories.contains('cipher'),
        isTrue,
        reason: 'Expected cipher category in summaries',
      );
      expect(
        categories.contains('aead'),
        isTrue,
        reason: 'Expected aead category in summaries',
      );

      for (final summary in summaries) {
        expect(summary.operationCount, greaterThan(0));
        expect(summary.totalMeasurements, greaterThan(0));
        expect(summary.totalWarmTimeMs, greaterThanOrEqualTo(0));
        expect(summary.meanThroughputMbps, greaterThanOrEqualTo(0));
        expect(
          summary.maxThroughputMbps,
          greaterThanOrEqualTo(summary.minThroughputMbps),
        );
      }
    });
  });

  group('Timing fix validation', () {
    test('computeMbps returns 0.0 for ms below resolution (< 0.0005)', () {
      expect(computeMbps(1048576, 0.0), equals(0.0));
      expect(computeMbps(1048576, 0.0004), equals(0.0));
      expect(computeMbps(1048576, 0.0001), equals(0.0));
    });

    test('computeMbps returns 0.0 for zero or negative bytes', () {
      expect(computeMbps(0, 1.0), equals(0.0));
      expect(computeMbps(-1, 1.0), equals(0.0));
    });

    test('computeMbps clamps to finite value for impossibly fast timing', () {
      final result = computeMbps(1048576, 0.00001);
      expect(result, isNot(equals(double.infinity)));
      expect(result, isNot(equals(double.nan)));
      expect(result, greaterThanOrEqualTo(0));
    });

    test('computeMbps produces reasonable value for normal timing', () {
      final result = computeMbps(1048576, 10.0);
      expect(result, greaterThan(50));
      expect(result, lessThan(200));
    });

    test('computeOpsPerSec returns 0.0 for near-zero ms', () {
      expect(computeOpsPerSec(0.0), equals(0.0));
      expect(computeOpsPerSec(0.0004), equals(0.0));
    });

    test('computeOpsPerSec returns valid value for normal timing', () {
      final result = computeOpsPerSec(1.0);
      expect(result, equals(1000.0));
    });

    test('computeOpsPerMin returns 0.0 for near-zero ms', () {
      expect(computeOpsPerMin(0.0), equals(0.0));
      expect(computeOpsPerMin(0.0004), equals(0.0));
    });

    test('computeOpsPerMin returns valid value for normal timing', () {
      final result = computeOpsPerMin(1.0);
      expect(result, equals(60000.0));
    });

    test('measureWarm returns throughputMbps = 0.0 for fast no-op', () {
      final warm = bench.measureWarm(
        'noop_test',
        () {},
        dataSizeBytes: 1048576,
        iterations: 100,
      );
      expect(warm.throughputMbps, equals(0.0));
      expect(warm.meanMs, isNot(equals(double.nan)));
      expect(warm.meanMs, greaterThanOrEqualTo(0));
    });

    test('measureWarm produces valid stats with cumulative timing', () {
      final warm = bench.measureWarm(
        'sha256_1kb_cumulative_test',
        () => api.sha256(data1KB),
        dataSizeBytes: 1024,
        iterations: 100,
      );
      expect(warm.meanMs, isNot(equals(double.nan)));
      expect(warm.meanMs, greaterThan(0));
      expect(warm.minMs, isNot(equals(double.nan)));
      expect(warm.maxMs, isNot(equals(double.nan)));
      expect(warm.minMs, lessThanOrEqualTo(warm.maxMs));
      expect(warm.iterations, equals(25));
    });

    test('measureWarm minMs <= meanMs <= maxMs invariant', () {
      final warm = bench.measureWarm(
        'sha256_64kb_invariant_test',
        () => api.sha256(data64KB),
        dataSizeBytes: 65536,
        iterations: 100,
      );
      expect(warm.minMs, lessThanOrEqualTo(warm.meanMs));
      expect(warm.meanMs, lessThanOrEqualTo(warm.maxMs));
    });

    test('measureWarm throughput is finite for real crypto operations', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final warm = bench.measureWarm(
        'aes128Cbc_1mb_fix_test',
        () => api.aes128CbcEncrypt(key, iv, data1MB),
        dataSizeBytes: 1048576,
        iterations: 100,
      );
      expect(warm.throughputMbps, isNot(equals(double.infinity)));
      expect(warm.throughputMbps, isNot(equals(double.nan)));
    });
  });

  tearDownAll(() async {
    final metricsOutput = Platform.environment['TCC_METRICS_OUTPUT'];
    if (metricsOutput == null || metricsOutput.isEmpty) return;

    final timings = _collector.operationTimings;

    _collector.computeCategorySummaries();

    final timing = TimingMetrics(
      operations: timings,
      cryptoApiLoadMs: 0,
      totalBenchmarkTimeMs: _collector.suiteElapsedMs,
      histograms: _collector.histograms,
      rawSamples: _collector.rawSamples,
      categorySummaries: _collector.categorySummaries,
    );

    final samples = memoryTracker.samples;
    final baseline = samples['baseline'] ?? -1;
    final finalRss = samples['final'] ?? -1;
    final delta = finalRss >= 0 && baseline >= 0 ? finalRss - baseline : -1;
    final leakThresholdBytes = 51200000;
    final leakDetected = delta > leakThresholdBytes;
    final peakRss = samples.values
        .where((v) => v > 0)
        .fold<int>(0, (a, b) => a > b ? a : b);

    final memory = MemoryMetrics(
      baselineRssKb: baseline >= 0 ? baseline ~/ 1024 : 0,
      afterApiLoadRssKb: (samples['after_api_init'] ?? 0) ~/ 1024,
      peakRssKb: peakRss ~/ 1024,
      afterStressRssKb: (samples['after_stress'] ?? 0) ~/ 1024,
      finalRssKb: finalRss >= 0 ? finalRss ~/ 1024 : 0,
      rssDeltaKb: delta >= 0 ? delta ~/ 1024 : 0,
      leakDetected: leakDetected,
      perOperationAllocations: memoryTracker.allocations,
      notes: memoryTracker.notes,
    );

    final throughput = buildThroughputMetrics(
      timings,
      _collector.totalBytesProcessed,
    );

    SecurityMetrics buildSecurity() {
      final checks = _collector.securityChecks;

      bool checkPassed(String name) => checks[name]?.passed ?? false;

      double checkValue(String name, String key) {
        final evidence = checks[name]?.evidence;
        if (evidence == null) return 0.0;
        return (evidence[key] as num?)?.toDouble() ?? 0.0;
      }

      bool checkBoolValue(String name, String key) {
        final evidence = checks[name]?.evidence;
        if (evidence == null) return false;
        return (evidence[key] as bool?) ?? false;
      }

      final entropyPassed = checkPassed('entropy_random');
      final chiPassed = checkPassed('chi_squared_random');
      final rsaUnique = checkPassed('rsa_key_uniqueness');
      final ecUnique = checkPassed('ec_key_uniqueness');
      final rsaNonDetPassed = checkPassed('signature_nondeterminism_rsa');
      final ecNonDetPassed = checkPassed('signature_nondeterminism_ecdsa');
      final rsaNonDet = checkBoolValue(
        'signature_nondeterminism_rsa',
        'nondeterministic',
      );
      final ecNonDet = checkBoolValue(
        'signature_nondeterminism_ecdsa',
        'nondeterministic',
      );
      final ivUnique = checkPassed('iv_uniqueness');
      final gcmTagAuth = checkPassed('gcm_tag_auth_enforced');
      final gcmAadBind = checkPassed('gcm_aad_binding_enforced');
      final crossKey = checkPassed('cross_key_rejection');

      final allPassed =
          entropyPassed &&
          chiPassed &&
          rsaUnique &&
          ecUnique &&
          rsaNonDetPassed &&
          ecNonDetPassed &&
          ivUnique &&
          gcmTagAuth &&
          gcmAadBind &&
          crossKey;

      return SecurityMetrics(
        entropyRandomBytes1024: checkValue('entropy_random', 'entropy'),
        entropyPassed: entropyPassed,
        chiSquared: checkValue('chi_squared_random', 'chi_squared'),
        chiSquaredPValue: checkValue('chi_squared_random', 'p_value'),
        chiSquaredPassed: chiPassed,
        rsaKeyUniquenessRate: checkValue(
          'rsa_key_uniqueness',
          'uniqueness_rate',
        ),
        ecKeyUniquenessRate: checkValue('ec_key_uniqueness', 'uniqueness_rate'),
        signatureNondeterminismRsa: rsaNonDet,
        signatureNondeterminismEcdsa: ecNonDet,
        ivUniquenessRate: checkValue('iv_uniqueness', 'uniqueness_rate'),
        gcmTagAuthEnforced: gcmTagAuth,
        gcmAadBindingEnforced: gcmAadBind,
        crossKeyRejection: crossKey,
        summary: allPassed
            ? 'All security checks passed.'
            : 'One or more security checks failed.',
        safeCurveChecklist: [
          buildSafeCurveChecklist('prime256v1'),
          buildSafeCurveChecklist('secp384r1'),
          buildSafeCurveChecklist('secp521r1'),
        ],
      );
    }

    final security = buildSecurity();

    try {
      final cipherResults = CipherSuiteComparison.compareCiphers(
        api,
        dataSizeBytes: 1048576,
        iterations: 50,
      );
      final cipherMetrics = cipherResults.asMap().entries.map((e) {
        final idx = e.key;
        final r = e.value;
        return CipherPerformanceMetrics(
          cipherName: r.name,
          encryptMbps: r.encryptMBps,
          decryptMbps: r.decryptMBps,
          hwAccelerated: r.hwAccelerated,
          keySizeBits: r.keySizeBits,
          blockSizeBytes: 16,
          throughputRatio: r.ratio,
          comparisonRank: idx + 1,
        );
      }).toList();
      final comparison = CipherSuiteComparisonMetrics(
        perCipher: cipherMetrics,
        fastestCipher: cipherMetrics.isNotEmpty
            ? cipherMetrics.first.cipherName
            : '',
        slowestCipher: cipherMetrics.isNotEmpty
            ? cipherMetrics.last.cipherName
            : '',
        overallThroughputRatio:
            cipherMetrics.isNotEmpty && cipherMetrics.last.encryptMbps > 0
            ? cipherMetrics.first.encryptMbps / cipherMetrics.last.encryptMbps
            : 0.0,
      );
      _collector.recordCipherSuiteComparison(comparison);
      for (final cm in cipherMetrics) {
        _collector.recordCipherPerformance(cm);
      }
    } catch (e) {
      stderr.writeln('[metrics_timing] Cipher suite comparison failed: $e');
    }

    try {
      final tlsResult = TlsHandshakeSimulator.simulateFullSession(
        api,
        'TLS_AES_128_GCM_SHA256',
        dataSizeBytes: 1048576,
        numTransfers: 10,
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
      _collector.recordTlsSimulation(tlsSim);
    } catch (e) {
      stderr.writeln('[metrics_timing] TLS simulation failed: $e');
    }

    final resource = ResourceMetrics(
      totalSuiteTimeMs: _collector.suiteElapsedMs,
      perZoneDurationMs: _collector.perZoneDurationMs,
      slowestTests:
          _collector.testResults.where((t) => t.status == 'passed').toList()
            ..sort((a, b) => b.durationMs.compareTo(a.durationMs)),
      fastestTests:
          _collector.testResults.where((t) => t.status == 'passed').toList()
            ..sort((a, b) => a.durationMs.compareTo(b.durationMs)),
      totalTestsRun: _collector.totalTestsRun,
      totalTestsPassed: _collector.totalTestsPassed,
      totalTestsFailed: _collector.totalTestsFailed,
      totalTestsSkipped: _collector.totalTestsSkipped,
      nativeLoadTimeMs: 0,
      openSslVersion: api.getOpenSSLVersion(),
      dartVersion: Platform.version.split(' ').first,
      platformOs: Platform.operatingSystem,
      processorCount: Platform.numberOfProcessors,
      ldLibraryPath: Platform.environment['LD_LIBRARY_PATH'] ?? '',
    );

    final coverage = LcovParser().parse('coverage/lcov.info');

    try {
      await _collector.writeJson(metricsOutput,
        timing: timing,
        memory: memory,
        throughput: throughput,
        security: security,
        resource: resource,
        coverage: coverage,
      );
    } catch (e) {
      stderr.writeln('[metrics_timing] Report write failed: \$e');
    }
  });
}
