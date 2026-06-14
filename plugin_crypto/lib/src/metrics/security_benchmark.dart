library;

import 'dart:typed_data';

import '../crypto/crypto_api.dart';


/// Aggregated result from a batch benchmarking operation.
class BatchResult {
  /// Total bytes processed across all iterations.
  final int totalBytes;

  /// Total elapsed wall-clock time in milliseconds.
  final double elapsedMs;

  /// Operations per second (iterations / seconds).
  final double operationsPerSec;

  /// Number of iterations executed.
  final int iterations;

  /// Per-iteration average time in milliseconds.
  double get avgMsPerOp => elapsedMs / iterations;

  const BatchResult({
    required this.totalBytes,
    required this.elapsedMs,
    required this.operationsPerSec,
    required this.iterations,
  });

  Map<String, dynamic> toJson() => {
    'total_bytes': totalBytes,
    'elapsed_ms': elapsedMs,
    'operations_per_sec': operationsPerSec,
    'iterations': iterations,
    'avg_ms_per_op': avgMsPerOp,
  };
}

/// Result for a single cipher in a comparison benchmark.
class CipherResult {
  /// Human-readable cipher name (e.g. "AES-128-CBC").
  final String name;

  /// Encryption throughput in MB/s.
  final double encryptMBps;

  /// Decryption throughput in MB/s.
  final double decryptMBps;

  /// Ratio of encrypt to decrypt throughput.
  double get ratio => decryptMBps > 0 ? encryptMBps / decryptMBps : 0.0;

  /// Whether hardware acceleration was detected.
  final bool hwAccelerated;

  /// Key size in bits.
  final int keySizeBits;

  const CipherResult({
    required this.name,
    required this.encryptMBps,
    required this.decryptMBps,
    required this.hwAccelerated,
    required this.keySizeBits,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'encrypt_mbps': encryptMBps,
    'decrypt_mbps': decryptMBps,
    'ratio': ratio,
    'hw_accelerated': hwAccelerated,
    'key_size_bits': keySizeBits,
  };
}

/// Result for a simulated TLS handshake.
class TlsSimulationResult {
  final String cipherSuite;
  final double handshakeTimeMs;
  final double keyExchangeTimeMs;
  final double certificateVerifyTimeMs;
  final double hmacDerivationTimeMs;
  final double bulkTransferEncryptMbps;
  final double bulkTransferDecryptMbps;
  final int numBulkTransfers;
  final double totalSessionMs;

  const TlsSimulationResult({
    required this.cipherSuite,
    required this.handshakeTimeMs,
    required this.keyExchangeTimeMs,
    required this.certificateVerifyTimeMs,
    required this.hmacDerivationTimeMs,
    required this.bulkTransferEncryptMbps,
    required this.bulkTransferDecryptMbps,
    required this.numBulkTransfers,
    required this.totalSessionMs,
  });

  Map<String, dynamic> toJson() => {
    'cipher_suite': cipherSuite,
    'handshake_time_ms': handshakeTimeMs,
    'key_exchange_time_ms': keyExchangeTimeMs,
    'certificate_verify_time_ms': certificateVerifyTimeMs,
    'hmac_derivation_time_ms': hmacDerivationTimeMs,
    'bulk_transfer_encrypt_mbps': bulkTransferEncryptMbps,
    'bulk_transfer_decrypt_mbps': bulkTransferDecryptMbps,
    'num_bulk_transfers': numBulkTransfers,
    'total_session_ms': totalSessionMs,
  };
}


class SecurityBenchmark {
  SecurityBenchmark._();

  static BatchResult batchHash(
    PluginCryptoAPI api,
    int iterations,
    int dataSizeBytes,
  ) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      final data = api.randomBytes(dataSizeBytes);
      api.sha256(data);
      api.sha512(data);
      api.sha3_256(data);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final totalHashes = iterations * 3;
    final hashesPerSec = elapsedMs > 0
        ? (totalHashes / elapsedMs) * 1000.0
        : 0.0;
    return BatchResult(
      totalBytes: iterations * dataSizeBytes,
      elapsedMs: elapsedMs,
      operationsPerSec: hashesPerSec,
      iterations: iterations,
    );
  }

  static BatchResult batchEncrypt(
    PluginCryptoAPI api,
    int iterations,
    int dataSizeBytes,
    String cipher,
  ) {
    final (key, iv) = _prepareCipherParams(api, cipher);
    final data = api.randomBytes(dataSizeBytes);

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      _runEncrypt(api, cipher, key, iv, data);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * dataSizeBytes,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  static BatchResult batchDecrypt(
    PluginCryptoAPI api,
    int iterations,
    int dataSizeBytes,
    String cipher,
  ) {
    final (key, iv) = _prepareCipherParams(api, cipher);
    final data = api.randomBytes(dataSizeBytes);

    final ciphertexts = <Uint8List>[];
    Uint8List? gcmTag; // stored once per cipher suite for GCM
    for (var i = 0; i < iterations; i++) {
      if (_isGcm(cipher)) {
        final result = _runGcmEncrypt(api, cipher, key, iv, data);
        ciphertexts.add(result.ciphertext);
        gcmTag = result.tag;
      } else {
        ciphertexts.add(_runEncrypt(api, cipher, key, iv, data) as Uint8List);
      }
    }

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      _runDecrypt(api, cipher, key, iv, ciphertexts[i], gcmTag);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * dataSizeBytes,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  /// Runs a batch ECDSA P-256 signing benchmark.
  static BatchResult batchSign(PluginCryptoAPI api, int iterations) {
    final keyPair = api.generateEcKeyPair('prime256v1');
    final privateKey = _pemToBytes(keyPair.privateKeyPem);
    final message = api.randomBytes(32);

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      api.sign(message, privateKey);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * 32,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  /// Runs a batch ECDSA P-256 verification benchmark.
  static BatchResult batchVerify(PluginCryptoAPI api, int iterations) {
    final keyPair = api.generateEcKeyPair('prime256v1');
    final publicKey = _pemToBytes(keyPair.publicKeyPem);
    final privateKey = _pemToBytes(keyPair.privateKeyPem);
    final message = api.randomBytes(32);
    final signature = api.sign(message, privateKey);

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      api.verify(message, publicKey, signature);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * 32,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  /// Runs a batch RSA signing benchmark for [keyBits] (2048 or 4096).
  static BatchResult batchRsaSign(
    PluginCryptoAPI api,
    int iterations,
    int keyBits,
  ) {
    final keyPair = api.generateRsaKeyPair(keyBits);
    final privateKey = _pemToBytes(keyPair.privateKeyPem);
    final message = api.randomBytes(32);

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      api.sign(message, privateKey);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * 32,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  /// Runs a batch RSA verification benchmark for [keyBits] (2048 or 4096).
  static BatchResult batchRsaVerify(
    PluginCryptoAPI api,
    int iterations,
    int keyBits,
  ) {
    final keyPair = api.generateRsaKeyPair(keyBits);
    final publicKey = _pemToBytes(keyPair.publicKeyPem);
    final privateKey = _pemToBytes(keyPair.privateKeyPem);
    final message = api.randomBytes(32);
    final signature = api.sign(message, privateKey);

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      api.verify(message, publicKey, signature);
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: iterations * 32,
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  static BatchResult batchKeyGen(
    PluginCryptoAPI api,
    int iterations,
    String type,
  ) {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      switch (type) {
        case 'rsa2048':
          api.generateRsaKeyPair(2048);
          break;
        case 'rsa4096':
          api.generateRsaKeyPair(4096);
          break;
        case 'ecp256':
          api.generateEcKeyPair('prime256v1');
          break;
        case 'ecp384':
          api.generateEcKeyPair('secp384r1');
          break;
        case 'ecp521':
          api.generateEcKeyPair('secp521r1');
          break;
        default:
          throw ArgumentError('Unsupported key type: $type');
      }
    }
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    final opsPerSec = elapsedMs > 0 ? (iterations / elapsedMs) * 1000.0 : 0.0;
    return BatchResult(
      totalBytes: 0, // keygen doesn't process input bytes
      elapsedMs: elapsedMs,
      operationsPerSec: opsPerSec,
      iterations: iterations,
    );
  }

  /// Returns the full OpenSSL version string.
  static String getOpenSslVersionFull(PluginCryptoAPI api) {
    return api.getOpenSSLVersion();
  }

  static Map<String, dynamic> getOpenSslCipherInfo(PluginCryptoAPI api) {
    final version = api.getOpenSSLVersion();
    final hasAesNi =
        version.contains('AES') ||
        version.contains('aesni') ||
        version.contains('AES-NI');
    final hasArmCrypto =
        version.contains('ARM') ||
        version.contains('armv8') ||
        version.contains('aarch64');

    final hwAccel = hasAesNi || hasArmCrypto;

    return {
      'aes128cbc': {
        'engine': hwAccel ? 'HW' : 'SW',
        'key_size_bits': 128,
        'block_size_bytes': 16,
        'mode': 'CBC',
        'hw_accelerated': hwAccel,
      },
      'aes256cbc': {
        'engine': hwAccel ? 'HW' : 'SW',
        'key_size_bits': 256,
        'block_size_bytes': 16,
        'mode': 'CBC',
        'hw_accelerated': hwAccel,
      },
      'aes128gcm': {
        'engine': hwAccel ? 'HW' : 'SW',
        'key_size_bits': 128,
        'block_size_bytes': 16,
        'mode': 'GCM',
        'hw_accelerated': hwAccel,
      },
      'aes256gcm': {
        'engine': hwAccel ? 'HW' : 'SW',
        'key_size_bits': 256,
        'block_size_bytes': 16,
        'mode': 'GCM',
        'hw_accelerated': hwAccel,
      },
      'openssl_version': version,
      'hw_acceleration_detected': hwAccel,
    };
  }


  static bool _isGcm(String cipher) =>
      cipher == 'aes128gcm' || cipher == 'aes256gcm';

  static (Uint8List, Uint8List) _prepareCipherParams(
    PluginCryptoAPI api,
    String cipher,
  ) {
    final keyLen = _isGcm(cipher)
        ? (cipher == 'aes128gcm' ? 16 : 32)
        : (cipher == 'aes128cbc' ? 16 : 32);
    final ivLen = _isGcm(cipher) ? 12 : 16;
    return (api.randomBytes(keyLen), api.randomBytes(ivLen));
  }

  static dynamic _runEncrypt(
    PluginCryptoAPI api,
    String cipher,
    Uint8List key,
    Uint8List iv,
    Uint8List data,
  ) {
    switch (cipher) {
      case 'aes128cbc':
        return api.aes128CbcEncrypt(key, iv, data);
      case 'aes256cbc':
        return api.aes256CbcEncrypt(key, iv, data);
      case 'aes128gcm':
        return api.aes128GcmEncrypt(key, iv, data);
      case 'aes256gcm':
        return api.aes256GcmEncrypt(key, iv, data);
      default:
        throw ArgumentError('Unsupported cipher: $cipher');
    }
  }

  static AesGcmResult _runGcmEncrypt(
    PluginCryptoAPI api,
    String cipher,
    Uint8List key,
    Uint8List iv,
    Uint8List data,
  ) {
    switch (cipher) {
      case 'aes128gcm':
        return api.aes128GcmEncrypt(key, iv, data);
      case 'aes256gcm':
        return api.aes256GcmEncrypt(key, iv, data);
      default:
        throw ArgumentError('Not a GCM cipher: $cipher');
    }
  }

  static dynamic _runDecrypt(
    PluginCryptoAPI api,
    String cipher,
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List? tag,
  ) {
    switch (cipher) {
      case 'aes128cbc':
        return api.aes128CbcDecrypt(key, iv, ciphertext);
      case 'aes256cbc':
        return api.aes256CbcDecrypt(key, iv, ciphertext);
      case 'aes128gcm':
        return api.aes128GcmDecrypt(key, iv, ciphertext, tag!);
      case 'aes256gcm':
        return api.aes256GcmDecrypt(key, iv, ciphertext, tag!);
      default:
        throw ArgumentError('Unsupported cipher: $cipher');
    }
  }

  static Uint8List _pemToBytes(String pem) {
    return Uint8List.fromList(pem.codeUnits);
  }

  /// Compute throughput in MB/s from data size and elapsed ms.
  static double _computeMbps(int bytes, double ms) {
    if (ms <= 0 || bytes <= 0) return 0.0;
    return (bytes / (1024 * 1024)) / (ms / 1000.0);
  }
}


class CipherSuiteComparison {
  CipherSuiteComparison._();

  static const _allCiphers = [
    'aes128cbc',
    'aes256cbc',
    'aes128gcm',
    'aes256gcm',
  ];

  static List<CipherResult> compareCiphers(
    PluginCryptoAPI api, {
    int dataSizeBytes = 1048576,
    int iterations = 100,
  }) {
    final cipherInfo = SecurityBenchmark.getOpenSslCipherInfo(api);
    final results = <CipherResult>[];

    for (final cipher in _allCiphers) {
      final info = cipherInfo[cipher] as Map<String, dynamic>?;
      final hwAccel = info?['hw_accelerated'] as bool? ?? false;
      final keyBits =
          info?['key_size_bits'] as int? ??
          (cipher.contains('256') ? 256 : 128);

      final encResult = SecurityBenchmark.batchEncrypt(
        api,
        iterations,
        dataSizeBytes,
        cipher,
      );
      final decResult = SecurityBenchmark.batchDecrypt(
        api,
        iterations,
        dataSizeBytes,
        cipher,
      );

      final encryptMBps = SecurityBenchmark._computeMbps(
        encResult.totalBytes,
        encResult.elapsedMs,
      );
      final decryptMBps = SecurityBenchmark._computeMbps(
        decResult.totalBytes,
        decResult.elapsedMs,
      );

      final name = switch (cipher) {
        'aes128cbc' => 'AES-128-CBC',
        'aes256cbc' => 'AES-256-CBC',
        'aes128gcm' => 'AES-128-GCM',
        'aes256gcm' => 'AES-256-GCM',
        _ => cipher,
      };

      results.add(
        CipherResult(
          name: name,
          encryptMBps: encryptMBps,
          decryptMBps: decryptMBps,
          hwAccelerated: hwAccel,
          keySizeBits: keyBits,
        ),
      );
    }

    results.sort((a, b) => b.encryptMBps.compareTo(a.encryptMBps));
    return results;
  }

  static List<CipherResult> compareCertificates(PluginCryptoAPI api) {
    final results = <CipherResult>[];

    for (final bits in [2048, 4096]) {
      SecurityBenchmark.batchKeyGen(
        api,
        5,
        bits == 2048 ? 'rsa2048' : 'rsa4096',
      );

      final signResult = SecurityBenchmark.batchRsaSign(api, 50, bits);

      final verifyResult = SecurityBenchmark.batchRsaVerify(api, 50, bits);

      final signMBps = SecurityBenchmark._computeMbps(
        signResult.totalBytes,
        signResult.elapsedMs,
      );
      final verifyMBps = SecurityBenchmark._computeMbps(
        verifyResult.totalBytes,
        verifyResult.elapsedMs,
      );

      results.add(
        CipherResult(
          name: 'RSA-$bits',
          encryptMBps: signMBps,
          decryptMBps: verifyMBps,
          hwAccelerated: false, // RSA is typically pure software
          keySizeBits: bits,
        ),
      );
    }

    return results;
  }

  static List<CipherResult> compareCurves(PluginCryptoAPI api) {
    final results = <CipherResult>[];
    final curves = [
      ('P-256', 'ecp256', 256),
      ('P-384', 'ecp384', 384),
      ('P-521', 'ecp521', 521),
    ];

    for (final (name, type, bits) in curves) {
      SecurityBenchmark.batchKeyGen(api, 10, type);

      BatchResult signResult;
      BatchResult verifyResult;

      if (type == 'ecp256') {
        signResult = SecurityBenchmark.batchSign(api, 100);
        verifyResult = SecurityBenchmark.batchVerify(api, 100);
      } else {
        final curveName = type == 'ecp384' ? 'secp384r1' : 'secp521r1';
        final keyPair = api.generateEcKeyPair(curveName);
        final privateKey = Uint8List.fromList(keyPair.privateKeyPem.codeUnits);
        final publicKey = Uint8List.fromList(keyPair.publicKeyPem.codeUnits);
        final message = api.randomBytes(32);

        final signSw = Stopwatch()..start();
        for (var i = 0; i < 100; i++) {
          api.sign(message, privateKey);
        }
        signSw.stop();
        final signElapsed = signSw.elapsedMicroseconds / 1000.0;
        signResult = BatchResult(
          totalBytes: 100 * 32,
          elapsedMs: signElapsed,
          operationsPerSec: signElapsed > 0
              ? (100 / signElapsed) * 1000.0
              : 0.0,
          iterations: 100,
        );

        final signature = api.sign(message, privateKey);
        final verifySw = Stopwatch()..start();
        for (var i = 0; i < 100; i++) {
          api.verify(message, publicKey, signature);
        }
        verifySw.stop();
        final verifyElapsed = verifySw.elapsedMicroseconds / 1000.0;
        verifyResult = BatchResult(
          totalBytes: 100 * 32,
          elapsedMs: verifyElapsed,
          operationsPerSec: verifyElapsed > 0
              ? (100 / verifyElapsed) * 1000.0
              : 0.0,
          iterations: 100,
        );
      }

      final signMBps = SecurityBenchmark._computeMbps(
        signResult.totalBytes,
        signResult.elapsedMs,
      );
      final verifyMBps = SecurityBenchmark._computeMbps(
        verifyResult.totalBytes,
        verifyResult.elapsedMs,
      );

      results.add(
        CipherResult(
          name: 'ECDSA-$name',
          encryptMBps: signMBps,
          decryptMBps: verifyMBps,
          hwAccelerated: false,
          keySizeBits: bits,
        ),
      );
    }

    return results;
  }
}


class TlsHandshakeSimulator {
  TlsHandshakeSimulator._();

  static TlsSimulationResult simulateHandshake(
    PluginCryptoAPI api,
    String cipherSuite,
  ) {
    final ecdhSw = Stopwatch()..start();
    final serverKey = api.generateEcKeyPair('prime256v1');
    final clientKey = api.generateEcKeyPair('prime256v1');
    final serverPubBytes = Uint8List.fromList(serverKey.publicKeyPem.codeUnits);
    final clientPubBytes = Uint8List.fromList(clientKey.publicKeyPem.codeUnits);
    final combined = Uint8List(serverPubBytes.length + clientPubBytes.length);
    combined.setAll(0, serverPubBytes);
    combined.setAll(serverPubBytes.length, clientPubBytes);
    api.sha256(combined);
    ecdhSw.stop();
    final keyExchangeMs = ecdhSw.elapsedMicroseconds / 1000.0;

    final challenge = api.randomBytes(32);
    final serverPrivBytes = Uint8List.fromList(
      serverKey.privateKeyPem.codeUnits,
    );
    final serverPubBytesOnly = Uint8List.fromList(
      serverKey.publicKeyPem.codeUnits,
    );

    final certSw = Stopwatch()..start();
    final sig = api.sign(challenge, serverPrivBytes);
    api.verify(challenge, serverPubBytesOnly, sig);
    certSw.stop();
    final certVerifyMs = certSw.elapsedMicroseconds / 1000.0;

    final hmacSw = Stopwatch()..start();
    for (var i = 0; i < 4; i++) {
      api.sha256(combined);
    }
    hmacSw.stop();
    final hmacMs = hmacSw.elapsedMicroseconds / 1000.0;

    final totalHandshakeMs = keyExchangeMs + certVerifyMs + hmacMs;

    return TlsSimulationResult(
      cipherSuite: cipherSuite,
      handshakeTimeMs: totalHandshakeMs,
      keyExchangeTimeMs: keyExchangeMs,
      certificateVerifyTimeMs: certVerifyMs,
      hmacDerivationTimeMs: hmacMs,
      bulkTransferEncryptMbps: 0,
      bulkTransferDecryptMbps: 0,
      numBulkTransfers: 0,
      totalSessionMs: totalHandshakeMs,
    );
  }

  /// Simulates a bulk data transfer phase: encrypt + MAC + decrypt + verify.
  static TlsSimulationResult simulateBulkTransfer(
    PluginCryptoAPI api,
    String cipherSuite,
    int dataSizeBytes,
  ) {
    final (keyLen, ivLen) = _cipherParamsForSuite(cipherSuite);
    final key = api.randomBytes(keyLen);
    final iv = api.randomBytes(ivLen);
    final plaintext = api.randomBytes(dataSizeBytes);

    final encSw = Stopwatch()..start();
    late Uint8List ciphertext;
    Uint8List? gcmTag;
    if (cipherSuite.contains('GCM')) {
      final result = cipherSuite.contains('128')
          ? api.aes128GcmEncrypt(key, iv, plaintext)
          : api.aes256GcmEncrypt(key, iv, plaintext);
      ciphertext = result.ciphertext;
      gcmTag = result.tag;
    } else {
      ciphertext = cipherSuite.contains('128')
          ? api.aes128CbcEncrypt(key, iv, plaintext)
          : api.aes256CbcEncrypt(key, iv, plaintext);
    }
    encSw.stop();
    final encryptMs = encSw.elapsedMicroseconds / 1000.0;

    final macSw = Stopwatch()..start();
    api.sha256(ciphertext);
    macSw.stop();
    final macMs = macSw.elapsedMicroseconds / 1000.0;

    final decSw = Stopwatch()..start();
    if (cipherSuite.contains('GCM')) {
      cipherSuite.contains('128')
          ? api.aes128GcmDecrypt(key, iv, ciphertext, gcmTag!)
          : api.aes256GcmDecrypt(key, iv, ciphertext, gcmTag!);
    } else {
      cipherSuite.contains('128')
          ? api.aes128CbcDecrypt(key, iv, ciphertext)
          : api.aes256CbcDecrypt(key, iv, ciphertext);
    }
    decSw.stop();
    final decryptMs = decSw.elapsedMicroseconds / 1000.0;

    final verifySw = Stopwatch()..start();
    api.sha256(ciphertext);
    verifySw.stop();
    final verifyMs = verifySw.elapsedMicroseconds / 1000.0;

    final encryptMBps = SecurityBenchmark._computeMbps(
      dataSizeBytes,
      encryptMs,
    );
    final decryptMBps = SecurityBenchmark._computeMbps(
      dataSizeBytes,
      decryptMs,
    );

    return TlsSimulationResult(
      cipherSuite: cipherSuite,
      handshakeTimeMs: 0,
      keyExchangeTimeMs: 0,
      certificateVerifyTimeMs: 0,
      hmacDerivationTimeMs: 0,
      bulkTransferEncryptMbps: encryptMBps,
      bulkTransferDecryptMbps: decryptMBps,
      numBulkTransfers: 1,
      totalSessionMs: encryptMs + macMs + decryptMs + verifyMs,
    );
  }

  /// Simulates a full TLS session: handshake + multiple bulk transfers.
  static TlsSimulationResult simulateFullSession(
    PluginCryptoAPI api,
    String cipherSuite, {
    int dataSizeBytes = 1048576,
    int numTransfers = 10,
  }) {
    final handshake = simulateHandshake(api, cipherSuite);

    var totalBulkEncryptMBps = 0.0;
    var totalBulkDecryptMBps = 0.0;
    var totalBulkMs = 0.0;

    for (var i = 0; i < numTransfers; i++) {
      final bulk = simulateBulkTransfer(api, cipherSuite, dataSizeBytes);
      totalBulkEncryptMBps += bulk.bulkTransferEncryptMbps;
      totalBulkDecryptMBps += bulk.bulkTransferDecryptMbps;
      totalBulkMs += bulk.totalSessionMs;
    }

    return TlsSimulationResult(
      cipherSuite: cipherSuite,
      handshakeTimeMs: handshake.handshakeTimeMs,
      keyExchangeTimeMs: handshake.keyExchangeTimeMs,
      certificateVerifyTimeMs: handshake.certificateVerifyTimeMs,
      hmacDerivationTimeMs: handshake.hmacDerivationTimeMs,
      bulkTransferEncryptMbps: numTransfers > 0
          ? totalBulkEncryptMBps / numTransfers
          : 0,
      bulkTransferDecryptMbps: numTransfers > 0
          ? totalBulkDecryptMBps / numTransfers
          : 0,
      numBulkTransfers: numTransfers,
      totalSessionMs: handshake.handshakeTimeMs + totalBulkMs,
    );
  }

  static (int, int) _cipherParamsForSuite(String cipherSuite) {
    final is256 =
        cipherSuite.contains('AES_256') ||
        (cipherSuite.contains('256') && !cipherSuite.contains('128'));
    final isGcm = cipherSuite.contains('GCM');
    final keyLen = is256 ? 32 : 16;
    final ivLen = isGcm ? 12 : 16;
    return (keyLen, ivLen);
  }
}
