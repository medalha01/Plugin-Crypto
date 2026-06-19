library;

import 'dart:convert';
import 'dart:typed_data';


/// Base64-encode binary data for JSON storage.
String hexEncode(Uint8List bytes) => base64Encode(bytes);

/// Base64-decode binary data from JSON storage.
Uint8List hexDecode(String s) => base64Decode(s);


/// A single micro-benchmark timing record for one crypto operation.
class OperationTiming {
  final String operation;
  final String category;
  final int inputSizeBytes;
  final double coldMs;
  final double warmMs;
  final double throughputMbps;
  final int iterationsWarm;

  const OperationTiming({
    required this.operation,
    required this.category,
    required this.inputSizeBytes,
    required this.coldMs,
    required this.warmMs,
    required this.throughputMbps,
    required this.iterationsWarm,
  });

  Map<String, dynamic> toJson() => {
    'operation': operation,
    'category': category,
    'input_size_bytes': inputSizeBytes,
    'cold_ms': coldMs,
    'warm_ms': warmMs,
    'throughput_mbps': throughputMbps,
    'iterations_warm': iterationsWarm,
  };

  factory OperationTiming.fromJson(Map<String, dynamic> json) {
    return OperationTiming(
      operation: json['operation'] as String,
      category: json['category'] as String,
      inputSizeBytes: json['input_size_bytes'] as int,
      coldMs: (json['cold_ms'] as num).toDouble(),
      warmMs: (json['warm_ms'] as num).toDouble(),
      throughputMbps: (json['throughput_mbps'] as num).toDouble(),
      iterationsWarm: json['iterations_warm'] as int,
    );
  }
}

class HistogramSnapshot {
  final String operation;
  final String category;
  final int inputSizeBytes;
  final int sampleCount;
  final double minMs;
  final double p5Ms;
  final double p25Ms;
  final double medianMs;
  final double p75Ms;
  final double p95Ms;
  final double p99Ms;
  final double maxMs;
  final double meanMs;
  final double stddevMs;

  const HistogramSnapshot({
    required this.operation,
    required this.category,
    required this.inputSizeBytes,
    required this.sampleCount,
    required this.minMs,
    required this.p5Ms,
    required this.p25Ms,
    required this.medianMs,
    required this.p75Ms,
    required this.p95Ms,
    required this.p99Ms,
    required this.maxMs,
    required this.meanMs,
    required this.stddevMs,
  });

  Map<String, dynamic> toJson() => {
    'operation': operation,
    'category': category,
    'input_size_bytes': inputSizeBytes,
    'sample_count': sampleCount,
    'min_ms': minMs,
    'p5_ms': p5Ms,
    'p25_ms': p25Ms,
    'median_ms': medianMs,
    'p75_ms': p75Ms,
    'p95_ms': p95Ms,
    'p99_ms': p99Ms,
    'max_ms': maxMs,
    'mean_ms': meanMs,
    'stddev_ms': stddevMs,
  };

  factory HistogramSnapshot.fromJson(Map<String, dynamic> json) {
    return HistogramSnapshot(
      operation: json['operation'] as String,
      category: json['category'] as String,
      inputSizeBytes: json['input_size_bytes'] as int,
      sampleCount: json['sample_count'] as int,
      minMs: (json['min_ms'] as num).toDouble(),
      p5Ms: (json['p5_ms'] as num).toDouble(),
      p25Ms: (json['p25_ms'] as num).toDouble(),
      medianMs: (json['median_ms'] as num).toDouble(),
      p75Ms: (json['p75_ms'] as num).toDouble(),
      p95Ms: (json['p95_ms'] as num).toDouble(),
      p99Ms: (json['p99_ms'] as num).toDouble(),
      maxMs: (json['max_ms'] as num).toDouble(),
      meanMs: (json['mean_ms'] as num).toDouble(),
      stddevMs: (json['stddev_ms'] as num).toDouble(),
    );
  }
}

class RawTimingSample {
  final String operation;
  final String category;
  final int inputSizeBytes;
  final String phase; // 'cold' or 'warm'
  final int sampleIndex;
  final double elapsedMs;
  final bool isWarmup;

  const RawTimingSample({
    required this.operation,
    required this.category,
    required this.inputSizeBytes,
    required this.phase,
    required this.sampleIndex,
    required this.elapsedMs,
    required this.isWarmup,
  });

  Map<String, dynamic> toJson() => {
    'operation': operation,
    'category': category,
    'input_size_bytes': inputSizeBytes,
    'phase': phase,
    'sample_index': sampleIndex,
    'elapsed_ms': elapsedMs,
    'is_warmup': isWarmup,
  };

  factory RawTimingSample.fromJson(Map<String, dynamic> json) {
    return RawTimingSample(
      operation: json['operation'] as String,
      category: json['category'] as String,
      inputSizeBytes: json['input_size_bytes'] as int,
      phase: json['phase'] as String,
      sampleIndex: json['sample_index'] as int,
      elapsedMs: (json['elapsed_ms'] as num).toDouble(),
      isWarmup: json['is_warmup'] as bool,
    );
  }
}

class CategorySummary {
  final String category;
  final int operationCount;
  final int totalMeasurements;
  final double totalWarmTimeMs;
  final double totalColdTimeMs;
  final double meanThroughputMbps;
  final double maxThroughputMbps;
  final double minThroughputMbps;
  final double weightedThroughputMbps;

  const CategorySummary({
    required this.category,
    required this.operationCount,
    required this.totalMeasurements,
    required this.totalWarmTimeMs,
    required this.totalColdTimeMs,
    required this.meanThroughputMbps,
    required this.maxThroughputMbps,
    required this.minThroughputMbps,
    required this.weightedThroughputMbps,
  });

  Map<String, dynamic> toJson() => {
    'category': category,
    'operation_count': operationCount,
    'total_measurements': totalMeasurements,
    'total_warm_time_ms': totalWarmTimeMs,
    'total_cold_time_ms': totalColdTimeMs,
    'mean_throughput_mbps': meanThroughputMbps,
    'max_throughput_mbps': maxThroughputMbps,
    'min_throughput_mbps': minThroughputMbps,
    'weighted_throughput_mbps': weightedThroughputMbps,
  };

  factory CategorySummary.fromJson(Map<String, dynamic> json) {
    return CategorySummary(
      category: json['category'] as String,
      operationCount: json['operation_count'] as int,
      totalMeasurements: json['total_measurements'] as int,
      totalWarmTimeMs: (json['total_warm_time_ms'] as num).toDouble(),
      totalColdTimeMs: (json['total_cold_time_ms'] as num).toDouble(),
      meanThroughputMbps: (json['mean_throughput_mbps'] as num).toDouble(),
      maxThroughputMbps: (json['max_throughput_mbps'] as num).toDouble(),
      minThroughputMbps: (json['min_throughput_mbps'] as num).toDouble(),
      weightedThroughputMbps: (json['weighted_throughput_mbps'] as num)
          .toDouble(),
    );
  }
}

/// Micro-benchmark timing results for all measured crypto operations.
class TimingMetrics {
  final List<OperationTiming> operations;
  final double cryptoApiLoadMs;
  final double totalBenchmarkTimeMs;
  final List<HistogramSnapshot> histograms;
  final List<RawTimingSample> rawSamples;
  final List<CategorySummary> categorySummaries;
  final List<CipherPerformanceMetrics> cipherSuites;

  const TimingMetrics({
    required this.operations,
    required this.cryptoApiLoadMs,
    required this.totalBenchmarkTimeMs,
    this.histograms = const [],
    this.rawSamples = const [],
    this.categorySummaries = const [],
    this.cipherSuites = const [],
  });

  Map<String, dynamic> toJson() => {
    'operations': operations.map((e) => e.toJson()).toList(),
    'crypto_api_load_ms': cryptoApiLoadMs,
    'total_benchmark_time_ms': totalBenchmarkTimeMs,
    'histograms': histograms.map((e) => e.toJson()).toList(),
    'raw_samples': rawSamples.map((e) => e.toJson()).toList(),
    'category_summaries': categorySummaries.map((e) => e.toJson()).toList(),
    'cipher_suites': cipherSuites.map((e) => e.toJson()).toList(),
  };

  factory TimingMetrics.fromJson(Map<String, dynamic> json) {
    return TimingMetrics(
      operations: (json['operations'] as List<dynamic>)
          .map((e) => OperationTiming.fromJson(e as Map<String, dynamic>))
          .toList(),
      cryptoApiLoadMs: (json['crypto_api_load_ms'] as num).toDouble(),
      totalBenchmarkTimeMs: (json['total_benchmark_time_ms'] as num).toDouble(),
      histograms:
          (json['histograms'] as List<dynamic>?)
              ?.map(
                (e) => HistogramSnapshot.fromJson(e as Map<String, dynamic>),
              )
              .toList() ??
          const [],
      rawSamples:
          (json['raw_samples'] as List<dynamic>?)
              ?.map((e) => RawTimingSample.fromJson(e as Map<String, dynamic>))
              .toList() ??
          const [],
      categorySummaries:
          (json['category_summaries'] as List<dynamic>?)
              ?.map((e) => CategorySummary.fromJson(e as Map<String, dynamic>))
              .toList() ??
          const [],
      cipherSuites:
          (json['cipher_suites'] as List<dynamic>?)
              ?.map(
                (e) => CipherPerformanceMetrics.fromJson(
                  e as Map<String, dynamic>,
                ),
              )
              .toList() ??
          const [],
    );
  }
}


/// Performance metrics for a single cipher suite.
class CipherPerformanceMetrics {
  /// Human-readable cipher name (e.g. "AES-128-CBC").
  final String cipherName;

  /// Encryption throughput in MB/s.
  final double encryptMbps;

  /// Decryption throughput in MB/s.
  final double decryptMbps;

  /// Whether hardware acceleration was detected.
  final bool hwAccelerated;

  /// Key size in bits.
  final int keySizeBits;

  /// Block size in bytes.
  final int blockSizeBytes;

  /// Ratio of encrypt to decrypt throughput.
  final double throughputRatio;

  /// Rank in comparison (1 = fastest).
  final int comparisonRank;

  const CipherPerformanceMetrics({
    required this.cipherName,
    required this.encryptMbps,
    required this.decryptMbps,
    required this.hwAccelerated,
    required this.keySizeBits,
    required this.blockSizeBytes,
    required this.throughputRatio,
    required this.comparisonRank,
  });

  Map<String, dynamic> toJson() => {
    'cipher_name': cipherName,
    'encrypt_mbps': encryptMbps,
    'decrypt_mbps': decryptMbps,
    'hw_accelerated': hwAccelerated,
    'key_size_bits': keySizeBits,
    'block_size_bytes': blockSizeBytes,
    'throughput_ratio': throughputRatio,
    'comparison_rank': comparisonRank,
  };

  factory CipherPerformanceMetrics.fromJson(Map<String, dynamic> json) {
    return CipherPerformanceMetrics(
      cipherName: json['cipher_name'] as String,
      encryptMbps: (json['encrypt_mbps'] as num).toDouble(),
      decryptMbps: (json['decrypt_mbps'] as num).toDouble(),
      hwAccelerated: json['hw_accelerated'] as bool,
      keySizeBits: json['key_size_bits'] as int,
      blockSizeBytes: json['block_size_bytes'] as int,
      throughputRatio: (json['throughput_ratio'] as num).toDouble(),
      comparisonRank: json['comparison_rank'] as int,
    );
  }
}


/// Aggregate comparison results across multiple cipher suites.
class CipherSuiteComparisonMetrics {
  /// Per-cipher performance metrics, sorted by rank.
  final List<CipherPerformanceMetrics> perCipher;

  /// Name of the fastest cipher suite.
  final String fastestCipher;

  /// Name of the slowest cipher suite.
  final String slowestCipher;

  /// Ratio between fastest and slowest throughput.
  final double overallThroughputRatio;

  const CipherSuiteComparisonMetrics({
    required this.perCipher,
    required this.fastestCipher,
    required this.slowestCipher,
    required this.overallThroughputRatio,
  });

  Map<String, dynamic> toJson() => {
    'per_cipher': perCipher.map((e) => e.toJson()).toList(),
    'fastest_cipher': fastestCipher,
    'slowest_cipher': slowestCipher,
    'overall_throughput_ratio': overallThroughputRatio,
  };

  factory CipherSuiteComparisonMetrics.fromJson(Map<String, dynamic> json) {
    return CipherSuiteComparisonMetrics(
      perCipher: (json['per_cipher'] as List<dynamic>)
          .map(
            (e) => CipherPerformanceMetrics.fromJson(e as Map<String, dynamic>),
          )
          .toList(),
      fastestCipher: json['fastest_cipher'] as String,
      slowestCipher: json['slowest_cipher'] as String,
      overallThroughputRatio: (json['overall_throughput_ratio'] as num)
          .toDouble(),
    );
  }
}


/// Simulated TLS session metrics.
class TlsSimulationMetrics {
  /// Total handshake time in milliseconds.
  final double handshakeTimeMs;

  /// Cipher suite used for the session.
  final String cipherSuite;

  /// Key exchange phase time in milliseconds.
  final double keyExchangeTimeMs;

  /// Certificate verification time in milliseconds.
  final double certificateVerifyTimeMs;

  /// HMAC key derivation time in milliseconds.
  final double hmacDerivationTimeMs;

  /// Average bulk transfer encrypt throughput in MB/s.
  final double bulkTransferEncryptMbps;

  /// Average bulk transfer decrypt throughput in MB/s.
  final double bulkTransferDecryptMbps;

  /// Number of bulk transfers simulated.
  final int numBulkTransfers;

  /// Total session time (handshake + all transfers) in ms.
  final double totalSessionMs;

  const TlsSimulationMetrics({
    required this.handshakeTimeMs,
    required this.cipherSuite,
    required this.keyExchangeTimeMs,
    required this.certificateVerifyTimeMs,
    required this.hmacDerivationTimeMs,
    required this.bulkTransferEncryptMbps,
    required this.bulkTransferDecryptMbps,
    required this.numBulkTransfers,
    required this.totalSessionMs,
  });

  Map<String, dynamic> toJson() => {
    'handshake_time_ms': handshakeTimeMs,
    'cipher_suite': cipherSuite,
    'key_exchange_time_ms': keyExchangeTimeMs,
    'certificate_verify_time_ms': certificateVerifyTimeMs,
    'hmac_derivation_time_ms': hmacDerivationTimeMs,
    'bulk_transfer_encrypt_mbps': bulkTransferEncryptMbps,
    'bulk_transfer_decrypt_mbps': bulkTransferDecryptMbps,
    'num_bulk_transfers': numBulkTransfers,
    'total_session_ms': totalSessionMs,
  };

  factory TlsSimulationMetrics.fromJson(Map<String, dynamic> json) {
    return TlsSimulationMetrics(
      handshakeTimeMs: (json['handshake_time_ms'] as num).toDouble(),
      cipherSuite: json['cipher_suite'] as String,
      keyExchangeTimeMs: (json['key_exchange_time_ms'] as num).toDouble(),
      certificateVerifyTimeMs: (json['certificate_verify_time_ms'] as num)
          .toDouble(),
      hmacDerivationTimeMs: (json['hmac_derivation_time_ms'] as num).toDouble(),
      bulkTransferEncryptMbps: (json['bulk_transfer_encrypt_mbps'] as num)
          .toDouble(),
      bulkTransferDecryptMbps: (json['bulk_transfer_decrypt_mbps'] as num)
          .toDouble(),
      numBulkTransfers: json['num_bulk_transfers'] as int,
      totalSessionMs: (json['total_session_ms'] as num).toDouble(),
    );
  }
}


/// Memory footprint samples taken at key checkpoints during the test suite.
class MemoryMetrics {
  /// RSS before any operation (baseline).
  final int baselineRssKb;

  /// RSS after PluginCryptoAPI.instance initialization.
  final int afterApiLoadRssKb;

  /// Peak RSS observed during RSA 4096 key generation.
  final int peakRssKb;

  /// RSS after 1000-iteration stress loop.
  final int afterStressRssKb;

  /// RSS after all operations complete.
  final int finalRssKb;

  /// Delta: final - baseline. Near-zero means no leak.
  final int rssDeltaKb;

  /// True if delta suggests a memory leak (> 1024 KB).
  final bool leakDetected;

  /// Known per-operation native allocation counts.
  final Map<String, int> perOperationAllocations;

  /// Platform-specific notes about memory measurement.
  final String notes;

  const MemoryMetrics({
    required this.baselineRssKb,
    required this.afterApiLoadRssKb,
    required this.peakRssKb,
    required this.afterStressRssKb,
    required this.finalRssKb,
    required this.rssDeltaKb,
    required this.leakDetected,
    required this.perOperationAllocations,
    required this.notes,
  });

  Map<String, dynamic> toJson() => {
    'baseline_rss_kb': baselineRssKb,
    'after_api_load_rss_kb': afterApiLoadRssKb,
    'peak_rss_kb': peakRssKb,
    'after_stress_rss_kb': afterStressRssKb,
    'final_rss_kb': finalRssKb,
    'rss_delta_kb': rssDeltaKb,
    'leak_detected': leakDetected,
    'per_operation_allocations': perOperationAllocations,
    'notes': notes,
  };

  factory MemoryMetrics.fromJson(Map<String, dynamic> json) {
    return MemoryMetrics(
      baselineRssKb: json['baseline_rss_kb'] as int,
      afterApiLoadRssKb: json['after_api_load_rss_kb'] as int,
      peakRssKb: json['peak_rss_kb'] as int,
      afterStressRssKb: json['after_stress_rss_kb'] as int,
      finalRssKb: json['final_rss_kb'] as int,
      rssDeltaKb: json['rss_delta_kb'] as int,
      leakDetected: json['leak_detected'] as bool,
      perOperationAllocations: Map<String, int>.from(
        json['per_operation_allocations'] as Map,
      ),
      notes: json['notes'] as String,
    );
  }
}


/// Aggregated throughput calculations derived from timing data.
class ThroughputMetrics {
  /// sha256 on 1 MB data.
  final double sha256Mbps;

  /// sha384 on 1 MB data.
  final double sha384Mbps;

  /// sha512 on 1 MB data.
  final double sha512Mbps;

  /// sha3_256 on 1 MB data.
  final double sha3_256Mbps;

  /// sha3_512 on 1 MB data.
  final double sha3_512Mbps;

  /// AES-128-CBC encrypt on 1 MB data.
  final double aes128CbcEncryptMbps;

  /// AES-128-CBC decrypt on 1 MB data.
  final double aes128CbcDecryptMbps;

  /// AES-256-CBC encrypt on 1 MB data.
  final double aes256CbcEncryptMbps;

  /// AES-256-CBC decrypt on 1 MB data.
  final double aes256CbcDecryptMbps;

  /// AES-128-GCM encrypt on 1 MB data.
  final double aes128GcmEncryptMbps;

  /// AES-128-GCM decrypt on 1 MB data.
  final double aes128GcmDecryptMbps;

  /// AES-256-GCM encrypt on 1 MB data.
  final double aes256GcmEncryptMbps;

  /// AES-256-GCM decrypt on 1 MB data.
  final double aes256GcmDecryptMbps;

  /// RSA 2048 keygen operations per minute.
  final double rsa2048KeygenOpsPerMin;

  /// RSA 4096 keygen operations per minute.
  final double rsa4096KeygenOpsPerMin;

  /// EC prime256v1 keygen ops/min.
  final double ecPrime256v1KeygenOpsPerMin;

  /// EC secp384r1 keygen ops/min.
  final double ecSecp384r1KeygenOpsPerMin;

  /// EC secp521r1 keygen ops/min.
  final double ecSecp521r1KeygenOpsPerMin;

  /// RSA SHA-256 sign operations per second.
  final double rsaSignPerSec;

  /// RSA SHA-256 verify operations per second.
  final double rsaVerifyPerSec;

  /// EC prime256v1 sign ops/sec.
  final double ecSignPerSec;

  /// EC prime256v1 verify ops/sec.
  final double ecVerifyPerSec;

  /// Total bytes processed across all operations.
  final int totalBytesProcessed;

  const ThroughputMetrics({
    required this.sha256Mbps,
    required this.sha384Mbps,
    required this.sha512Mbps,
    required this.sha3_256Mbps,
    required this.sha3_512Mbps,
    required this.aes128CbcEncryptMbps,
    required this.aes128CbcDecryptMbps,
    required this.aes256CbcEncryptMbps,
    required this.aes256CbcDecryptMbps,
    required this.aes128GcmEncryptMbps,
    required this.aes128GcmDecryptMbps,
    required this.aes256GcmEncryptMbps,
    required this.aes256GcmDecryptMbps,
    required this.rsa2048KeygenOpsPerMin,
    required this.rsa4096KeygenOpsPerMin,
    required this.ecPrime256v1KeygenOpsPerMin,
    required this.ecSecp384r1KeygenOpsPerMin,
    required this.ecSecp521r1KeygenOpsPerMin,
    required this.rsaSignPerSec,
    required this.rsaVerifyPerSec,
    required this.ecSignPerSec,
    required this.ecVerifyPerSec,
    required this.totalBytesProcessed,
  });

  Map<String, dynamic> toJson() => {
    'sha256_mbps': sha256Mbps,
    'sha384_mbps': sha384Mbps,
    'sha512_mbps': sha512Mbps,
    'sha3_256_mbps': sha3_256Mbps,
    'sha3_512_mbps': sha3_512Mbps,
    'aes128_cbc_encrypt_mbps': aes128CbcEncryptMbps,
    'aes128_cbc_decrypt_mbps': aes128CbcDecryptMbps,
    'aes256_cbc_encrypt_mbps': aes256CbcEncryptMbps,
    'aes256_cbc_decrypt_mbps': aes256CbcDecryptMbps,
    'aes128_gcm_encrypt_mbps': aes128GcmEncryptMbps,
    'aes128_gcm_decrypt_mbps': aes128GcmDecryptMbps,
    'aes256_gcm_encrypt_mbps': aes256GcmEncryptMbps,
    'aes256_gcm_decrypt_mbps': aes256GcmDecryptMbps,
    'rsa_2048_keygen_ops_per_min': rsa2048KeygenOpsPerMin,
    'rsa_4096_keygen_ops_per_min': rsa4096KeygenOpsPerMin,
    'ec_prime256v1_keygen_ops_per_min': ecPrime256v1KeygenOpsPerMin,
    'ec_secp384r1_keygen_ops_per_min': ecSecp384r1KeygenOpsPerMin,
    'ec_secp521r1_keygen_ops_per_min': ecSecp521r1KeygenOpsPerMin,
    'rsa_sign_per_sec': rsaSignPerSec,
    'rsa_verify_per_sec': rsaVerifyPerSec,
    'ec_sign_per_sec': ecSignPerSec,
    'ec_verify_per_sec': ecVerifyPerSec,
    'total_bytes_processed': totalBytesProcessed,
  };

  factory ThroughputMetrics.fromJson(Map<String, dynamic> json) {
    return ThroughputMetrics(
      sha256Mbps: (json['sha256_mbps'] as num).toDouble(),
      sha384Mbps: (json['sha384_mbps'] as num).toDouble(),
      sha512Mbps: (json['sha512_mbps'] as num).toDouble(),
      sha3_256Mbps: (json['sha3_256_mbps'] as num).toDouble(),
      sha3_512Mbps: (json['sha3_512_mbps'] as num).toDouble(),
      aes128CbcEncryptMbps: (json['aes128_cbc_encrypt_mbps'] as num).toDouble(),
      aes128CbcDecryptMbps: (json['aes128_cbc_decrypt_mbps'] as num).toDouble(),
      aes256CbcEncryptMbps: (json['aes256_cbc_encrypt_mbps'] as num).toDouble(),
      aes256CbcDecryptMbps: (json['aes256_cbc_decrypt_mbps'] as num).toDouble(),
      aes128GcmEncryptMbps: (json['aes128_gcm_encrypt_mbps'] as num).toDouble(),
      aes128GcmDecryptMbps: (json['aes128_gcm_decrypt_mbps'] as num).toDouble(),
      aes256GcmEncryptMbps: (json['aes256_gcm_encrypt_mbps'] as num).toDouble(),
      aes256GcmDecryptMbps: (json['aes256_gcm_decrypt_mbps'] as num).toDouble(),
      rsa2048KeygenOpsPerMin: (json['rsa_2048_keygen_ops_per_min'] as num)
          .toDouble(),
      rsa4096KeygenOpsPerMin: (json['rsa_4096_keygen_ops_per_min'] as num)
          .toDouble(),
      ecPrime256v1KeygenOpsPerMin:
          (json['ec_prime256v1_keygen_ops_per_min'] as num).toDouble(),
      ecSecp384r1KeygenOpsPerMin:
          (json['ec_secp384r1_keygen_ops_per_min'] as num).toDouble(),
      ecSecp521r1KeygenOpsPerMin:
          (json['ec_secp521r1_keygen_ops_per_min'] as num).toDouble(),
      rsaSignPerSec: (json['rsa_sign_per_sec'] as num).toDouble(),
      rsaVerifyPerSec: (json['rsa_verify_per_sec'] as num).toDouble(),
      ecSignPerSec: (json['ec_sign_per_sec'] as num).toDouble(),
      ecVerifyPerSec: (json['ec_verify_per_sec'] as num).toDouble(),
      totalBytesProcessed: json['total_bytes_processed'] as int,
    );
  }
}


class SafeCurveChecklist {
  final String curveName;
  final int fieldSizeBits;
  final bool hasPrimeOrder;
  final bool cofactorIsOne;
  final int embeddingDegree;
  final bool embeddingDegreeSafe;
  final bool twistSecure;
  final bool twistOrderChecked;
  final String notes;

  const SafeCurveChecklist({
    required this.curveName,
    required this.fieldSizeBits,
    required this.hasPrimeOrder,
    required this.cofactorIsOne,
    required this.embeddingDegree,
    required this.embeddingDegreeSafe,
    required this.twistSecure,
    required this.twistOrderChecked,
    required this.notes,
  });

  Map<String, dynamic> toJson() => {
    'curve_name': curveName,
    'field_size_bits': fieldSizeBits,
    'has_prime_order': hasPrimeOrder,
    'cofactor_is_one': cofactorIsOne,
    'embedding_degree': embeddingDegree,
    'embedding_degree_safe': embeddingDegreeSafe,
    'twist_secure': twistSecure,
    'twist_order_checked': twistOrderChecked,
    'notes': notes,
  };

  factory SafeCurveChecklist.fromJson(Map<String, dynamic> json) {
    return SafeCurveChecklist(
      curveName: json['curve_name'] as String,
      fieldSizeBits: json['field_size_bits'] as int,
      hasPrimeOrder: json['has_prime_order'] as bool,
      cofactorIsOne: json['cofactor_is_one'] as bool,
      embeddingDegree: json['embedding_degree'] as int,
      embeddingDegreeSafe: json['embedding_degree_safe'] as bool,
      twistSecure: json['twist_secure'] as bool,
      twistOrderChecked: json['twist_order_checked'] as bool,
      notes: json['notes'] as String,
    );
  }
}

/// Security property validation results.
class SecurityMetrics {
  /// Shannon entropy (bits per byte) of randomBytes(1024). Expect > 7.9.
  final double entropyRandomBytes1024;

  /// Whether entropy check passed.
  final bool entropyPassed;

  /// Chi-squared statistic against uniform distribution.
  final double chiSquared;

  /// P-value for the chi-squared test. Pass > 0.01.
  final double chiSquaredPValue;

  /// Whether chi-squared test passed.
  final bool chiSquaredPassed;

  /// Fraction of unique RSA public keys from 100 keygens.
  final double rsaKeyUniquenessRate;

  /// Fraction of unique EC public keys from 100 keygens.
  final double ecKeyUniquenessRate;

  /// Whether RSA signatures are nondeterministic.
  final bool signatureNondeterminismRsa;

  /// Whether ECDSA signatures are nondeterministic.
  final bool signatureNondeterminismEcdsa;

  /// Fraction of unique IVs from 100 AES-GCM encrypts.
  final double ivUniquenessRate;

  /// Whether GCM tag authentication is enforced.
  final bool gcmTagAuthEnforced;

  /// Whether GCM AAD binding is enforced.
  final bool gcmAadBindingEnforced;

  /// Whether cross-key rejection works (A signs, B verifies → false).
  final bool crossKeyRejection;

  /// Human-readable summary of security posture.
  final String summary;

  /// SafeCurve checklist results for NIST P-256, P-384, P-521.
  final List<SafeCurveChecklist> safeCurveChecklist;

  /// Resumos KAT (Known Answer Test) por algoritmo.
  final List<KatSummary> katSummaries;

  const SecurityMetrics({
    required this.entropyRandomBytes1024,
    required this.entropyPassed,
    required this.chiSquared,
    required this.chiSquaredPValue,
    required this.chiSquaredPassed,
    required this.rsaKeyUniquenessRate,
    required this.ecKeyUniquenessRate,
    required this.signatureNondeterminismRsa,
    required this.signatureNondeterminismEcdsa,
    required this.ivUniquenessRate,
    required this.gcmTagAuthEnforced,
    required this.gcmAadBindingEnforced,
    required this.crossKeyRejection,
    required this.summary,
    this.safeCurveChecklist = const [],
    this.katSummaries = const [],
  });

  Map<String, dynamic> toJson() => {
    'entropy_random_bytes_1024': entropyRandomBytes1024,
    'entropy_passed': entropyPassed,
    'chi_squared': chiSquared,
    'chi_squared_p_value': chiSquaredPValue,
    'chi_squared_passed': chiSquaredPassed,
    'rsa_key_uniqueness_rate': rsaKeyUniquenessRate,
    'ec_key_uniqueness_rate': ecKeyUniquenessRate,
    'signature_nondeterminism_rsa': signatureNondeterminismRsa,
    'signature_nondeterminism_ecdsa': signatureNondeterminismEcdsa,
    'iv_uniqueness_rate': ivUniquenessRate,
    'gcm_tag_auth_enforced': gcmTagAuthEnforced,
    'gcm_aad_binding_enforced': gcmAadBindingEnforced,
    'cross_key_rejection': crossKeyRejection,
    'summary': summary,
    'safe_curve_checklist': safeCurveChecklist.map((e) => e.toJson()).toList(),
    'kat_summaries': katSummaries.map((e) => e.toJson()).toList(),
  };

  factory SecurityMetrics.fromJson(Map<String, dynamic> json) {
    return SecurityMetrics(
      entropyRandomBytes1024: (json['entropy_random_bytes_1024'] as num)
          .toDouble(),
      entropyPassed: json['entropy_passed'] as bool,
      chiSquared: (json['chi_squared'] as num).toDouble(),
      chiSquaredPValue: (json['chi_squared_p_value'] as num).toDouble(),
      chiSquaredPassed: json['chi_squared_passed'] as bool,
      rsaKeyUniquenessRate: (json['rsa_key_uniqueness_rate'] as num).toDouble(),
      ecKeyUniquenessRate: (json['ec_key_uniqueness_rate'] as num).toDouble(),
      signatureNondeterminismRsa: json['signature_nondeterminism_rsa'] as bool,
      signatureNondeterminismEcdsa:
          json['signature_nondeterminism_ecdsa'] as bool,
      ivUniquenessRate: (json['iv_uniqueness_rate'] as num).toDouble(),
      gcmTagAuthEnforced: json['gcm_tag_auth_enforced'] as bool,
      gcmAadBindingEnforced: json['gcm_aad_binding_enforced'] as bool,
      crossKeyRejection: json['cross_key_rejection'] as bool,
      summary: json['summary'] as String,
      safeCurveChecklist:
          (json['safe_curve_checklist'] as List<dynamic>?)
              ?.map(
                (e) => SafeCurveChecklist.fromJson(e as Map<String, dynamic>),
              )
              .toList() ??
          const [],
      katSummaries:
          (json['kat_summaries'] as List<dynamic>?)
              ?.map((e) => KatSummary.fromJson(e as Map<String, dynamic>))
              .toList() ??
          const [],
    );
  }
}


class ConstantTimeResult {
  /// The operation name (e.g. "sha256", "aes128CbcEncrypt").
  final String operation;

  /// Number of iterations measured.
  final int iterations;

  /// Mean execution time in milliseconds.
  final double meanMs;

  /// Population standard deviation in milliseconds.
  final double stddevMs;

  /// Coefficient of variation: (stddev / mean) * 100.
  final double cvPercent;

  /// Minimum execution time in milliseconds.
  final double minMs;

  /// Maximum execution time in milliseconds.
  final double maxMs;

  /// max/min ratio. Values near 1.0 indicate uniform timing.
  final double maxMinRatio;

  /// p95/min ratio. Captures tail behavior.
  final double p95MinRatio;

  /// Whether timing analysis suggests constant-time execution.
  /// True when cvPercent < 5.0 AND maxMinRatio < 2.0.
  final bool likelyConstantTime;

  /// Human-readable interpretation of the analysis.
  final String evidence;

  const ConstantTimeResult({
    required this.operation,
    required this.iterations,
    required this.meanMs,
    required this.stddevMs,
    required this.cvPercent,
    required this.minMs,
    required this.maxMs,
    required this.maxMinRatio,
    required this.p95MinRatio,
    required this.likelyConstantTime,
    required this.evidence,
  });

  Map<String, dynamic> toJson() => {
    'operation': operation,
    'iterations': iterations,
    'mean_ms': meanMs,
    'stddev_ms': stddevMs,
    'cv_percent': cvPercent,
    'min_ms': minMs,
    'max_ms': maxMs,
    'max_min_ratio': maxMinRatio,
    'p95_min_ratio': p95MinRatio,
    'likely_constant_time': likelyConstantTime,
    'evidence': evidence,
  };

  factory ConstantTimeResult.fromJson(Map<String, dynamic> json) {
    return ConstantTimeResult(
      operation: json['operation'] as String,
      iterations: json['iterations'] as int,
      meanMs: (json['mean_ms'] as num).toDouble(),
      stddevMs: (json['stddev_ms'] as num).toDouble(),
      cvPercent: (json['cv_percent'] as num).toDouble(),
      minMs: (json['min_ms'] as num).toDouble(),
      maxMs: (json['max_ms'] as num).toDouble(),
      maxMinRatio: (json['max_min_ratio'] as num).toDouble(),
      p95MinRatio: (json['p95_min_ratio'] as num).toDouble(),
      likelyConstantTime: json['likely_constant_time'] as bool,
      evidence: json['evidence'] as String,
    );
  }
}


class KatSummary {
  final String standard;
  final String algorithm;
  final int vectorsTested;
  final int vectorsPassed;
  final int vectorsFailed;
  final double passRate;
  final bool allPassed;
  final String details;

  const KatSummary({
    required this.standard,
    required this.algorithm,
    required this.vectorsTested,
    required this.vectorsPassed,
    required this.vectorsFailed,
    required this.passRate,
    required this.allPassed,
    required this.details,
  });

  Map<String, dynamic> toJson() => {
    'standard': standard,
    'algorithm': algorithm,
    'vectors_tested': vectorsTested,
    'vectors_passed': vectorsPassed,
    'vectors_failed': vectorsFailed,
    'pass_rate': passRate,
    'all_passed': allPassed,
    'details': details,
  };

  factory KatSummary.fromJson(Map<String, dynamic> json) {
    return KatSummary(
      standard: json['standard'] as String,
      algorithm: json['algorithm'] as String,
      vectorsTested: json['vectors_tested'] as int,
      vectorsPassed: json['vectors_passed'] as int,
      vectorsFailed: json['vectors_failed'] as int,
      passRate: (json['pass_rate'] as num).toDouble(),
      allPassed: json['all_passed'] as bool,
      details: json['details'] as String,
    );
  }
}


/// Aggregate result of constant-time analysis across multiple operations.
class ConstantTimeMetrics {
  final List<ConstantTimeResult> results;
  final String summary;

  const ConstantTimeMetrics({required this.results, required this.summary});

  Map<String, dynamic> toJson() => {
    'results': results.map((e) => e.toJson()).toList(),
    'summary': summary,
  };

  factory ConstantTimeMetrics.fromJson(Map<String, dynamic> json) {
    return ConstantTimeMetrics(
      results: (json['results'] as List<dynamic>)
          .map((e) => ConstantTimeResult.fromJson(e as Map<String, dynamic>))
          .toList(),
      summary: json['summary'] as String,
    );
  }
}


/// Verification results for memory zeroization / secure cleanup.
class ZeroizationMetrics {
  /// `verified`, `failed`, or `unavailable`.
  final String verificationStatus;
  /// Memory covered by this evidence. Dart caller-owned memory is excluded.
  final String scope;
  final bool keyMaterialWipedAfterFree;
  final bool intermediateBuffersCleared;
  final bool opensslCleanseVerified;
  final bool cryptoFreeVerified;
  final bool fipsProviderActive;
  final String evidence;
  final String methodology;

  const ZeroizationMetrics({
    required this.verificationStatus,
    required this.scope,
    required this.keyMaterialWipedAfterFree,
    required this.intermediateBuffersCleared,
    required this.opensslCleanseVerified,
    required this.cryptoFreeVerified,
    required this.fipsProviderActive,
    required this.evidence,
    required this.methodology,
  });

  Map<String, dynamic> toJson() => {
    'verification_status': verificationStatus,
    'scope': scope,
    'key_material_wiped_after_free': keyMaterialWipedAfterFree,
    'intermediate_buffers_cleared': intermediateBuffersCleared,
    'openssl_cleanse_verified': opensslCleanseVerified,
    'crypto_free_verified': cryptoFreeVerified,
    'fips_provider_active': fipsProviderActive,
    'evidence': evidence,
    'methodology': methodology,
  };

  factory ZeroizationMetrics.fromJson(Map<String, dynamic> json) {
    return ZeroizationMetrics(
      verificationStatus:
          json['verification_status'] as String? ?? 'unavailable',
      scope: json['scope'] as String? ?? 'legacy-unspecified',
      keyMaterialWipedAfterFree: json['key_material_wiped_after_free'] as bool,
      intermediateBuffersCleared: json['intermediate_buffers_cleared'] as bool,
      opensslCleanseVerified: json['openssl_cleanse_verified'] as bool,
      cryptoFreeVerified: json['crypto_free_verified'] as bool,
      fipsProviderActive: json['fips_provider_active'] as bool? ?? false,
      evidence: json['evidence'] as String,
      methodology: json['methodology'] as String,
    );
  }
}


/// Results from fuzzing and edge-case input testing.
class FuzzingMetrics {
  final int malformedPayloadsTested;
  final int malformedPayloadsSafelyRejected;
  final int zeroLengthInputsTested;
  final int zeroLengthInputsSafelyHandled;
  final int massivePayloadsTested;
  final int massivePayloadsSafelyHandled;
  final int nullPointerTests;
  final int nullPointerSafelyHandled;
  final int totalEdgeCases;
  final int safelyRejected;
  final double rejectionRate;
  final String summary;

  const FuzzingMetrics({
    required this.malformedPayloadsTested,
    required this.malformedPayloadsSafelyRejected,
    required this.zeroLengthInputsTested,
    required this.zeroLengthInputsSafelyHandled,
    required this.massivePayloadsTested,
    required this.massivePayloadsSafelyHandled,
    required this.nullPointerTests,
    required this.nullPointerSafelyHandled,
    required this.totalEdgeCases,
    required this.safelyRejected,
    required this.rejectionRate,
    required this.summary,
  });

  Map<String, dynamic> toJson() => {
    'malformed_payloads_tested': malformedPayloadsTested,
    'malformed_payloads_safely_rejected': malformedPayloadsSafelyRejected,
    'zero_length_inputs_tested': zeroLengthInputsTested,
    'zero_length_inputs_safely_handled': zeroLengthInputsSafelyHandled,
    'massive_payloads_tested': massivePayloadsTested,
    'massive_payloads_safely_handled': massivePayloadsSafelyHandled,
    'null_pointer_tests': nullPointerTests,
    'null_pointer_safely_handled': nullPointerSafelyHandled,
    'total_edge_cases': totalEdgeCases,
    'safely_rejected': safelyRejected,
    'rejection_rate': rejectionRate,
    'summary': summary,
  };

  factory FuzzingMetrics.fromJson(Map<String, dynamic> json) {
    return FuzzingMetrics(
      malformedPayloadsTested: json['malformed_payloads_tested'] as int,
      malformedPayloadsSafelyRejected:
          json['malformed_payloads_safely_rejected'] as int,
      zeroLengthInputsTested: json['zero_length_inputs_tested'] as int,
      zeroLengthInputsSafelyHandled:
          json['zero_length_inputs_safely_handled'] as int,
      massivePayloadsTested: json['massive_payloads_tested'] as int,
      massivePayloadsSafelyHandled:
          json['massive_payloads_safely_handled'] as int,
      nullPointerTests: json['null_pointer_tests'] as int,
      nullPointerSafelyHandled: json['null_pointer_safely_handled'] as int,
      totalEdgeCases: json['total_edge_cases'] as int,
      safelyRejected: json['safely_rejected'] as int,
      rejectionRate: (json['rejection_rate'] as num).toDouble(),
      summary: json['summary'] as String,
    );
  }
}


/// Throughput measurement for a specific isolate count.
class IsolateScalingPoint {
  /// `measured` or `failed`; synthetic values are never emitted.
  final String status;
  final String measurementSource;
  final String? error;
  final int isolateCount;
  final double totalThroughputMbps;
  final double throughputPerIsolateMbps;
  final double scalingEfficiency;
  final double totalSuiteMs;

  const IsolateScalingPoint({
    this.status = 'measured',
    this.measurementSource = 'plugin_crypto_native',
    this.error,
    required this.isolateCount,
    required this.totalThroughputMbps,
    required this.throughputPerIsolateMbps,
    required this.scalingEfficiency,
    required this.totalSuiteMs,
  });

  Map<String, dynamic> toJson() => {
    'status': status,
    'measurement_source': measurementSource,
    if (error != null) 'error': error,
    'isolate_count': isolateCount,
    'total_throughput_mbps': totalThroughputMbps,
    'throughput_per_isolate_mbps': throughputPerIsolateMbps,
    'scaling_efficiency': scalingEfficiency,
    'total_suite_ms': totalSuiteMs,
  };

  factory IsolateScalingPoint.fromJson(Map<String, dynamic> json) {
    return IsolateScalingPoint(
      status: json['status'] as String? ?? 'measured',
      measurementSource:
          json['measurement_source'] as String? ?? 'legacy-unspecified',
      error: json['error'] as String?,
      isolateCount: json['isolate_count'] as int,
      totalThroughputMbps: (json['total_throughput_mbps'] as num).toDouble(),
      throughputPerIsolateMbps: (json['throughput_per_isolate_mbps'] as num)
          .toDouble(),
      scalingEfficiency: (json['scaling_efficiency'] as num).toDouble(),
      totalSuiteMs: (json['total_suite_ms'] as num).toDouble(),
    );
  }
}


/// Aggregate concurrency scaling metrics across all isolate counts.
class ConcurrencyMetrics {
  final int availableCores;
  final List<IsolateScalingPoint> scalingPoints;

  const ConcurrencyMetrics({
    required this.availableCores,
    required this.scalingPoints,
  });

  Map<String, dynamic> toJson() => {
    'available_cores': availableCores,
    'scaling_points': scalingPoints.map((e) => e.toJson()).toList(),
  };

  factory ConcurrencyMetrics.fromJson(Map<String, dynamic> json) {
    return ConcurrencyMetrics(
      availableCores: json['available_cores'] as int,
      scalingPoints: (json['scaling_points'] as List<dynamic>)
          .map((e) => IsolateScalingPoint.fromJson(e as Map<String, dynamic>))
          .toList(),
    );
  }
}


/// A single test result record.
class TestResult {
  final String name;
  final String status; // 'passed', 'failed', 'skipped'
  final int durationMs;

  const TestResult({
    required this.name,
    required this.status,
    required this.durationMs,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    'status': status,
    'duration_ms': durationMs,
  };

  factory TestResult.fromJson(Map<String, dynamic> json) {
    return TestResult(
      name: json['name'] as String,
      status: json['status'] as String,
      durationMs: json['duration_ms'] as int,
    );
  }
}

/// Suite-level resource metrics and platform information.
class ResourceMetrics {
  final double totalSuiteTimeMs;
  final Map<String, double> perZoneDurationMs;
  final List<TestResult> slowestTests;
  final List<TestResult> fastestTests;
  final int totalTestsRun;
  final int totalTestsPassed;
  final int totalTestsFailed;
  final int totalTestsSkipped;
  final double nativeLoadTimeMs;
  final String openSslVersion;
  final String dartVersion;
  final String platformOs;
  final int processorCount;
  final String ldLibraryPath;

  const ResourceMetrics({
    required this.totalSuiteTimeMs,
    required this.perZoneDurationMs,
    required this.slowestTests,
    required this.fastestTests,
    required this.totalTestsRun,
    required this.totalTestsPassed,
    required this.totalTestsFailed,
    required this.totalTestsSkipped,
    required this.nativeLoadTimeMs,
    required this.openSslVersion,
    required this.dartVersion,
    required this.platformOs,
    required this.processorCount,
    required this.ldLibraryPath,
  });

  Map<String, dynamic> toJson() => {
    'total_suite_time_ms': totalSuiteTimeMs,
    'per_zone_duration_ms': perZoneDurationMs,
    'slowest_tests': slowestTests.map((e) => e.toJson()).toList(),
    'fastest_tests': fastestTests.map((e) => e.toJson()).toList(),
    'total_tests_run': totalTestsRun,
    'total_tests_passed': totalTestsPassed,
    'total_tests_failed': totalTestsFailed,
    'total_tests_skipped': totalTestsSkipped,
    'native_load_time_ms': nativeLoadTimeMs,
    'open_ssl_version': openSslVersion,
    'dart_version': dartVersion,
    'platform_os': platformOs,
    'processor_count': processorCount,
    'ld_library_path': ldLibraryPath,
  };

  factory ResourceMetrics.fromJson(Map<String, dynamic> json) {
    return ResourceMetrics(
      totalSuiteTimeMs: (json['total_suite_time_ms'] as num).toDouble(),
      perZoneDurationMs: Map<String, double>.from(
        json['per_zone_duration_ms'] as Map,
      ),
      slowestTests: (json['slowest_tests'] as List<dynamic>)
          .map((e) => TestResult.fromJson(e as Map<String, dynamic>))
          .toList(),
      fastestTests: (json['fastest_tests'] as List<dynamic>)
          .map((e) => TestResult.fromJson(e as Map<String, dynamic>))
          .toList(),
      totalTestsRun: json['total_tests_run'] as int,
      totalTestsPassed: json['total_tests_passed'] as int,
      totalTestsFailed: json['total_tests_failed'] as int,
      totalTestsSkipped: json['total_tests_skipped'] as int,
      nativeLoadTimeMs: (json['native_load_time_ms'] as num).toDouble(),
      openSslVersion: json['open_ssl_version'] as String,
      dartVersion: json['dart_version'] as String,
      platformOs: json['platform_os'] as String,
      processorCount: json['processor_count'] as int,
      ldLibraryPath: json['ld_library_path'] as String,
    );
  }
}


/// Per-file line coverage data.
class FileCoverage {
  final String filePath;
  final int totalLines;
  final int coveredLines;
  final double coveragePct;

  const FileCoverage({
    required this.filePath,
    required this.totalLines,
    required this.coveredLines,
    required this.coveragePct,
  });

  Map<String, dynamic> toJson() => {
    'file_path': filePath,
    'total_lines': totalLines,
    'covered_lines': coveredLines,
    'coverage_pct': coveragePct,
  };

  factory FileCoverage.fromJson(Map<String, dynamic> json) {
    return FileCoverage(
      filePath: json['file_path'] as String,
      totalLines: json['total_lines'] as int,
      coveredLines: json['covered_lines'] as int,
      coveragePct: (json['coverage_pct'] as num).toDouble(),
    );
  }
}

/// Code coverage metrics parsed from lcov.info.
class CoverageMetrics {
  final bool coverageAvailable;
  final double overallLineCoveragePct;
  final List<FileCoverage> perFile;
  final int filesAbove80Pct;
  final int filesBelow50Pct;
  final int apiMethodsTotal;
  final int apiMethodsTested;
  final int ffiBindingsTotal;
  final int ffiBindingsExercised;
  final String notes;

  const CoverageMetrics({
    required this.coverageAvailable,
    required this.overallLineCoveragePct,
    required this.perFile,
    required this.filesAbove80Pct,
    required this.filesBelow50Pct,
    required this.apiMethodsTotal,
    required this.apiMethodsTested,
    required this.ffiBindingsTotal,
    required this.ffiBindingsExercised,
    required this.notes,
  });

  Map<String, dynamic> toJson() => {
    'coverage_available': coverageAvailable,
    'overall_line_coverage_pct': overallLineCoveragePct,
    'per_file': perFile.map((e) => e.toJson()).toList(),
    'files_above_80pct': filesAbove80Pct,
    'files_below_50pct': filesBelow50Pct,
    'api_methods_total': apiMethodsTotal,
    'api_methods_tested': apiMethodsTested,
    'ffi_bindings_total': ffiBindingsTotal,
    'ffi_bindings_exercised': ffiBindingsExercised,
    'notes': notes,
  };

  factory CoverageMetrics.fromJson(Map<String, dynamic> json) {
    return CoverageMetrics(
      coverageAvailable: json['coverage_available'] as bool,
      overallLineCoveragePct: (json['overall_line_coverage_pct'] as num)
          .toDouble(),
      perFile: (json['per_file'] as List<dynamic>)
          .map((e) => FileCoverage.fromJson(e as Map<String, dynamic>))
          .toList(),
      filesAbove80Pct: json['files_above_80pct'] as int,
      filesBelow50Pct: json['files_below_50pct'] as int,
      apiMethodsTotal: json['api_methods_total'] as int,
      apiMethodsTested: json['api_methods_tested'] as int,
      ffiBindingsTotal: json['ffi_bindings_total'] as int,
      ffiBindingsExercised: json['ffi_bindings_exercised'] as int,
      notes: json['notes'] as String,
    );
  }
}


class MetricsReport {
  final String schemaVersion;
  final String generatedAt;
  final String projectName;
  final TimingMetrics timing;
  final MemoryMetrics memory;
  final ThroughputMetrics throughput;
  final SecurityMetrics security;
  final ResourceMetrics resource;
  final CoverageMetrics coverage;
  final CipherSuiteComparisonMetrics? cipherSuiteComparison;
  final TlsSimulationMetrics? tlsSimulation;
  final ConstantTimeMetrics? constantTime;
  final ZeroizationMetrics? zeroization;
  final FuzzingMetrics? fuzzing;
  final ConcurrencyMetrics? concurrency;

  const MetricsReport({
    required this.schemaVersion,
    required this.generatedAt,
    required this.projectName,
    required this.timing,
    required this.memory,
    required this.throughput,
    required this.security,
    required this.resource,
    required this.coverage,
    this.cipherSuiteComparison,
    this.tlsSimulation,
    this.constantTime,
    this.zeroization,
    this.fuzzing,
    this.concurrency,
  });

  Map<String, dynamic> toJson() => {
    'schema_version': schemaVersion,
    'generated_at': generatedAt,
    'project_name': projectName,
    'timing': timing.toJson(),
    'memory': memory.toJson(),
    'throughput': throughput.toJson(),
    'security': security.toJson(),
    'resource': resource.toJson(),
    'coverage': coverage.toJson(),
    if (cipherSuiteComparison != null)
      'cipher_suite_comparison': cipherSuiteComparison!.toJson(),
    if (tlsSimulation != null) 'tls_simulation': tlsSimulation!.toJson(),
    if (constantTime != null) 'constant_time': constantTime!.toJson(),
    if (zeroization != null) 'zeroization': zeroization!.toJson(),
    if (fuzzing != null) 'fuzzing': fuzzing!.toJson(),
    if (concurrency != null) 'concurrency': concurrency!.toJson(),
  };

  factory MetricsReport.fromJson(Map<String, dynamic> json) {
    return MetricsReport(
      schemaVersion: json['schema_version'] as String,
      generatedAt: json['generated_at'] as String,
      projectName: json['project_name'] as String,
      timing: TimingMetrics.fromJson(json['timing'] as Map<String, dynamic>),
      memory: MemoryMetrics.fromJson(json['memory'] as Map<String, dynamic>),
      throughput: ThroughputMetrics.fromJson(
        json['throughput'] as Map<String, dynamic>,
      ),
      security: SecurityMetrics.fromJson(
        json['security'] as Map<String, dynamic>,
      ),
      resource: ResourceMetrics.fromJson(
        json['resource'] as Map<String, dynamic>,
      ),
      coverage: CoverageMetrics.fromJson(
        json['coverage'] as Map<String, dynamic>,
      ),
      cipherSuiteComparison: json['cipher_suite_comparison'] != null
          ? CipherSuiteComparisonMetrics.fromJson(
              json['cipher_suite_comparison'] as Map<String, dynamic>,
            )
          : null,
      tlsSimulation: json['tls_simulation'] != null
          ? TlsSimulationMetrics.fromJson(
              json['tls_simulation'] as Map<String, dynamic>,
            )
          : null,
      constantTime: json['constant_time'] != null
          ? ConstantTimeMetrics.fromJson(
              json['constant_time'] as Map<String, dynamic>,
            )
          : null,
      zeroization: json['zeroization'] != null
          ? ZeroizationMetrics.fromJson(
              json['zeroization'] as Map<String, dynamic>,
            )
          : null,
      fuzzing: json['fuzzing'] != null
          ? FuzzingMetrics.fromJson(json['fuzzing'] as Map<String, dynamic>)
          : null,
      concurrency: json['concurrency'] != null
          ? ConcurrencyMetrics.fromJson(
              json['concurrency'] as Map<String, dynamic>,
            )
          : null,
    );
  }
}
