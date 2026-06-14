library;

import 'metrics_models.dart';

const double _maxTheoreticalMbps = 10000;

const double _minMeasurableMs = 0.0005;

double computeMbps(int bytes, double ms) {
  if (ms < _minMeasurableMs || bytes <= 0) return 0.0;
  final raw = (bytes / (1024 * 1024)) / (ms / 1000);
  return raw.clamp(0.0, _maxTheoreticalMbps);
}

double computeOpsPerSec(double ms) {
  if (ms < _minMeasurableMs) return 0.0;
  return 1000.0 / ms;
}

double computeOpsPerMin(double ms) {
  if (ms < _minMeasurableMs) return 0.0;
  return 60000.0 / ms;
}

double extractMbPs(String operation, List<OperationTiming> timings) {
  final candidates = timings.where(
    (t) => t.operation == operation && t.inputSizeBytes >= 1048576,
  );
  if (candidates.isNotEmpty) {
    final best = candidates.reduce(
      (a, b) => a.inputSizeBytes > b.inputSizeBytes ? a : b,
    );
    return best.throughputMbps;
  }
  return 0.0;
}

/// Build [ThroughputMetrics] from a flat list of [OperationTiming] records
/// and a total bytes-processed count.
ThroughputMetrics buildThroughputMetrics(
  List<OperationTiming> timings,
  int totalBytesProcessed,
) {
  double mbps(String op) => extractMbPs(op, timings);
  double keygenOpM(String op) {
    final t = timings.where((e) => e.operation == op);
    if (t.isEmpty) return 0.0;
    return computeOpsPerMin(t.first.coldMs);
  }

  double signOpS(String op) {
    final t = timings.where((e) => e.operation == op);
    if (t.isEmpty) return 0.0;
    return computeOpsPerSec(t.first.warmMs);
  }

  return ThroughputMetrics(
    sha256Mbps: mbps('sha256'),
    sha384Mbps: mbps('sha384'),
    sha512Mbps: mbps('sha512'),
    sha3_256Mbps: mbps('sha3_256'),
    sha3_512Mbps: mbps('sha3_512'),
    aes128CbcEncryptMbps: mbps('aes128CbcEncrypt'),
    aes128CbcDecryptMbps: mbps('aes128CbcDecrypt'),
    aes256CbcEncryptMbps: mbps('aes256CbcEncrypt'),
    aes256CbcDecryptMbps: mbps('aes256CbcDecrypt'),
    aes128GcmEncryptMbps: mbps('aes128GcmEncrypt'),
    aes128GcmDecryptMbps: mbps('aes128GcmDecrypt'),
    aes256GcmEncryptMbps: mbps('aes256GcmEncrypt'),
    aes256GcmDecryptMbps: mbps('aes256GcmDecrypt'),
    rsa2048KeygenOpsPerMin: keygenOpM('generateRsaKeyPair_2048'),
    rsa4096KeygenOpsPerMin: keygenOpM('generateRsaKeyPair_4096'),
    ecPrime256v1KeygenOpsPerMin: keygenOpM('generateEcKeyPair_prime256v1'),
    ecSecp384r1KeygenOpsPerMin: keygenOpM('generateEcKeyPair_secp384r1'),
    ecSecp521r1KeygenOpsPerMin: keygenOpM('generateEcKeyPair_secp521r1'),
    rsaSignPerSec: signOpS('rsaSign_sha256'),
    rsaVerifyPerSec: signOpS('rsaVerify_sha256'),
    ecSignPerSec: signOpS('ecSign_prime256v1'),
    ecVerifyPerSec: signOpS('ecVerify_prime256v1'),
    totalBytesProcessed: totalBytesProcessed,
  );
}
