library;

import 'dart:math';
import 'dart:typed_data';

double computeShannonEntropy(Uint8List data) {
  final counts = List<int>.filled(256, 0);
  for (final byte in data) {
    counts[byte]++;
  }
  final n = data.length;
  var entropy = 0.0;
  for (var i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      final p = counts[i] / n;
      entropy -= p * log(p) / ln2;
    }
  }
  return entropy;
}

ChiSquaredResult computeChiSquared(Uint8List data) {
  final counts = List<int>.filled(256, 0);
  for (final byte in data) {
    counts[byte]++;
  }
  final expected = data.length / 256.0;
  var chiSq = 0.0;
  for (var i = 0; i < 256; i++) {
    final diff = counts[i] - expected;
    chiSq += (diff * diff) / expected;
  }
  final df = 255.0;
  final z = (chiSq - df) / sqrt(2 * df);
  final pValue = 1.0 - _normalCdf(z);
  return ChiSquaredResult(chiSq, pValue);
}

/// Result of a chi-squared test.
class ChiSquaredResult {
  final double statistic;
  final double pValue;

  const ChiSquaredResult(this.statistic, this.pValue);

  /// Whether the test passed (p > 0.01).
  bool get passed => pValue > 0.01;
}

double checkUniqueness(List<Uint8List> samples) {
  final seen = <String>{};
  for (final s in samples) {
    seen.add(_bytesToKey(s));
  }
  return seen.length / samples.length;
}

bool checkSignatureNonDeterminism(Uint8List Function() signFn) {
  final sig1 = signFn();
  final sig2 = signFn();
  if (sig1.length != sig2.length) return true;
  for (var i = 0; i < sig1.length; i++) {
    if (sig1[i] != sig2[i]) return true;
  }
  return false;
}


const double ln2 = 0.6931471805599453;

String _bytesToKey(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Approximate standard normal CDF using Abramowitz & Stegun formula 7.1.26.
double _normalCdf(double x) {
  if (x < -8.0) return 0.0;
  if (x > 8.0) return 1.0;
  final t = 1.0 / (1.0 + 0.2316419 * x.abs());
  final d = 0.3989423 * exp(-x * x / 2);
  final p =
      d *
      t *
      (0.3193815 +
          t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  return x > 0 ? 1.0 - p : p;
}
