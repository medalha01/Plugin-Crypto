library;

import 'dart:math';

import 'metrics_models.dart';

/// Analyzes per-iteration timing data for evidence of constant-time execution.
class ConstantTimeAnalyzer {
  static ConstantTimeResult analyze(
    List<double> perIterationTimes,
    String operation,
  ) {
    if (perIterationTimes.isEmpty) {
      return ConstantTimeResult(
        operation: operation,
        iterations: 0,
        meanMs: 0,
        stddevMs: 0,
        cvPercent: 0,
        minMs: 0,
        maxMs: 0,
        maxMinRatio: 0,
        p95MinRatio: 0,
        likelyConstantTime: false,
        evidence: 'No timing data collected for $operation.',
      );
    }

    final sorted = List<double>.from(perIterationTimes)..sort();
    final n = sorted.length;
    final min = sorted.first;
    final max = sorted.last;

    final trimCount = (n * 0.01).ceil();
    final trimmed = sorted.sublist(trimCount, n - trimCount);
    final tn = trimmed.length;

    final sum = trimmed.fold<double>(0, (a, b) => a + b);
    final mean = sum / tn;
    final variance =
        trimmed.fold<double>(0, (a, b) => a + (b - mean) * (b - mean)) / tn;
    final stddev = sqrt(variance);
    final cvPercent = mean > 0 ? (stddev / mean) * 100.0 : 0.0;

    final p1 = _percentile(sorted, 0.01);
    final p99 = _percentile(sorted, 0.99);
    final p99P1Ratio = p1 > 0 ? p99 / p1 : 0.0;

    final p95 = _percentile(sorted, 0.95);
    final p95MinRatio = min > 0 ? p95 / min : 0.0;

    final likelyConstantTime = cvPercent < 15.0 && p99P1Ratio < 8.0;

    final evidence = likelyConstantTime
        ? 'CV(trimmed)=${cvPercent.toStringAsFixed(1)}%, p99/p1=${p99P1Ratio.toStringAsFixed(2)}'
        : 'CV(trimmed)=${cvPercent.toStringAsFixed(1)}%, p99/p1=${p99P1Ratio.toStringAsFixed(2)} — varies, possible side-channel';

    return ConstantTimeResult(
      operation: operation,
      iterations: n,
      meanMs: mean,
      stddevMs: stddev,
      cvPercent: cvPercent,
      minMs: min,
      maxMs: max,
      maxMinRatio: p99P1Ratio,
      p95MinRatio: p95MinRatio,
      likelyConstantTime: likelyConstantTime,
      evidence: evidence,
    );
  }

  static double _percentile(List<double> sorted, double q) {
    final n = sorted.length;
    if (n == 1) return sorted[0];
    final h = (n - 1) * q;
    final lo = h.floor();
    final hi = h.ceil();
    final frac = h - lo;
    return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
  }
}
