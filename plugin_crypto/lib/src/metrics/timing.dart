library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import '../metrics/metrics_models.dart';
import '../metrics/throughput.dart';

/// Resultado de uma medição de tempo de chamada fria (cold).
class ColdTimingResult {
  final double elapsedMs;

  const ColdTimingResult(this.elapsedMs);
}

/// Resultado de uma medição de tempo de chamada quente (warm).
class WarmTimingResult {
  final double meanMs;
  final double minMs;
  final double maxMs;
  final double throughputMbps;
  final int dataSizeBytes;
  final int iterations;

  final List<double>? iterationTimesMs;

  const WarmTimingResult({
    required this.meanMs,
    required this.minMs,
    required this.maxMs,
    required this.throughputMbps,
    required this.dataSizeBytes,
    required this.iterations,
    this.iterationTimesMs,
  });
}

class CryptoMicroBenchmark {
  final int _warmupIterations;

  final bool _collectPerIterationStats;

  final bool _collectRawSamples;

  /// Armazenamento para amostras individuais brutas de tempo coletadas durante a medição.
  final List<RawTimingSample> _rawSamples = [];

  /// Acesso somente leitura às amostras brutas de tempo coletadas durante a medição.
  List<RawTimingSample> get rawSamples => List.unmodifiable(_rawSamples);

  static const int _resolutionLimitUs = 1;

  static const int _minTotalTimeUs = 20;

  CryptoMicroBenchmark({
    int warmupIterations = 75,
    bool collectPerIterationStats = false,
    bool collectRawSamples = false,
  }) : _warmupIterations = warmupIterations,
       _collectPerIterationStats = collectPerIterationStats,
       _collectRawSamples = collectRawSamples;

  ColdTimingResult measureCold(
    String label,
    void Function() op, {
    int preWarmupCalls = 0,
    String category = '',
    int inputSizeBytes = 0,
  }) {
    for (var i = 0; i < preWarmupCalls; i++) {
      op();
    }
    _stabilizeHeap();
    final sw = Stopwatch()..start();
    op();
    sw.stop();
    final elapsedMs = sw.elapsedMicroseconds / 1000.0;
    if (_collectRawSamples) {
      _rawSamples.add(
        RawTimingSample(
          operation: label,
          category: category,
          inputSizeBytes: inputSizeBytes,
          phase: 'cold',
          sampleIndex: 0,
          elapsedMs: elapsedMs,
          isWarmup: false,
        ),
      );
    }
    return ColdTimingResult(elapsedMs);
  }

  WarmTimingResult measureWarm(
    String label,
    void Function() op, {
    required int dataSizeBytes,
    int iterations = 150,
    String category = '',
  }) {
    _stabilizeHeap();

    for (var i = 0; i < _warmupIterations; i++) {
      op();
    }

    final measuredCount = iterations - _warmupIterations;
    if (measuredCount <= 0) {
      final sw = Stopwatch()..start();
      for (var i = 0; i < iterations; i++) {
        op();
      }
      sw.stop();
      final mean = sw.elapsedMicroseconds / 1000.0 / iterations;
      final totalElapsedUs = sw.elapsedMicroseconds;
      if (_collectRawSamples) {
        for (var i = 0; i < iterations; i++) {
          _rawSamples.add(
            RawTimingSample(
              operation: label,
              category: category,
              inputSizeBytes: dataSizeBytes,
              phase: 'warm',
              sampleIndex: i,
              elapsedMs: mean,
              isWarmup: true,
            ),
          );
        }
      }
      return _buildResult(
        mean,
        dataSizeBytes,
        iterations,
        totalElapsedUs,
        label,
      );
    }

    if (_collectPerIterationStats) {
      return _measureWarmPerIteration(
        op,
        measuredCount,
        dataSizeBytes,
        label,
        category,
      );
    }

    final sw = Stopwatch()..start();
    for (var i = 0; i < measuredCount; i++) {
      op();
    }
    sw.stop();
    final mean = sw.elapsedMicroseconds / 1000.0 / measuredCount;
    final totalElapsedUs = sw.elapsedMicroseconds;
    if (_collectRawSamples) {
      for (var i = 0; i < measuredCount; i++) {
        _rawSamples.add(
          RawTimingSample(
            operation: label,
            category: category,
            inputSizeBytes: dataSizeBytes,
            phase: 'warm',
            sampleIndex: i,
            elapsedMs: mean,
            isWarmup: false,
          ),
        );
      }
    }
    return _buildResult(
      mean,
      dataSizeBytes,
      measuredCount,
      totalElapsedUs,
      label,
    );
  }

  WarmTimingResult _measureWarmPerIteration(
    void Function() op,
    int measuredCount,
    int dataSizeBytes,
    String label,
    String category,
  ) {
    final times = List<double>.filled(measuredCount, 0.0);
    final cumulativeSw = Stopwatch()..start();
    for (var i = 0; i < measuredCount; i++) {
      final iterSw = Stopwatch()..start();
      op();
      iterSw.stop();
      times[i] = iterSw.elapsedMicroseconds / 1000.0;
    }
    cumulativeSw.stop();

    final mean = times.reduce((a, b) => a + b) / measuredCount;
    final min = times.reduce((a, b) => a < b ? a : b);
    final max = times.reduce((a, b) => a > b ? a : b);
    final totalElapsedUs = cumulativeSw.elapsedMicroseconds;

    final throughputMbps = _computeThroughput(
      dataSizeBytes,
      mean,
      totalElapsedUs,
      label,
    );

    if (_collectRawSamples) {
      for (var i = 0; i < measuredCount; i++) {
        _rawSamples.add(
          RawTimingSample(
            operation: label,
            category: category,
            inputSizeBytes: dataSizeBytes,
            phase: 'warm',
            sampleIndex: i,
            elapsedMs: times[i],
            isWarmup: false,
          ),
        );
      }
    }

    return WarmTimingResult(
      meanMs: mean,
      minMs: min,
      maxMs: max,
      throughputMbps: throughputMbps,
      dataSizeBytes: dataSizeBytes,
      iterations: measuredCount,
      iterationTimesMs: times,
    );
  }

  WarmTimingResult _buildResult(
    double mean,
    int dataSizeBytes,
    int iterations,
    int totalElapsedUs,
    String label, {
    List<double>? perIterationTimes,
  }) {
    final throughputMbps = _computeThroughput(
      dataSizeBytes,
      mean,
      totalElapsedUs,
      label,
    );
    return WarmTimingResult(
      meanMs: mean,
      minMs: mean,
      maxMs: mean,
      throughputMbps: throughputMbps,
      dataSizeBytes: dataSizeBytes,
      iterations: iterations,
      iterationTimesMs: perIterationTimes,
    );
  }

  double _computeThroughput(
    int dataSizeBytes,
    double meanMs,
    int totalElapsedUs,
    String label,
  ) {
    if (dataSizeBytes <= 0) return 0.0;

    if (totalElapsedUs < _resolutionLimitUs) {
      stderr.writeln(
        '[timing] WARNING: $label — elapsed time ($totalElapsedUs μs) '
        'is below Stopwatch resolution ($_resolutionLimitUs μs). '
        'Throughput is unmeasurable.',
      );
      return 0.0;
    }

    if (totalElapsedUs < _minTotalTimeUs) {
      stderr.writeln(
        '[timing] WARNING: $label — cumulative elapsed time '
        '($totalElapsedUs μs) is below the $_minTotalTimeUs μs precision '
        'threshold. Throughput is approximate.',
      );
    }

    return computeMbps(dataSizeBytes, meanMs);
  }

  void _stabilizeHeap() {
    for (var i = 0; i < 8; i++) {
      Uint8List(4 * 1024 * 1024); // allocate and immediately discard 4MB
      Uint8List(0); // allocate and discard empty list
    }
  }

  /// Converte resultados cold + warm em um registro [OperationTiming].
  OperationTiming toOperationTiming(
    String operation,
    String category,
    ColdTimingResult cold,
    WarmTimingResult warm,
  ) {
    return OperationTiming(
      operation: operation,
      category: category,
      inputSizeBytes: warm.dataSizeBytes,
      coldMs: cold.elapsedMs,
      warmMs: warm.meanMs,
      throughputMbps: warm.throughputMbps,
      iterationsWarm: warm.iterations,
    );
  }

  HistogramSnapshot computeHistogram({
    required String operation,
    required String category,
    required WarmTimingResult warm,
    List<double>? perIterationTimes,
  }) {
    if (perIterationTimes == null || perIterationTimes.isEmpty) {
      return HistogramSnapshot(
        operation: operation,
        category: category,
        inputSizeBytes: warm.dataSizeBytes,
        sampleCount: warm.iterations,
        minMs: warm.meanMs,
        p5Ms: warm.meanMs,
        p25Ms: warm.meanMs,
        medianMs: warm.meanMs,
        p75Ms: warm.meanMs,
        p95Ms: warm.meanMs,
        p99Ms: warm.meanMs,
        maxMs: warm.meanMs,
        meanMs: warm.meanMs,
        stddevMs: 0.0,
      );
    }

    final sorted = List<double>.from(perIterationTimes)..sort();
    final n = sorted.length;

    double percentile(double p) {
      final pos = (n - 1) * p;
      final lo = pos.floor();
      final hi = pos.ceil();
      if (lo == hi) return sorted[lo];
      final frac = pos - lo;
      return sorted[lo] + frac * (sorted[hi] - sorted[lo]);
    }

    final min = sorted.first;
    final max = sorted.last;
    final p5 = percentile(0.05);
    final p25 = percentile(0.25);
    final median = percentile(0.50);
    final p75 = percentile(0.75);
    final p95 = percentile(0.95);
    final p99 = percentile(0.99);

    final mean = sorted.reduce((a, b) => a + b) / n;
    var sumSqDiff = 0.0;
    for (final x in sorted) {
      final diff = x - mean;
      sumSqDiff += diff * diff;
    }
    final stddev = sqrt(sumSqDiff / n); // population stddev

    return HistogramSnapshot(
      operation: operation,
      category: category,
      inputSizeBytes: warm.dataSizeBytes,
      sampleCount: n,
      minMs: min,
      p5Ms: p5,
      p25Ms: p25,
      medianMs: median,
      p75Ms: p75,
      p95Ms: p95,
      p99Ms: p99,
      maxMs: max,
      meanMs: mean,
      stddevMs: stddev,
    );
  }
}
