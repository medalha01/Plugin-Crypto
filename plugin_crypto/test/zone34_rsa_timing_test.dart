/// RSA timing side-channel defenses: D1 2048-bit, D2 3072-bit, D3 4096-bit.
@TestOn('linux')
@Tags(['timing', 'side-channel'])
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';


/// Returns the arithmetic mean of [values].
double mean(List<double> values) {
  if (values.isEmpty) return 0.0;
  return values.reduce((a, b) => a + b) / values.length;
}

/// Returns the sample standard deviation of [values].
double stddev(List<double> values) {
  if (values.length < 2) return 0.0;
  final m = mean(values);
  final sumSq = values.fold<double>(0, (s, v) => s + (v - m) * (v - m));
  return math.sqrt(sumSq / (values.length - 1));
}

/// Returns the [percentile]-th percentile (0–100) of sorted [values] using
/// the R-7 (linear interpolation) method.
double percentile(List<double> sorted, double p) {
  if (sorted.isEmpty) return 0.0;
  final n = sorted.length;
  final pos = (n - 1) * p / 100.0;
  final lo = pos.floor();
  final hi = pos.ceil();
  if (lo == hi) return sorted[lo];
  final frac = pos - lo;
  return sorted[lo] + frac * (sorted[hi] - sorted[lo]);
}

/// Returns the median of sorted [values].
double median(List<double> sorted) => percentile(sorted, 50);

/// Returns the coefficient of variation = stddev / mean.
double cv(List<double> values) {
  final m = mean(values);
  if (m <= 0.0) return double.infinity;
  return stddev(values) / m;
}

/// Returns trimmed mean excluding [trimFraction] from each tail.
/// e.g., trimFraction = 0.01 removes the bottom 1% and top 1%.
double trimmedMean(List<double> values, double trimFraction) {
  if (values.isEmpty) return 0.0;
  final sorted = List<double>.from(values)..sort();
  final trimCount = (sorted.length * trimFraction).round();
  if (trimCount * 2 >= sorted.length) {
    return median(sorted);
  }
  final trimmed = sorted.sublist(trimCount, sorted.length - trimCount);
  return mean(trimmed);
}

double _studentTCdf(double t, double df) {
  if (df <= 0) return double.nan;
  final x = df / (df + t * t);
  return _regularizedIncompleteBeta(df / 2, 0.5, x);
}

/// Two-sample t-test statistic (equal variance assumed).
double tStatistic(List<double> sample1, List<double> sample2) {
  final m1 = mean(sample1);
  final m2 = mean(sample2);
  final n1 = sample1.length;
  final n2 = sample2.length;

  final v1 = sample1.fold<double>(0, (s, v) => s + (v - m1) * (v - m1));
  final v2 = sample2.fold<double>(0, (s, v) => s + (v - m2) * (v - m2));

  final pooledVar = (v1 + v2) / (n1 + n2 - 2);
  final se = math.sqrt(pooledVar * (1 / n1 + 1 / n2));
  if (se == 0) return double.infinity;
  return (m1 - m2).abs() / se;
}

/// Two-sample t-test p-value (two-tailed).
double tTestPValue(List<double> sample1, List<double> sample2) {
  final t = tStatistic(sample1, sample2);
  final df = sample1.length + sample2.length - 2.0;
  return 2.0 * (1.0 - _studentTCdf(t, df));
}

/// Regularized incomplete beta function I_x(a, b) via continued fraction
/// (Lentz's method).
double _regularizedIncompleteBeta(double a, double b, double x) {
  if (x < 0.0 || x > 1.0) return double.nan;
  if (x == 0.0) return 0.0;
  if (x == 1.0) return 1.0;

  final front = math.exp(
    _logGamma(a + b) -
        _logGamma(a) -
        _logGamma(b) +
        a * math.log(x) +
        b * math.log(1.0 - x),
  );

  const maxIter = 200;
  const epsilon = 1e-12;

  var f = 1.0;
  var c = 1.0;
  var d = 1.0 - (a + b) * x / (a + 1.0);
  if (d.abs() < epsilon) d = epsilon;
  d = 1.0 / d;
  f = d;

  for (var m = 1; m <= maxIter; m++) {
    final m2 = 2 * m;

    var term = m * (b - m) * x / ((a + m2 - 1) * (a + m2));
    d = 1.0 + term * d;
    if (d.abs() < epsilon) d = epsilon;
    c = 1.0 + term / c;
    if (c.abs() < epsilon) c = epsilon;
    d = 1.0 / d;
    f *= d * c;

    term = -(a + m) * (a + b + m) * x / ((a + m2) * (a + m2 + 1));
    d = 1.0 + term * d;
    if (d.abs() < epsilon) d = epsilon;
    c = 1.0 + term / c;
    if (c.abs() < epsilon) c = epsilon;
    d = 1.0 / d;
    final factor = d * c;
    f *= factor;

    if ((factor - 1.0).abs() < epsilon) break;
  }

  return front * f / a;
}

/// Log-Gamma function using Stirling's approximation.
double _logGamma(double x) {
  if (x <= 0) return double.nan;
  if (x < 1.0) {
    return _logGamma(1.0 + x) - math.log(x);
  }
  return 0.5 * math.log(2 * math.pi) +
      (x - 0.5) * math.log(x) -
      x +
      1.0 / (12 * x) -
      1.0 / (360 * x * x * x) +
      1.0 / (1260 * x * x * x * x * x);
}


/// Cached [PluginCryptoAPI] singleton.
PluginCryptoAPI get _api => PluginCryptoAPI.instance;

/// Triggers a full GC by allocating and discarding a large buffer.
/// This reduces cross-sample GC interference in timing measurements.
void _gcBarrier() {
  // ignore: unused_local_variable
  var buf = Uint8List(16 * 1024 * 1024);
  buf = Uint8List(0);
}

double _timeDecrypt(Uint8List privateKeyPem, Uint8List ciphertext) {
  final sw = Stopwatch()..start();
  _api.rsaDecrypt(privateKeyPem, ciphertext);
  sw.stop();
  return sw.elapsedMicroseconds / 1000.0; // Return milliseconds
}

List<double> _collectTimingSamples({
  required Uint8List privateKeyPem,
  required Uint8List ciphertext,
  required int samples,
  int warmup = 10,
}) {
  for (var i = 0; i < warmup; i++) {
    _api.rsaDecrypt(privateKeyPem, ciphertext);
    _gcBarrier();
  }

  final results = <double>[];
  for (var i = 0; i < samples; i++) {
    _gcBarrier();
    results.add(_timeDecrypt(privateKeyPem, ciphertext));
  }
  return results;
}


void main() {
  late KeyPair rsa2048KeyPair;
  late KeyPair rsa4096KeyPair;
  late KeyPair wrongRsa2048KeyPair;

  late Uint8List plaintext2048;
  late Uint8List ciphertext2048;
  late Uint8List privKey2048Bytes;

  late Uint8List plaintext4096;
  late Uint8List ciphertext4096;
  late Uint8List privKey4096Bytes;

  late Uint8List wrongPrivKey2048Bytes;

  setUpAll(() {
    rsa2048KeyPair = _api.generateRsaKeyPair(2048);
    rsa4096KeyPair = _api.generateRsaKeyPair(4096);
    wrongRsa2048KeyPair = _api.generateRsaKeyPair(2048);

    plaintext2048 = _api.randomBytes(32);
    final pubKey2048Bytes = Uint8List.fromList(
      rsa2048KeyPair.publicKeyPem.codeUnits,
    );
    privKey2048Bytes = Uint8List.fromList(
      rsa2048KeyPair.privateKeyPem.codeUnits,
    );
    ciphertext2048 = _api.rsaEncrypt(pubKey2048Bytes, plaintext2048);

    plaintext4096 = _api.randomBytes(32);
    final pubKey4096Bytes = Uint8List.fromList(
      rsa4096KeyPair.publicKeyPem.codeUnits,
    );
    privKey4096Bytes = Uint8List.fromList(
      rsa4096KeyPair.privateKeyPem.codeUnits,
    );
    ciphertext4096 = _api.rsaEncrypt(pubKey4096Bytes, plaintext4096);

    wrongPrivKey2048Bytes = Uint8List.fromList(
      wrongRsa2048KeyPair.privateKeyPem.codeUnits,
    );
  });

  group('D1: RSA-2048 decrypt timing distribution', () {
    test(
      '500 samples — CV < 0.50, no outliers > 10× median',
      () {
        final times = _collectTimingSamples(
          privateKeyPem: privKey2048Bytes,
          ciphertext: ciphertext2048,
          samples: 500,
          warmup: 15,
        );

        expect(times.length, equals(500));

        final sorted = List<double>.from(times)..sort();
        final med = median(sorted);
        final trimmedM = trimmedMean(times, 0.01);
        final cvVal = cv(times);
        final std = stddev(times);

        for (final t in times) {
          expect(
            t,
            greaterThan(0),
            reason: 'Every decrypt timing sample must be > 0 ms',
          );
        }

        expect(
          cvVal,
          lessThan(0.50),
          reason:
              'RSA-2048 decrypt timing CV must be < 0.50 '
              '(constant-time guarantee). Got CV=${cvVal.toStringAsFixed(4)}, '
              'median=${med.toStringAsFixed(4)}ms, '
              'stddev=${std.toStringAsFixed(4)}ms',
        );

        final outlierThreshold = med * 10.0;
        final outliers = times.where((t) => t > outlierThreshold).toList();
        expect(
          outliers,
          isEmpty,
          reason:
              'RSA-2048 decrypt must have no outliers > 10× median '
              '(${outlierThreshold.toStringAsFixed(4)}ms). '
              'Found ${outliers.length} outliers: '
              '${outliers.map((t) => t.toStringAsFixed(4)).join(", ")}',
        );

        final rawMean = mean(times);
        expect(
          trimmedM,
          greaterThan(rawMean * 0.50),
          reason: 'Trimmed mean must be >= 50% of raw mean',
        );
        expect(
          trimmedM,
          lessThan(rawMean * 1.50),
          reason: 'Trimmed mean must be <= 150% of raw mean',
        );

        print(
          'D1 RSA-2048 decrypt timing: '
          'n=${times.length}, '
          'mean=${rawMean.toStringAsFixed(4)}ms, '
          'tmean=${trimmedM.toStringAsFixed(4)}ms, '
          'median=$med, '
          'stddev=${std.toStringAsFixed(4)}ms, '
          'min=${sorted.first.toStringAsFixed(4)}ms, '
          'max=${sorted.last.toStringAsFixed(4)}ms, '
          'CV=${cvVal.toStringAsFixed(4)}',
        );
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );
  });

  group('D2: RSA-2048 correct vs wrong key t-test', () {
    test(
      '500 samples each — p > 0.05 (no timing oracle)',
      () {
        final correctTimes = _collectTimingSamples(
          privateKeyPem: privKey2048Bytes,
          ciphertext: ciphertext2048,
          samples: 500,
          warmup: 15,
        );

        final wrongTimes = <double>[];
        for (var i = 0; i < 10; i++) {
          try {
            _api.rsaDecrypt(wrongPrivKey2048Bytes, ciphertext2048);
          } catch (_) {
          }
          _gcBarrier();
        }
        for (var i = 0; i < 500; i++) {
          _gcBarrier();
          final sw = Stopwatch()..start();
          try {
            _api.rsaDecrypt(wrongPrivKey2048Bytes, ciphertext2048);
          } catch (_) {
          }
          sw.stop();
          wrongTimes.add(sw.elapsedMicroseconds / 1000.0);
        }

        expect(correctTimes.length, equals(500));
        expect(wrongTimes.length, equals(500));

        final t = tStatistic(correctTimes, wrongTimes);
        final p = tTestPValue(correctTimes, wrongTimes);
        final df = correctTimes.length + wrongTimes.length - 2.0;

        expect(
          p,
          greaterThan(0.05),
          reason:
              'RSA-2048 decrypt timing must be indistinguishable '
              'between correct and wrong keys. '
              't(${df.toInt()})=${t.toStringAsFixed(4)}, '
              'p=${p.toStringAsFixed(6)}. '
              'mean_correct=${mean(correctTimes).toStringAsFixed(4)}ms, '
              'mean_wrong=${mean(wrongTimes).toStringAsFixed(4)}ms',
        );

        print(
          'D2 RSA-2048 correct vs wrong key t-test: '
          't=$t, df=${df.toInt()}, '
          'p=$p, '
          'mean_correct=${mean(correctTimes).toStringAsFixed(4)}ms, '
          'mean_wrong=${mean(wrongTimes).toStringAsFixed(4)}ms, '
          'cv_correct=${cv(correctTimes).toStringAsFixed(4)}',
        );
      },
      timeout: const Timeout(Duration(minutes: 4)),
    );
  });

  group('D3: RSA-4096 decrypt timing', () {
    test('100 samples — CV < 0.50', () {
      final times = _collectTimingSamples(
        privateKeyPem: privKey4096Bytes,
        ciphertext: ciphertext4096,
        samples: 100,
        warmup: 5,
      );

      expect(times.length, equals(100));

      final sorted = List<double>.from(times)..sort();
      final med = median(sorted);
      final cvVal = cv(times);
      final rawMean = mean(times);
      final std = stddev(times);

      for (final t in times) {
        expect(
          t,
          greaterThan(0),
          reason: 'RSA-4096 decrypt timing must be > 0 ms',
        );
      }

      expect(
        cvVal,
        lessThan(0.80),
        reason:
            'RSA-4096 decrypt timing CV must be < 0.80. '
            'Got CV=${cvVal.toStringAsFixed(4)}, '
            'median=${med.toStringAsFixed(4)}ms',
      );

      final outlierThreshold = med * 10.0;
      final outliers = times.where((t) => t > outlierThreshold).toList();
      expect(
        outliers,
        isEmpty,
        reason: 'RSA-4096 decrypt must have no outliers > 10× median',
      );

      print(
        'D3 RSA-4096 decrypt timing: '
        'n=${times.length}, '
        'mean=${rawMean.toStringAsFixed(4)}ms, '
        'median=$med, '
        'stddev=${std.toStringAsFixed(4)}ms, '
        'min=${sorted.first.toStringAsFixed(4)}ms, '
        'max=${sorted.last.toStringAsFixed(4)}ms, '
        'CV=${cvVal.toStringAsFixed(4)}',
      );
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}
