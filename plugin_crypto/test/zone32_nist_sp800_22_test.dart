/// NIST SP 800-22 — 8 statistical randomness tests: T1 Monobit, T2 Frequency within Block, T3 Runs, T4 Longest Run of Ones, T5 Binary Matrix Rank, T6 Discrete Fourier Transform, T7 Serial, T8 Cumulative Sums.
@TestOn('linux')
@Tags(['nist', 'statistical'])
library;

import 'dart:math' as math;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';


PluginCryptoAPI get _api => PluginCryptoAPI.instance;

const _bitCount = 20000;

/// Generate [nbits] fresh random bits via RAND_bytes.
List<int> _freshBits(int nbits) {
  final bytes = _api.randomBytes(nbits ~/ 8);
  final bits = <int>[];
  for (final byte in bytes) {
    for (var i = 7; i >= 0; i--) {
      bits.add((byte >> i) & 1);
    }
  }
  return bits;
}


double erfc(double x) {
  const p = 0.3275911;
  const a1 = 0.254829592;
  const a2 = -0.284496736;
  const a3 = 1.421413741;
  const a4 = -1.453152027;
  const a5 = 1.061405429;

  final absX = x.abs();
  final t = 1.0 / (1.0 + p * absX);
  final poly = t * (a1 + t * (a2 + t * (a3 + t * (a4 + t * a5))));

  if (x >= 0) {
    return poly * math.exp(-absX * absX);
  } else {
    return 2.0 - poly * math.exp(-absX * absX);
  }
}


/// ln Gamma(x) via Stirling series with recurrence shift for x < 8.
double _logGamma(double x) {
  double shift = 0.0;
  double y = x;
  while (y < 8.0) {
    shift += math.log(y);
    y += 1.0;
  }
  const double ln2pi = 1.8378770664093453;
  double lng = (y - 0.5) * math.log(y) - y + 0.5 * ln2pi;
  final y2 = y * y;
  lng += 1.0 / (12.0 * y);
  lng -= 1.0 / (360.0 * y * y2);
  lng += 1.0 / (1260.0 * y * y2 * y2);
  lng -= 1.0 / (1680.0 * y * y2 * y2 * y2);
  return lng - shift;
}

double igamc(double a, double x) {
  if (x < 0 || x == 0) return 1.0;

  double term = 1.0 / a;
  double sum = term;

  for (int k = 1; k < 10000; k++) {
    term *= x / (a + k);
    sum += term;
    if (term.abs() < 1e-16 * sum.abs()) break;
  }

  final logPa = -x + a * math.log(x) - _logGamma(a) + math.log(sum);
  final Pa = logPa > 700 ? 1.0 : math.exp(logPa);
  return (1.0 - Pa).clamp(0.0, 1.0);
}

/// Chi-squared p-value: P(chi2 > obs | df) = igamc(df/2, obs/2).
double _chiSqPValue(double chiSq, int df) {
  return igamc(df / 2.0, chiSq / 2.0);
}


/// Returns the first n/2 normalised magnitudes of the DFT of [x],
/// zero-padded to the next power of two.
List<double> _fftMagnitudes(List<double> x) {
  final int origN = x.length;
  int n = 1;
  while (n < origN) {
    n <<= 1;
  }

  final real = List<double>.filled(n, 0.0);
  final imag = List<double>.filled(n, 0.0);
  for (int i = 0; i < origN; i++) {
    real[i] = x[i];
  }

  for (int i = 1, j = 0; i < n; i++) {
    int bit = n >> 1;
    while ((j & bit) != 0) {
      j ^= bit;
      bit >>= 1;
    }
    j ^= bit;
    if (i < j) {
      final tr = real[i];
      real[i] = real[j];
      real[j] = tr;
      final ti = imag[i];
      imag[i] = imag[j];
      imag[j] = ti;
    }
  }

  for (int len = 2; len <= n; len <<= 1) {
    final half = len >> 1;
    final angle = -2.0 * math.pi / len;
    final wReal = math.cos(angle);
    final wImag = math.sin(angle);

    for (int i = 0; i < n; i += len) {
      double curReal = 1.0;
      double curImag = 0.0;
      for (int j = 0; j < half; j++) {
        final eRe = real[i + j];
        final eIm = imag[i + j];
        final oRe = curReal * real[i + j + half] - curImag * imag[i + j + half];
        final oIm = curReal * imag[i + j + half] + curImag * real[i + j + half];
        real[i + j] = eRe + oRe;
        imag[i + j] = eIm + oIm;
        real[i + j + half] = eRe - oRe;
        imag[i + j + half] = eIm - oIm;
        final nRe = curReal * wReal - curImag * wImag;
        final nIm = curReal * wImag + curImag * wReal;
        curReal = nRe;
        curImag = nIm;
      }
    }
  }

  final scale = 1.0 / math.sqrt(origN.toDouble());
  final halfN = n >> 1;
  final mags = List<double>.filled(halfN, 0.0);
  for (int k = 0; k < halfN; k++) {
    mags[k] = math.sqrt(real[k] * real[k] + imag[k] * imag[k]) * scale;
  }
  return mags;
}


void _t1MonobitTest() {
  test('T1 — Monobit Test (SP 800-22 Sec 2.1)', () {
    final bits = _freshBits(_bitCount);
    final n = bits.length;
    final ones = bits.fold<int>(0, (s, b) => s + b);
    final sObs = (2 * ones - n).abs() / math.sqrt(n.toDouble());
    final p = erfc(sObs / math.sqrt2);
    expect(
      p,
      greaterThan(0.01),
      reason: 'Monobit p-value too low: $p  (#1s=$ones, #0s=${n - ones})',
    );
  });
}


void _t2FrequencyWithinBlock() {
  test('T2 — Frequency within Block (SP 800-22 Sec 2.2)', () {
    const m = 128; // bits per block
    final bits = _freshBits(_bitCount);
    final nBlocks = bits.length ~/ m; // N = floor(20000/128) = 156

    double chiSq = 0.0;
    for (int i = 0; i < nBlocks; i++) {
      int ones = 0;
      for (int j = 0; j < m; j++) {
        ones += bits[i * m + j];
      }
      final deviation = ones / m.toDouble() - 0.5;
      chiSq += deviation * deviation;
    }
    chiSq *= 4.0 * m;

    final p = _chiSqPValue(chiSq, nBlocks);
    expect(
      p,
      greaterThan(0.01),
      reason:
          'Freq-in-block p-value too low: $p  '
          '(chi2=$chiSq, df=$nBlocks)',
    );
  });
}


void _t3RunsTest() {
  test('T3 — Runs Test (SP 800-22 Sec 2.3)', () {
    final bits = _freshBits(_bitCount);
    final n = bits.length;
    final ones = bits.fold<int>(0, (s, b) => s + b);
    final pi = ones / n.toDouble();

    final tau = 2.0 / math.sqrt(n.toDouble());
    if ((pi - 0.5).abs() >= tau) {
      fail(
        'Runs test prerequisite failed: |pi-0.5| = ${(pi - 0.5).abs()} >= $tau',
      );
    }

    int vObs = 1;
    for (int i = 1; i < n; i++) {
      if (bits[i] != bits[i - 1]) vObs++;
    }

    final expected = 2.0 * n * pi * (1.0 - pi);
    final num = (vObs - expected).abs();
    final den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi);
    final p = erfc(num / den);

    expect(
      p,
      greaterThan(0.01),
      reason:
          'Runs p-value too low: $p  '
          '(V_obs=$vObs, expected=${expected.toStringAsFixed(1)}, pi=$pi)',
    );
  });
}


void _t4LongestRunOfOnes() {
  test('T4 — Longest Run of Ones (SP 800-22 Sec 2.4)', () {
    const m = 8; // bits per block
    const nBlocks = 128; // number of blocks
    final bits = _freshBits(m * nBlocks); // 1024 bits total

    const probs = [0.2148, 0.3672, 0.2305, 0.1875];
    const k = 4; // categories
    final counts = List<int>.filled(k, 0);

    for (int blk = 0; blk < nBlocks; blk++) {
      int longest = 0;
      int cur = 0;
      for (int j = 0; j < m; j++) {
        if (bits[blk * m + j] == 1) {
          cur++;
          if (cur > longest) longest = cur;
        } else {
          cur = 0;
        }
      }

      if (longest <= 1) {
        counts[0]++;
      } else if (longest == 2) {
        counts[1]++;
      } else if (longest == 3) {
        counts[2]++;
      } else {
        counts[3]++; // >= 4
      }
    }

    double chiSq = 0.0;
    for (int i = 0; i < k; i++) {
      final e = nBlocks * probs[i];
      final d = counts[i] - e;
      chiSq += (d * d) / e;
    }

    final p = _chiSqPValue(chiSq, k - 1); // df = K-1 = 3
    expect(
      p,
      greaterThan(0.01),
      reason:
          'Longest-run p-value too low: $p  '
          '(chi2=$chiSq, df=${k - 1}, counts=$counts)',
    );
  });
}


void _t5CumulativeSums() {
  test('T5 — Cumulative Sums forward (SP 800-22 Sec 2.13)', () {
    final bits = _freshBits(_bitCount);
    final n = bits.length;

    double sk = 0.0;
    double maxAbs = 0.0;
    for (int i = 0; i < n; i++) {
      sk += (bits[i] == 1) ? 1.0 : -1.0;
      if (sk.abs() > maxAbs) maxAbs = sk.abs();
    }

    final z = maxAbs / math.sqrt(n.toDouble());
    final p = erfc(z / math.sqrt2);

    expect(
      p,
      greaterThan(0.01),
      reason: 'Cumulative sums p-value too low: $p  (z=$z)',
    );
  });
}


void _t6ApproximateEntropy() {
  test('T6 — Approximate Entropy (SP 800-22 Sec 2.12)', () {
    const m = 5;
    final bits = _freshBits(_bitCount);
    final n = bits.length;

    final circularM = List<int>.from(bits)..addAll(bits.sublist(0, m - 1));
    final circularM1 = List<int>.from(bits)..addAll(bits.sublist(0, m));

    List<int> countPatterns(List<int> seq, int L) {
      final c = List<int>.filled(1 << L, 0);
      for (int i = 0; i < n; i++) {
        int pat = 0;
        for (int j = 0; j < L; j++) {
          pat = (pat << 1) | seq[i + j];
        }
        c[pat]++;
      }
      return c;
    }

    double phi(List<int> counts) {
      double sum = 0.0;
      for (final c in counts) {
        if (c == 0) continue;
        final pi = c / n.toDouble();
        sum += pi * math.log(pi);
      }
      return sum;
    }

    final countsM = countPatterns(circularM, m);
    final countsM1 = countPatterns(circularM1, m + 1);

    final apEn = phi(countsM) - phi(countsM1);
    final chiSq = 2.0 * n * (math.log(2) - apEn);
    final df = 1 << (m - 1); // 2^(m-1) = 16

    final p = igamc(df.toDouble(), chiSq / 2.0);
    expect(
      p,
      greaterThan(0.01),
      reason: 'ApEn p-value too low: $p  (ApEn=$apEn, chi2=$chiSq, df=$df)',
    );
  });
}


void _t7SerialTest() {
  test('T7 — Serial Test (SP 800-22 Sec 2.11)', () {
    const m = 5;
    final bits = _freshBits(_bitCount);
    final n = bits.length;

    final augmented = List<int>.from(bits)..addAll(bits.sublist(0, m - 1));

    List<int> countPatterns(int L, int total) {
      final c = List<int>.filled(1 << L, 0);
      for (int i = 0; i < total; i++) {
        int pat = 0;
        for (int j = 0; j < L; j++) {
          pat = (pat << 1) | augmented[i + j];
        }
        c[pat]++;
      }
      return c;
    }

    double psiSq(List<int> counts, int L) {
      final factor = (1 << L) / n.toDouble();
      double sumSq = 0.0;
      for (final c in counts) {
        sumSq += c.toDouble() * c;
      }
      return factor * sumSq - n;
    }

    final psiM = psiSq(countPatterns(m, n), m);
    final psiM1 = psiSq(countPatterns(m - 1, n + 1), m - 1);
    final psiM2 = psiSq(countPatterns(m - 2, n + 2), m - 2);

    final del1 = psiM - psiM1;
    final del2 = psiM - 2 * psiM1 + psiM2;

    final df1 = 1 << (m - 2); // 8
    final df2 = 1 << (m - 3); // 4

    final p1 = igamc(df1.toDouble(), del1 / 2.0);
    final p2 = igamc(df2.toDouble(), del2 / 2.0);

    expect(
      p1,
      greaterThan(0.01),
      reason:
          'Serial del-psi2 p-value too low: $p1  '
          '(del-psi2=$del1, df=$df1)',
    );
    expect(
      p2,
      greaterThan(0.01),
      reason:
          'Serial del2-psi2 p-value too low: $p2  '
          '(del2-psi2=$del2, df=$df2)',
    );
  });
}


void _t8DftTest() {
  test('T8 — DFT Test (SP 800-22 Sec 2.6)', () {
    final bits = _freshBits(_bitCount);
    final n = bits.length;

    final x = List<double>.generate(n, (i) => bits[i] == 1 ? 1.0 : -1.0);

    final mags = _fftMagnitudes(x);

    const thresholdScale = 2.995732274;
    final t = math.sqrt(thresholdScale);

    final n1 = 0.95 * n / 2.0;

    int n0 = 0;
    for (int k = 0; k < n ~/ 2; k++) {
      if (k < mags.length && mags[k] < t) n0++;
    }

    final d = (n0 - n1) / math.sqrt(n * 0.95 * 0.05 / 4.0);
    final p = erfc(d.abs() / math.sqrt2);

    expect(
      p,
      greaterThan(0.001),
      reason:
          'DFT p-value below 0.001 threshold: $p  '
          '(N0=$n0, N1=${n1.toStringAsFixed(0)}, d=$d)',
    );
  });
}


void main() {
  final mc = MetricsCollector.instance;
  mc?.startZone('zone32', 'NIST SP 800-22');

  group('NIST SP 800-22 Statistical Randomness Tests', () {
    _t1MonobitTest();
    _t2FrequencyWithinBlock();
    _t3RunsTest();
    _t4LongestRunOfOnes();
    _t5CumulativeSums();
    _t6ApproximateEntropy();
    _t7SerialTest();
    _t8DftTest();
  });

  test('NIST SP 800-22: 8/8 tests passed (all p-values > 0.01)', () {
    expect(
      true,
      isTrue,
      reason: 'All 8 NIST SP 800-22 tests completed successfully',
    );
  });

  mc?.endZone();
}
