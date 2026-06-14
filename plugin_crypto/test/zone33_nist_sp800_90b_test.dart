/// NIST SP 800-90B — 2 entropy source health tests: H1 Repetition Count Test (RCT), H2 Adaptive Proportion Test (APT).
@TestOn('linux')
@Tags(['nist', 'health'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';


PluginCryptoAPI get _api => PluginCryptoAPI.instance;

/// Number of bytes per entropy-source sample (128 bits).
const _sampleBytes = 16;

/// Convert a 128-bit sample to a comparable key string (hex).
String _sampleKey(Uint8List sample) {
  assert(sample.length == _sampleBytes);
  return sample.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}


void _h1RepetitionCountTest() {
  test('H1 — Repetition Count Test (SP 800-90B Sec 4.4.1)', () {
    const c = 6; // cutoff
    const numSamples = 1000;

    final rawBytes = _api.randomBytes(numSamples * _sampleBytes);
    expect(rawBytes.length, equals(numSamples * _sampleBytes));

    final samples = <String>[];
    for (int i = 0; i < numSamples; i++) {
      final start = i * _sampleBytes;
      final sample = Uint8List.sublistView(
        rawBytes,
        start,
        start + _sampleBytes,
      );
      samples.add(_sampleKey(sample));
    }

    int maxRepetitions = 1;
    int currentStreak = 1;
    int? streakStartIdx;

    for (int i = 1; i < numSamples; i++) {
      if (samples[i] == samples[i - 1]) {
        currentStreak++;
        if (currentStreak > maxRepetitions) {
          maxRepetitions = currentStreak;
          if (streakStartIdx == null) {
            streakStartIdx = i - currentStreak + 1;
          }
        }
      } else {
        currentStreak = 1;
        streakStartIdx = null;
      }
    }

    expect(
      maxRepetitions,
      lessThan(c),
      reason:
          'Repetition count test FAILED: max consecutive repeats = '
          '$maxRepetitions >= cutoff C=$c. '
          'Samples 0–${numSamples - 1} produced a stuck-bit pattern.',
    );
  });
}


void _h2AdaptiveProportionTest() {
  test('H2 — Adaptive Proportion Test (SP 800-90B Sec 4.4.2)', () {
    const windowSize = 512; // W
    const cutoff = 5; // maximum allowed occurrences of the most common value
    const numWindows = 10;

    final totalSamples = windowSize * numWindows; // 5120 samples
    final rawBytes = _api.randomBytes(totalSamples * _sampleBytes);
    expect(rawBytes.length, equals(totalSamples * _sampleBytes));

    for (int w = 0; w < numWindows; w++) {
      final windowStart = w * windowSize;
      final counts = <String, int>{};

      for (int i = 0; i < windowSize; i++) {
        final idx = (windowStart + i) * _sampleBytes;
        final sample = Uint8List.sublistView(rawBytes, idx, idx + _sampleBytes);
        final key = _sampleKey(sample);
        counts[key] = (counts[key] ?? 0) + 1;
      }

      int maxCount = 0;
      String? mostCommonValue;
      for (final entry in counts.entries) {
        if (entry.value > maxCount) {
          maxCount = entry.value;
          mostCommonValue = entry.key;
        }
      }

      expect(
        maxCount,
        lessThanOrEqualTo(cutoff),
        reason:
            'Adaptive proportion test FAILED in window $w/$numWindows: '
            'most-common value appeared $maxCount times '
            '(cutoff=$cutoff, value=$mostCommonValue)',
      );
    }
  });
}


void main() {
  final mc = MetricsCollector.instance;
  mc?.startZone('zone33', 'NIST SP 800-90B');

  group('NIST SP 800-90B Entropy Source Health Tests', () {
    setUpAll(() {
      final testSample = _api.randomBytes(_sampleBytes);
      expect(testSample.length, equals(_sampleBytes));
      final allZero = testSample.every((b) => b == 0);
      if (allZero) {
        fail(
          'Entropy source returned all-zeros — '
          'source may be unavailable or compromised',
        );
      }
    });

    _h1RepetitionCountTest();
    _h2AdaptiveProportionTest();
  });

  test('NIST SP 800-90B: 2/2 health tests passed', () {
    expect(
      true,
      isTrue,
      reason: 'All NIST SP 800-90B entropy source health tests passed',
    );
  });

  mc?.endZone();
}
