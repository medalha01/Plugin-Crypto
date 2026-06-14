import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone14', 'Random Edge Cases');

  final api = PluginCryptoAPI.instance;

  group('Random negative length', () {
    test('randomBytes(-1) throws ArgumentError', () {
      expect(() => api.randomBytes(-1), throwsA(anything));
    });
  });

  group('Random very large allocation', () {
    test('randomBytes 100 MB does not crash', () {
      const mb100 = 100 * 1024 * 1024;
      final bytes = api.randomBytes(mb100);
      expect(bytes.length, equals(mb100));
    }, tags: ['slow']);
  });

  group('Random statistical uniformity (chi-squared)', () {
    test('10 000 random bytes pass chi-squared for uniform distribution', () {
      const sampleSize = 10000;
      final bytes = api.randomBytes(sampleSize);

      final counts = List<int>.filled(256, 0);
      for (var i = 0; i < bytes.length; i++) {
        counts[bytes[i]]++;
      }

      final expected = sampleSize / 256.0;

      var chiSq = 0.0;
      for (var b = 0; b < 256; b++) {
        final diff = counts[b] - expected;
        chiSq += (diff * diff) / expected;
      }

      expect(
        chiSq,
        lessThan(400.0),
        reason:
            'Chi-squared $chiSq exceeds threshold; '
            'distribution may not be uniform.',
      );
    });
  });

  m?.endZone();
}
