@Tags(['metrics'])
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/concurrency.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  group('Isolate scaling — synthetic', () {
    test('1 isolate baseline produces valid result shape', () async {
      final r = await IsolateBenchmark.measureIsolateScaling(
        isolateCount: 1,
        dataSizeBytes: 1048576,
        opType: 'sha256',
      );
      expect(r.containsKey('isolateCount'), isTrue);
      expect(r.containsKey('totalThroughputMbps'), isTrue);
      expect(r.containsKey('throughputPerIsolateMbps'), isTrue);
      expect(r.containsKey('scalingEfficiency'), isTrue);
      expect(r.containsKey('totalSuiteMs'), isTrue);

      _collector.recordScalingPoint(
        IsolateScalingPoint(
          isolateCount: r['isolateCount'] as int,
          totalThroughputMbps: (r['totalThroughputMbps'] as num).toDouble(),
          throughputPerIsolateMbps: (r['throughputPerIsolateMbps'] as num)
              .toDouble(),
          scalingEfficiency: (r['scalingEfficiency'] as num).toDouble(),
          totalSuiteMs: (r['totalSuiteMs'] as num).toDouble(),
        ),
      );
    });

    test('2 isolates scaling result shape and efficiency', () async {
      final r = await IsolateBenchmark.measureIsolateScaling(
        isolateCount: 2,
        dataSizeBytes: 1048576,
        opType: 'sha256',
      );
      expect(r.containsKey('scalingEfficiency'), isTrue);
      expect((r['scalingEfficiency'] as num).toDouble(), greaterThan(0.0));

      _collector.recordScalingPoint(
        IsolateScalingPoint(
          isolateCount: r['isolateCount'] as int,
          totalThroughputMbps: (r['totalThroughputMbps'] as num).toDouble(),
          throughputPerIsolateMbps: (r['throughputPerIsolateMbps'] as num)
              .toDouble(),
          scalingEfficiency: (r['scalingEfficiency'] as num).toDouble(),
          totalSuiteMs: (r['totalSuiteMs'] as num).toDouble(),
        ),
      );
    });

    test('4 isolates scaling shape', () async {
      final r = await IsolateBenchmark.measureIsolateScaling(
        isolateCount: 4,
        dataSizeBytes: 1048576,
        opType: 'sha256',
      );
      expect((r['scalingEfficiency'] as num).toDouble(), greaterThan(0.0));

      _collector.recordScalingPoint(
        IsolateScalingPoint(
          isolateCount: r['isolateCount'] as int,
          totalThroughputMbps: (r['totalThroughputMbps'] as num).toDouble(),
          throughputPerIsolateMbps: (r['throughputPerIsolateMbps'] as num)
              .toDouble(),
          scalingEfficiency: (r['scalingEfficiency'] as num).toDouble(),
          totalSuiteMs: (r['totalSuiteMs'] as num).toDouble(),
        ),
      );
    });

    test('8 isolates scaling shape', () async {
      final r = await IsolateBenchmark.measureIsolateScaling(
        isolateCount: 8,
        dataSizeBytes: 1048576,
        opType: 'sha256',
      );
      expect((r['scalingEfficiency'] as num).toDouble(), greaterThan(0.0));

      _collector.recordScalingPoint(
        IsolateScalingPoint(
          isolateCount: r['isolateCount'] as int,
          totalThroughputMbps: (r['totalThroughputMbps'] as num).toDouble(),
          throughputPerIsolateMbps: (r['throughputPerIsolateMbps'] as num)
              .toDouble(),
          scalingEfficiency: (r['scalingEfficiency'] as num).toDouble(),
          totalSuiteMs: (r['totalSuiteMs'] as num).toDouble(),
        ),
      );
    });

    test('AES-128-CBC 2 isolates shape', () async {
      final r = await IsolateBenchmark.measureIsolateScaling(
        isolateCount: 2,
        dataSizeBytes: 1048576,
        opType: 'aes128CbcEncrypt',
      );
      expect((r['scalingEfficiency'] as num).toDouble(), greaterThan(0.0));

      _collector.recordScalingPoint(
        IsolateScalingPoint(
          isolateCount: r['isolateCount'] as int,
          totalThroughputMbps: (r['totalThroughputMbps'] as num).toDouble(),
          throughputPerIsolateMbps: (r['throughputPerIsolateMbps'] as num)
              .toDouble(),
          scalingEfficiency: (r['scalingEfficiency'] as num).toDouble(),
          totalSuiteMs: (r['totalSuiteMs'] as num).toDouble(),
        ),
      );
    });
  });

  tearDownAll(() {
  });
}
