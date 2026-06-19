library;

import 'dart:isolate';
import 'dart:typed_data';

import '../crypto/crypto_api.dart';

class IsolateBenchmark {
  static const validOperations = <String>{
    'sha256',
    'aes128CbcEncrypt',
    'aes256GcmEncrypt',
  };

  static Future<Map<String, dynamic>> measureIsolateScaling({
    required int isolateCount,
    required int dataSizeBytes,
    required String opType,
  }) async {
    if (isolateCount < 1) {
      throw ArgumentError.value(isolateCount, 'isolateCount', 'must be >= 1');
    }
    if (dataSizeBytes < 1) {
      throw ArgumentError.value(dataSizeBytes, 'dataSizeBytes', 'must be >= 1');
    }
    if (!validOperations.contains(opType)) {
      throw ArgumentError.value(opType, 'opType', 'unsupported operation');
    }

    final baseline = await Isolate.run(
      () => _runNativeWorkload(opType, dataSizeBytes, 0),
    );
    final watch = Stopwatch()..start();
    final results = await Future.wait(
      List<Future<_WorkloadResult>>.generate(
        isolateCount,
        (index) => Isolate.run(
          () => _runNativeWorkload(opType, dataSizeBytes, index + 1),
        ),
      ),
      eagerError: true,
    );
    watch.stop();

    final totalThroughput = results.fold<double>(
      0,
      (total, result) => total + result.throughputMbps,
    );
    final idealThroughput = baseline.throughputMbps * isolateCount;
    return {
      'status': 'measured',
      'measurementSource': 'plugin_crypto_native',
      'operation': opType,
      'isolateCount': isolateCount,
      'totalThroughputMbps': totalThroughput,
      'throughputPerIsolateMbps': totalThroughput / results.length,
      'scalingEfficiency':
          idealThroughput > 0 ? totalThroughput / idealThroughput : 0.0,
      'totalSuiteMs': watch.elapsedMicroseconds / 1000.0,
      'checksum': results.fold<int>(0, (sum, result) => sum ^ result.checksum),
    };
  }
}

_WorkloadResult _runNativeWorkload(String operation, int dataSize, int seed) {
  final api = PluginCryptoAPI.instance;
  final data = Uint8List(dataSize);
  for (var i = 0; i < data.length; i++) {
    data[i] = (i * 7 + seed * 31 + 13) & 0xFF;
  }
  final key128 = Uint8List.fromList(List<int>.generate(16, (i) => i + seed));
  final key256 = Uint8List.fromList(List<int>.generate(32, (i) => i + seed));
  final cbcIv = Uint8List.fromList(List<int>.generate(16, (i) => 0xA0 ^ i));
  final gcmIv = Uint8List.fromList(List<int>.generate(12, (i) => 0x50 ^ i));

  Uint8List execute() => switch (operation) {
    'sha256' => api.sha256(data),
    'aes128CbcEncrypt' => api.aes128CbcEncrypt(key128, cbcIv, data),
    'aes256GcmEncrypt' =>
      api.aes256GcmEncrypt(key256, gcmIv, data).ciphertext,
    _ => throw StateError('Validated operation became unsupported: $operation'),
  };

  execute();
  const iterations = 10;
  var checksum = 0;
  final watch = Stopwatch()..start();
  for (var i = 0; i < iterations; i++) {
    final output = execute();
    if (output.isNotEmpty) checksum ^= output[i % output.length];
  }
  watch.stop();
  if (watch.elapsedMicroseconds == 0) {
    throw StateError('Benchmark duration was below timer resolution');
  }
  final megabytes = (dataSize * iterations) / (1024.0 * 1024.0);
  final seconds = watch.elapsedMicroseconds / 1000000.0;
  return _WorkloadResult(megabytes / seconds, checksum);
}

final class _WorkloadResult {
  final double throughputMbps;
  final int checksum;

  const _WorkloadResult(this.throughputMbps, this.checksum);
}
