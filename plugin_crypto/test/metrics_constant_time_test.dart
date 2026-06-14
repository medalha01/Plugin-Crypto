@Tags(['metrics'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/constant_time.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';

import 'fixtures/helpers.dart' as helpers;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

void main() {
  final api = helpers.api();
  final results = <ConstantTimeResult>[];

  List<double> measurePregen(
    int n,
    List<Uint8List> inputs,
    Uint8List Function(Uint8List) op,
  ) {
    final times = <double>[];
    for (var i = 0; i < n; i++) {
      final sw = Stopwatch()..start();
      op(inputs[i]);
      sw.stop();
      times.add(sw.elapsedMicroseconds / 1000.0);
    }
    return times;
  }

  const nSamples = 1000;

  group('SHA-256 constant-time', () {
    test('1000 random 1KB inputs', () {
      final inputs = List<Uint8List>.generate(
        nSamples,
        (_) => api.randomBytes(1024),
      );
      final times = measurePregen(nSamples, inputs, (d) => api.sha256(d));
      final r = ConstantTimeAnalyzer.analyze(times, 'sha256');
      results.add(r);
      _collector.recordConstantTimeResult(r);
      expect(r.maxMinRatio, lessThan(100.0));
    });
  });

  group('SHA-512 constant-time', () {
    test('1000 random 1KB inputs', () {
      final inputs = List<Uint8List>.generate(
        nSamples,
        (_) => api.randomBytes(1024),
      );
      final times = measurePregen(nSamples, inputs, (d) => api.sha512(d));
      final r = ConstantTimeAnalyzer.analyze(times, 'sha512');
      results.add(r);
      _collector.recordConstantTimeResult(r);
      expect(r.maxMinRatio, lessThan(100.0));
    });
  });

  group('AES-128-CBC constant-time', () {
    test('1000 random plaintexts, same key', () {
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final inputs = List<Uint8List>.generate(
        nSamples,
        (_) => api.randomBytes(1024),
      );
      final times = <double>[];
      for (var i = 0; i < nSamples; i++) {
        final sw = Stopwatch()..start();
        api.aes128CbcEncrypt(key, iv, inputs[i]);
        sw.stop();
        times.add(sw.elapsedMicroseconds / 1000.0);
      }
      final r = ConstantTimeAnalyzer.analyze(times, 'aes128CbcEncrypt');
      results.add(r);
      _collector.recordConstantTimeResult(r);
      expect(r.maxMinRatio, lessThan(100.0));
    });
  });

  group('AES-256-GCM constant-time', () {
    test('1000 random plaintexts, same key', () {
      final key = api.randomBytes(32);
      final iv = api.randomBytes(12);
      final inputs = List<Uint8List>.generate(
        nSamples,
        (_) => api.randomBytes(1024),
      );
      final times = <double>[];
      for (var i = 0; i < nSamples; i++) {
        final sw = Stopwatch()..start();
        api.aes256GcmEncrypt(key, iv, inputs[i]);
        sw.stop();
        times.add(sw.elapsedMicroseconds / 1000.0);
      }
      final r = ConstantTimeAnalyzer.analyze(times, 'aes256GcmEncrypt');
      results.add(r);
      _collector.recordConstantTimeResult(r);
      expect(r.maxMinRatio, lessThan(100.0));
    });
  });

  group('ECDSA sign constant-time', () {
    test('100 random messages, same key', () {
      final ecKey = api.generateEcKeyPair('prime256v1');
      final keyPem = helpers.pem(ecKey.privateKeyPem);
      final messages = List<Uint8List>.generate(
        100,
        (_) => api.randomBytes(32),
      );
      final times = <double>[];
      for (var i = 0; i < 100; i++) {
        final sw = Stopwatch()..start();
        api.sign(messages[i], keyPem);
        sw.stop();
        times.add(sw.elapsedMicroseconds / 1000.0);
      }
      final r = ConstantTimeAnalyzer.analyze(times, 'ecdsaSign');
      results.add(r);
      _collector.recordConstantTimeResult(r);
      expect(r.cvPercent, lessThan(100.0));
      expect(r.maxMinRatio, lessThan(30.0));
    });
  });

  tearDownAll(() {
  });
}
