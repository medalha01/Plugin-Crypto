library;

import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/helpers.dart' as helpers;

/// Shared [PluginCryptoAPI] instance.
PluginCryptoAPI get testApi => helpers.api();

/// Access the metrics collector (or `null` when metrics are disabled).
MetricsCollector? get collector => MetricsCollector.instance;

Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  TestWidgetsFlutterBinding.ensureInitialized();

  final metricsOutput = Platform.environment['TCC_METRICS_OUTPUT'];
  if (metricsOutput != null && metricsOutput.isNotEmpty) {
    MetricsCollector.create();
  }

  helpers.api();

  setUp(() {
    helpers.api().clearErrors();
  });

  tearDown(() {
    helpers.api().clearErrors();
  });

  await testMain();
}
