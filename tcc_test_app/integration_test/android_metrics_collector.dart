library;

import 'dart:convert';
import 'dart:io';

import 'package:plugin_crypto/src/metrics/metrics_models.dart';


class SecurityCheckResult {
  final bool passed;
  final Map<String, dynamic> evidence;

  const SecurityCheckResult(this.passed, this.evidence);
}


class AndroidMetricsCollector {

  static AndroidMetricsCollector? _instance;

  /// The singleton instance, or `null` when metrics are disabled.
  static AndroidMetricsCollector? get instance => _instance;

  static AndroidMetricsCollector create() {
    _instance = AndroidMetricsCollector._();
    return _instance!;
  }


  AndroidMetricsCollector._() : _suiteWatch = Stopwatch()..start();

  final Stopwatch _suiteWatch;

  /// Group-level timing records: groupName → duration in microseconds.
  final Map<String, double> _groupDurations = {};
  String? _currentGroupName;
  Stopwatch? _currentGroupWatch;

  /// Operation timing records from inline instrumentation.
  final List<OperationTiming> _operationTimings = [];

  /// Per-test results: testName → TestResult.
  final List<TestResult> _testResults = [];

  /// Amostras de memória: rótulo → RSS kB.
  final Map<String, int> _memorySamples = {};

  /// Contagens de alocações nativas por operação.
  final Map<String, int> _perOperationAllocations = {};

  /// Security check results: checkName → SecurityCheckResult.
  final Map<String, SecurityCheckResult> _securityChecks = {};

  /// Total acumulado de bytes processados em todas as operações.
  int _totalBytesProcessed = 0;

  /// Whether VmRSS is unavailable (all `_readVmRssKb()` calls returned -1).
  bool _vmRssUnavailable = false;


  static int _readVmRssKb() {
    try {
      final file = File('/proc/self/status');
      if (!file.existsSync()) return -1;
      final lines = file.readAsLinesSync();
      for (final line in lines) {
        if (line.startsWith('VmRSS:')) {
          final parts = line.split(RegExp(r'\s+'));
          if (parts.length >= 2) {
            return int.tryParse(parts[1]) ?? -1;
          }
        }
      }
      return -1;
    } on FileSystemException {
      return -1;
    } on FormatException {
      return -1;
    }
  }

  static int readVmRss() {
    final rss = _readVmRssKb();
    if (rss == -1 && _instance != null) {
      _instance!._vmRssUnavailable = true;
    }
    return rss;
  }


  /// Marks the end of the full test suite (stops the suite stopwatch).
  void endSuite() {
    _suiteWatch.stop();
  }


  void startGroup(String name) {
    _currentGroupName = name;
    _currentGroupWatch = Stopwatch()..start();
  }

  void endGroup() {
    if (_currentGroupName != null && _currentGroupWatch != null) {
      _currentGroupWatch!.stop();
      _groupDurations[_currentGroupName!] =
          _currentGroupWatch!.elapsedMicroseconds / 1000.0;
      _currentGroupName = null;
      _currentGroupWatch = null;
    }
  }


  void recordTestResult(String name, String status, int durationMs) {
    _testResults.add(TestResult(
      name: name,
      status: status,
      durationMs: durationMs,
    ));
  }


  /// Record timing for a single crypto operation.
  void recordOperationTiming(OperationTiming timing) {
    _operationTimings.add(timing);
    _totalBytesProcessed += timing.inputSizeBytes;
  }


  void recordMemorySample(String label, int rssKb) {
    _memorySamples[label] = rssKb;
  }

  /// Record a per-operation native allocation count.
  void recordPerOperationAllocations(String operation, int count) {
    _perOperationAllocations[operation] = count;
  }


  /// Record the result of a security property check.
  void recordSecurityCheck(
    String check,
    bool passed,
    Map<String, dynamic> evidence,
  ) {
    _securityChecks[check] = SecurityCheckResult(passed, evidence);
  }


  /// Accumulate bytes processed (used for throughput calculations).
  void addBytesProcessed(int bytes) {
    _totalBytesProcessed += bytes;
  }


  MetricsReport buildReport(
    TimingMetrics timing,
    MemoryMetrics memory,
    ThroughputMetrics throughput,
    SecurityMetrics security,
    ResourceMetrics resource,
    CoverageMetrics coverage,
  ) {
    return MetricsReport(
      schemaVersion: '1.0.0',
      generatedAt: DateTime.now().toUtc().toIso8601String(),
      projectName: 'plugin_crypto',
      timing: timing,
      memory: memory,
      throughput: throughput,
      security: security,
      resource: resource,
      coverage: coverage,
    );
  }

  Future<void> writeJson(
    String path, {
    required TimingMetrics timing,
    required MemoryMetrics memory,
    required ThroughputMetrics throughput,
    required SecurityMetrics security,
    required ResourceMetrics resource,
    required CoverageMetrics coverage,
  }) async {
    final report = buildReport(
      timing,
      memory,
      throughput,
      security,
      resource,
      coverage,
    );
    final encoder = const JsonEncoder.withIndent('  ');
    await File(path).writeAsString(encoder.convert(report.toJson()));
  }


  /// Suite elapsed time in milliseconds.
  double get suiteElapsedMs => _suiteWatch.elapsedMicroseconds / 1000.0;

  /// All recorded test results (unmodifiable).
  List<TestResult> get testResults => List.unmodifiable(_testResults);

  /// All memory samples: label → RSS kB (unmodifiable).
  Map<String, int> get memorySamples => Map.unmodifiable(_memorySamples);

  /// Group name → duration in ms.
  Map<String, double> get perGroupDurationMs =>
      Map.unmodifiable(_groupDurations);

  /// Total number of tests executed.
  int get totalTestsRun => _testResults.length;

  /// Number of passed tests.
  int get totalTestsPassed =>
      _testResults.where((t) => t.status == 'passed').length;

  /// Number of failed tests.
  int get totalTestsFailed =>
      _testResults.where((t) => t.status == 'failed').length;

  /// Number of skipped tests.
  int get totalTestsSkipped =>
      _testResults.where((t) => t.status == 'skipped').length;

  /// Total bytes processed across all timed operations.
  int get totalBytesProcessed => _totalBytesProcessed;

  /// All operation timing records (unmodifiable).
  List<OperationTiming> get operationTimings =>
      List.unmodifiable(_operationTimings);

  /// All security check results (unmodifiable).
  Map<String, SecurityCheckResult> get securityChecks =>
      Map.unmodifiable(_securityChecks);

  /// Per-operation allocation counts (unmodifiable).
  Map<String, int> get perOperationAllocations =>
      Map.unmodifiable(_perOperationAllocations);

  /// Whether VmRSS was unavailable throughout the run.
  bool get vmRssUnavailable => _vmRssUnavailable;
}
