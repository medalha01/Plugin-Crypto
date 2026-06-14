library;

import 'dart:convert';
import 'dart:io';

import 'metrics_models.dart';

MetricsCollector? get metricsCollector => MetricsCollector._instance;

class MetricsCollector {

  static MetricsCollector? _instance;

  /// Retorna a instância singleton, ou `null` se a coleta de métricas estiver desabilitada.
  static MetricsCollector? get instance => _instance;

  /// Cria o singleton. Chame exatamente uma vez na inicialização da suíte quando
  /// `TCC_METRICS_OUTPUT` estiver definido.
  static MetricsCollector create() {
    _instance = MetricsCollector._();
    return _instance!;
  }


  MetricsCollector._() : _suiteWatch = Stopwatch()..start();

  final Stopwatch _suiteWatch;

  /// Rastreamento de zonas: id → {nome, horaInício, horaFim}.
  final List<_ZoneRecord> _zones = [];
  _ZoneRecord? _currentZone;

  /// Registros de tempo de operação de micro-benchmarks.
  final List<OperationTiming> _operationTimings = [];

  /// Resultados por teste.
  final List<TestResult> _testResults = [];

  /// Amostras de memória: rótulo → RSS kB.
  final Map<String, int> _memorySamples = {};

  /// Contagens de alocações nativas por operação.
  final Map<String, int> _perOperationAllocations = {};

  /// Resultados de verificações de segurança: nome → {aprovado: bool, evidência: map}.
  final Map<String, SecurityCheckResult> _securityChecks = {};

  /// Snapshots de histograma para distribuições estatísticas por operação.
  final List<HistogramSnapshot> _histograms = [];

  /// Amostras brutas individuais de cada medição de Stopwatch.
  final List<RawTimingSample> _rawSamples = [];

  /// Agregados por categoria calculados no momento da construção do relatório.
  final List<CategorySummary> _categorySummaries = [];

  /// Métricas de desempenho de cifra dos benchmarks de segurança.
  final List<CipherPerformanceMetrics> _cipherPerformance = [];

  /// Resultados agregados de comparação de suíte de cifras.
  CipherSuiteComparisonMetrics? _cipherSuiteComparison;

  /// Resultados de simulação de sessão TLS.
  TlsSimulationMetrics? _tlsSimulation;

  /// Total acumulado de bytes processados em todas as operações.
  int _totalBytesProcessed = 0;

  /// Resumos KAT (Known Answer Test) por algoritmo.
  final List<KatSummary> _katSummaries = [];

  /// Resultados de análise de tempo constante por operação.
  final List<ConstantTimeResult> _constantTimeResults = [];

  /// Resultado da verificação de zeroização / higiene de memória.
  ZeroizationMetrics? _zeroizationMetrics;

  /// Resultado de robustez de fuzzing / casos extremos.
  FuzzingMetrics? _fuzzingMetrics;

  /// Pontos de dados de escalabilidade de isolates para análise de concorrência.
  final List<IsolateScalingPoint> _scalingPoints = [];


  /// Registra o fim da suíte completa.
  void endSuite() {
    _suiteWatch.stop();
  }


  void startZone(String id, String name) {
    _currentZone = _ZoneRecord(id, name, DateTime.now(), null);
  }

  void endZone() {
    if (_currentZone != null) {
      _currentZone!.end = DateTime.now();
      _zones.add(_currentZone!);
      _currentZone = null;
    }
  }


  void recordTestResult(String name, String status, int durationMs) {
    _testResults.add(
      TestResult(name: name, status: status, durationMs: durationMs),
    );
  }


  void recordOperationTiming(OperationTiming timing) {
    _operationTimings.add(timing);
    _totalBytesProcessed += timing.inputSizeBytes;
  }


  void recordMemorySample(String label, int rssKb) {
    _memorySamples[label] = rssKb;
  }

  void recordPerOperationAllocations(String operation, int count) {
    _perOperationAllocations[operation] = count;
  }


  void recordSecurityCheck(
    String check,
    bool passed,
    Map<String, dynamic> evidence,
  ) {
    _securityChecks[check] = SecurityCheckResult(passed, evidence);
  }

  /// Registra um snapshot de histograma por operação.
  void recordHistogram(HistogramSnapshot snapshot) {
    _histograms.add(snapshot);
  }

  /// Registra uma amostra bruta individual de tempo.
  void recordRawSample(RawTimingSample sample) {
    _rawSamples.add(sample);
  }

  /// Registra um resumo agregado por categoria.
  void recordCategorySummary(CategorySummary summary) {
    _categorySummaries.add(summary);
  }

  /// Registra métricas de desempenho de cifra de uma execução de comparação.
  void recordCipherPerformance(CipherPerformanceMetrics metrics) {
    _cipherPerformance.add(metrics);
  }

  /// Registra o resultado completo da comparação de suíte de cifras.
  void recordCipherSuiteComparison(CipherSuiteComparisonMetrics comparison) {
    _cipherSuiteComparison = comparison;
  }

  /// Registra resultados de simulação de sessão TLS.
  void recordTlsSimulation(TlsSimulationMetrics simulation) {
    _tlsSimulation = simulation;
  }

  /// Registra um resumo KAT (Known Answer Test) para um algoritmo.
  void recordKatSummary(KatSummary s) {
    _katSummaries.add(s);
  }

  /// Registra um resultado de análise de tempo constante para uma operação.
  void recordConstantTimeResult(ConstantTimeResult r) {
    _constantTimeResults.add(r);
  }

  /// Armazena o resultado da verificação de zeroização / higiene de memória.
  void setZeroizationMetrics(ZeroizationMetrics z) {
    _zeroizationMetrics = z;
  }

  /// Armazena o resultado de robustez de fuzzing / casos extremos.
  void setFuzzingMetrics(FuzzingMetrics f) {
    _fuzzingMetrics = f;
  }

  /// Registra um ponto de dados de escalabilidade de concorrência para uma contagem de isolates.
  void recordScalingPoint(IsolateScalingPoint p) {
    _scalingPoints.add(p);
  }


  void addBytesProcessed(int bytes) {
    _totalBytesProcessed += bytes;
  }


  /// Componentes de relatório armazenados para escrita JSON deferida.
  TimingMetrics? _storedTiming;
  MemoryMetrics? _storedMemory;
  ThroughputMetrics? _storedThroughput;
  SecurityMetrics? _storedSecurity;
  ResourceMetrics? _storedResource;
  CoverageMetrics? _storedCoverage;

  void storeReportComponents({
    required TimingMetrics timing,
    required MemoryMetrics memory,
    required ThroughputMetrics throughput,
    required SecurityMetrics security,
    required ResourceMetrics resource,
    required CoverageMetrics coverage,
  }) {
    _storedTiming = timing;
    _storedMemory = memory;
    _storedThroughput = throughput;
    _storedSecurity = security;
    _storedResource = resource;
    _storedCoverage = coverage;
  }

  Future<void> writeStoredReport(String path) async {
    final t = _storedTiming;
    final m = _storedMemory;
    final tp = _storedThroughput;
    final sec = _storedSecurity;
    final res = _storedResource;
    final cov = _storedCoverage;
    if (t == null ||
        m == null ||
        tp == null ||
        sec == null ||
        res == null ||
        cov == null) {
      stderr.writeln(
        '[MetricsCollector] Cannot write stored report — components not stored',
      );
      return;
    }
    final report = buildReport(t, m, tp, sec, res, cov);
    final encoder = JsonEncoder.withIndent('  ');
    await File(path).writeAsString(encoder.convert(report.toJson()));
    stderr.writeln('[MetricsCollector] Report written to $path');
  }

  /// Constrói o [MetricsReport] completo a partir de todos os dados coletados.
  MetricsReport buildReport(
    TimingMetrics timing,
    MemoryMetrics memory,
    ThroughputMetrics throughput,
    SecurityMetrics security,
    ResourceMetrics resource,
    CoverageMetrics coverage,
  ) {
    final mergedSecurity = SecurityMetrics(
      entropyRandomBytes1024: security.entropyRandomBytes1024,
      entropyPassed: security.entropyPassed,
      chiSquared: security.chiSquared,
      chiSquaredPValue: security.chiSquaredPValue,
      chiSquaredPassed: security.chiSquaredPassed,
      rsaKeyUniquenessRate: security.rsaKeyUniquenessRate,
      ecKeyUniquenessRate: security.ecKeyUniquenessRate,
      signatureNondeterminismRsa: security.signatureNondeterminismRsa,
      signatureNondeterminismEcdsa: security.signatureNondeterminismEcdsa,
      ivUniquenessRate: security.ivUniquenessRate,
      gcmTagAuthEnforced: security.gcmTagAuthEnforced,
      gcmAadBindingEnforced: security.gcmAadBindingEnforced,
      crossKeyRejection: security.crossKeyRejection,
      summary: security.summary,
      safeCurveChecklist: security.safeCurveChecklist,
      katSummaries: List.unmodifiable(_katSummaries),
    );

    final ConstantTimeMetrics? constantTime;
    if (_constantTimeResults.isNotEmpty) {
      final passing = _constantTimeResults
          .where((r) => r.likelyConstantTime)
          .length;
      constantTime = ConstantTimeMetrics(
        results: List.unmodifiable(_constantTimeResults),
        summary:
            '$passing/${_constantTimeResults.length} operations pass '
            'constant-time analysis',
      );
    } else {
      constantTime = null;
    }

    final ConcurrencyMetrics? concurrency;
    if (_scalingPoints.isNotEmpty) {
      concurrency = ConcurrencyMetrics(
        availableCores: Platform.numberOfProcessors,
        scalingPoints: List.unmodifiable(_scalingPoints),
      );
    } else {
      concurrency = null;
    }

    return MetricsReport(
      schemaVersion: '1.2.0',
      generatedAt: DateTime.now().toUtc().toIso8601String(),
      projectName: 'plugin_crypto',
      timing: timing,
      memory: memory,
      throughput: throughput,
      security: mergedSecurity,
      resource: resource,
      coverage: coverage,
      cipherSuiteComparison: _cipherSuiteComparison,
      tlsSimulation: _tlsSimulation,
      constantTime: constantTime,
      zeroization: _zeroizationMetrics,
      fuzzing: _fuzzingMetrics,
      concurrency: concurrency,
    );
  }

  /// Escreve o relatório em disco como JSON formatado.
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
    final encoder = JsonEncoder.withIndent('  ');
    await File(path).writeAsString(encoder.convert(report.toJson()));
  }


  double get suiteElapsedMs => _suiteWatch.elapsedMicroseconds / 1000.0;

  List<TestResult> get testResults => List.unmodifiable(_testResults);

  Map<String, double> get perZoneDurationMs {
    final map = <String, double>{};
    for (final z in _zones) {
      if (z.end != null) {
        map[z.id] = z.end!.difference(z.start).inMicroseconds / 1000.0;
      }
    }
    return map;
  }

  int get totalTestsRun => _testResults.length;

  int get totalTestsPassed =>
      _testResults.where((t) => t.status == 'passed').length;

  int get totalTestsFailed =>
      _testResults.where((t) => t.status == 'failed').length;

  int get totalTestsSkipped =>
      _testResults.where((t) => t.status == 'skipped').length;

  int get totalBytesProcessed => _totalBytesProcessed;

  Map<String, int> get memorySamples => Map.unmodifiable(_memorySamples);

  Map<String, int> get perOperationAllocations =>
      Map.unmodifiable(_perOperationAllocations);

  Map<String, SecurityCheckResult> get securityChecks =>
      Map.unmodifiable(_securityChecks);

  List<OperationTiming> get operationTimings =>
      List.unmodifiable(_operationTimings);

  List<HistogramSnapshot> get histograms => List.unmodifiable(_histograms);

  List<RawTimingSample> get rawSamples => List.unmodifiable(_rawSamples);

  List<CategorySummary> get categorySummaries =>
      List.unmodifiable(_categorySummaries);

  List<CipherPerformanceMetrics> get cipherPerformance =>
      List.unmodifiable(_cipherPerformance);

  CipherSuiteComparisonMetrics? get cipherSuiteComparison =>
      _cipherSuiteComparison;

  TlsSimulationMetrics? get tlsSimulation => _tlsSimulation;

  List<KatSummary> get katSummaries => List.unmodifiable(_katSummaries);

  List<ConstantTimeResult> get constantTimeResults =>
      List.unmodifiable(_constantTimeResults);

  ZeroizationMetrics? get zeroizationMetrics => _zeroizationMetrics;

  FuzzingMetrics? get fuzzingMetrics => _fuzzingMetrics;

  List<IsolateScalingPoint> get scalingPoints =>
      List.unmodifiable(_scalingPoints);

  List<CategorySummary> computeCategorySummaries() {
    _categorySummaries.clear();

    final byCategory = <String, List<OperationTiming>>{};
    for (final t in _operationTimings) {
      byCategory.putIfAbsent(t.category, () => []).add(t);
    }

    for (final entry in byCategory.entries) {
      final category = entry.key;
      final timings = entry.value;
      final opCount = timings.length;

      var totalWarm = 0.0;
      var totalCold = 0.0;
      var totalMeasurements = 0;
      var sumThroughput = 0.0;
      var maxThroughput = 0.0;
      var minThroughput = double.infinity;
      var weightedSum = 0.0;
      var totalInputBytes = 0;

      for (final t in timings) {
        totalWarm += t.warmMs;
        totalCold += t.coldMs;
        totalMeasurements += t.iterationsWarm;
        sumThroughput += t.throughputMbps;
        if (t.throughputMbps > maxThroughput) maxThroughput = t.throughputMbps;
        if (t.throughputMbps < minThroughput) minThroughput = t.throughputMbps;
        if (t.inputSizeBytes > 0) {
          weightedSum += t.throughputMbps * t.inputSizeBytes;
          totalInputBytes += t.inputSizeBytes;
        }
      }

      if (minThroughput == double.infinity) minThroughput = 0.0;

      final meanThroughput = opCount > 0 ? sumThroughput / opCount : 0.0;
      final weightedThroughput = totalInputBytes > 0
          ? weightedSum / totalInputBytes
          : 0.0;

      final summary = CategorySummary(
        category: category,
        operationCount: opCount,
        totalMeasurements: totalMeasurements,
        totalWarmTimeMs: totalWarm,
        totalColdTimeMs: totalCold,
        meanThroughputMbps: meanThroughput,
        maxThroughputMbps: maxThroughput,
        minThroughputMbps: minThroughput,
        weightedThroughputMbps: weightedThroughput,
      );
      _categorySummaries.add(summary);
    }

    return List.unmodifiable(_categorySummaries);
  }
}


class _ZoneRecord {
  final String id;
  final String name;
  final DateTime start;
  DateTime? end;
  _ZoneRecord(this.id, this.name, this.start, this.end);
}

class SecurityCheckResult {
  final bool passed;
  final Map<String, dynamic> evidence;
  SecurityCheckResult(this.passed, this.evidence);
}
