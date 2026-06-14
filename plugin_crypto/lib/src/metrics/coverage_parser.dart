library;

import 'dart:io';

import 'metrics_models.dart';

/// Parses an LCOV tracefile and produces [CoverageMetrics].
class LcovParser {
  CoverageMetrics parse(String lcovPath) {
    final file = File(lcovPath);
    if (!file.existsSync()) {
      return CoverageMetrics(
        coverageAvailable: false,
        overallLineCoveragePct: 0.0,
        perFile: [],
        filesAbove80Pct: 0,
        filesBelow50Pct: 0,
        apiMethodsTotal: 0,
        apiMethodsTested: 0,
        ffiBindingsTotal: 0,
        ffiBindingsExercised: 0,
        notes: 'lcov.info not found. Run with --coverage to generate.',
      );
    }

    final content = file.readAsStringSync();
    final records = _parseRecords(content);
    final perFile = <FileCoverage>[];

    for (final record in records) {
      final sf = record['SF'] as String?;
      if (sf == null) continue;
      final daList = record['DA'] as List<dynamic>?;
      if (daList == null || daList.isEmpty) continue;
      final daEntries = daList.cast<Map<String, dynamic>>();

      final totalLines = daEntries.length;
      final coveredLines = daEntries.where((e) {
        final hitStr = e['hit'] as String? ?? '0';
        final hit = int.tryParse(hitStr) ?? 0;
        return hit > 0;
      }).length;
      final pct = totalLines > 0 ? (coveredLines / totalLines) * 100.0 : 0.0;

      perFile.add(
        FileCoverage(
          filePath: sf,
          totalLines: totalLines,
          coveredLines: coveredLines,
          coveragePct: pct,
        ),
      );
    }

    final totalLines = perFile.fold<int>(0, (s, f) => s + f.totalLines);
    final coveredLines = perFile.fold<int>(0, (s, f) => s + f.coveredLines);
    final overallPct = totalLines > 0
        ? (coveredLines / totalLines) * 100.0
        : 0.0;

    final above80 = perFile.where((f) => f.coveragePct >= 80.0).length;
    final below50 = perFile.where((f) => f.coveragePct < 50.0).length;

    return CoverageMetrics(
      coverageAvailable: true,
      overallLineCoveragePct: overallPct,
      perFile: perFile,
      filesAbove80Pct: above80,
      filesBelow50Pct: below50,
      apiMethodsTotal: 0,
      apiMethodsTested: 0,
      ffiBindingsTotal: 0,
      ffiBindingsExercised: 0,
      notes: 'Parsed from $lcovPath',
    );
  }

  /// Parse raw LCOV content into a list of record maps.
  List<Map<String, dynamic>> _parseRecords(String content) {
    final records = <Map<String, dynamic>>[];
    Map<String, dynamic>? current;
    List<Map<String, String>>? currentDa;

    for (final line in content.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;

      if (trimmed == 'end_of_record') {
        if (current != null) {
          if (currentDa != null && currentDa.isNotEmpty) {
            current['DA'] = currentDa;
          }
          records.add(current);
        }
        current = null;
        currentDa = null;
        continue;
      }

      current ??= <String, dynamic>{};

      final colon = trimmed.indexOf(':');
      if (colon < 0) continue;

      final token = trimmed.substring(0, colon);

      switch (token) {
        case 'TN':
          current['TN'] = trimmed.substring(colon + 1);
          break;
        case 'SF':
          current['SF'] = trimmed.substring(colon + 1);
          break;
        case 'DA':
          final list = currentDa ??= [];
          final value = trimmed.substring(colon + 1);
          final comma = value.indexOf(',');
          if (comma > 0) {
            list.add({
              'line': value.substring(0, comma),
              'hit': value.substring(comma + 1),
            });
          }
          break;
        case 'LF':
          current['LF'] = int.tryParse(trimmed.substring(colon + 1)) ?? 0;
          break;
        case 'LH':
          current['LH'] = int.tryParse(trimmed.substring(colon + 1)) ?? 0;
          break;
      }
    }

    return records;
  }
}

/// Convenience function: parse coverage from default lcov.info location.
CoverageMetrics parseCoverage(String lcovPath) {
  return LcovParser().parse(lcovPath);
}
