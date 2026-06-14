library;

import 'dart:io';

/// Tracks memory usage during the test suite by sampling RSS.
class MemoryTracker {
  final List<_MemorySample> _samples = [];
  final Map<String, int> _allocationCounts = {};

  /// Whether RSS sampling is available (Linux only).
  bool get rssAvailable => Platform.isLinux;

  int sampleBytes(String label) {
    int rssBytes;
    if (rssAvailable) {
      try {
        rssBytes = ProcessInfo.currentRss;
      } catch (_) {
        rssBytes = -1;
      }
    } else {
      rssBytes = -1;
    }
    _samples.add(_MemorySample(label, rssBytes, DateTime.now()));
    return rssBytes;
  }

  /// Take a labeled RSS sample and return the value in kilobytes.
  int sampleKb(String label) {
    final bytes = sampleBytes(label);
    return bytes >= 0 ? bytes ~/ 1024 : -1;
  }

  /// Get a specific sample by label. Returns -1 if not found.
  int getSample(String label) {
    final s = _samples.where((s) => s.label == label);
    return s.isNotEmpty ? s.last.rssBytes : -1;
  }

  /// Compute the delta in RSS between two labeled samples.
  int delta(String label1, String label2) {
    final a = getSample(label1);
    final b = getSample(label2);
    if (a < 0 || b < 0) return -1;
    return b - a;
  }

  /// Register a per-operation native allocation count.
  void recordAllocation(String operation, int count) {
    _allocationCounts[operation] = count;
  }

  /// Get all samples as a label → RSS bytes map.
  Map<String, int> get samples {
    final map = <String, int>{};
    for (final s in _samples) {
      map[s.label] = s.rssBytes;
    }
    return map;
  }

  /// Get all allocation counts.
  Map<String, int> get allocations => Map.unmodifiable(_allocationCounts);

  /// Returns platform-specific notes about memory measurement.
  String get notes {
    if (rssAvailable) {
      return 'RSS sampling via ProcessInfo.currentRss (Linux). '
          'Raw samples are collected in bytes, converted to KB in '
          'MemoryMetrics report fields.';
    }
    return 'RSS sampling unavailable on ${Platform.operatingSystem}. '
        'Using native allocation counting as proxy.';
  }
}

class _MemorySample {
  final String label;
  final int rssBytes;
  final DateTime timestamp;
  _MemorySample(this.label, this.rssBytes, this.timestamp);
}
