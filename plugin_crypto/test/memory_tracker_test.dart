library;

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/metrics/memory_tracker.dart';

void main() {
  late MemoryTracker tracker;

  setUp(() {
    tracker = MemoryTracker();
  });

  group('MemoryTracker', () {

    test('rssAvailable matches Platform.isLinux', () {
      expect(tracker.rssAvailable, equals(Platform.isLinux));
    });


    test('sampleBytes returns a value for a known label', () {
      final bytes = tracker.sampleBytes('test_label');
      if (Platform.isLinux) {
        expect(bytes, greaterThan(0));
      } else {
        expect(bytes, equals(-1));
      }
    });

    test('sampleBytes returns different values for different labels', () {
      final a = tracker.sampleBytes('first');
      final b = tracker.sampleBytes('second');
      if (Platform.isLinux) {
        expect(a, greaterThan(0));
        expect(b, greaterThan(0));
      } else {
        expect(a, equals(-1));
        expect(b, equals(-1));
      }
    });


    test('sampleKb returns bytes ~/ 1024 on Linux, -1 otherwise', () {
      final bytes = tracker.sampleBytes('kb_test');
      final kb = tracker.sampleKb('kb_test');
      if (Platform.isLinux) {
        expect(kb, equals(bytes ~/ 1024));
        expect(kb, greaterThanOrEqualTo(0));
      } else {
        expect(kb, equals(-1));
      }
    });


    test('getSample returns correct value for existing label', () {
      tracker.sampleBytes('existing');
      final val = tracker.getSample('existing');
      if (Platform.isLinux) {
        expect(val, greaterThan(0));
      } else {
        expect(val, equals(-1));
      }
    });

    test('getSample returns -1 for missing label', () {
      expect(tracker.getSample('nonexistent'), equals(-1));
    });

    test('getSample returns last value when label is sampled twice', () {
      tracker.sampleBytes('repeated');
      final second = tracker.sampleBytes('repeated');
      final val = tracker.getSample('repeated');
      expect(val, equals(second));
    });


    test('delta computes difference between two labels', () {
      tracker.sampleBytes('start');
      tracker.sampleBytes('end');
      final d = tracker.delta('start', 'end');
      if (Platform.isLinux) {
        expect(d, isNot(equals(-1)));
      } else {
        expect(d, equals(-1));
      }
    });

    test('delta returns -1 when one label is missing', () {
      tracker.sampleBytes('only_start');
      expect(tracker.delta('only_start', 'missing_end'), equals(-1));
      expect(tracker.delta('missing_start', 'only_start'), equals(-1));
    });


    test('recordAllocation stores and allocations returns it', () {
      expect(tracker.allocations, isEmpty);
      tracker.recordAllocation('sha256', 2);
      tracker.recordAllocation('aesCbcEncrypt', 4);
      expect(tracker.allocations['sha256'], equals(2));
      expect(tracker.allocations['aesCbcEncrypt'], equals(4));
    });

    test('recordAllocation overwrites previous value for same operation', () {
      tracker.recordAllocation('sha256', 2);
      tracker.recordAllocation('sha256', 5);
      expect(tracker.allocations['sha256'], equals(5));
    });

    test('allocations returns unmodifiable map', () {
      tracker.recordAllocation('sha256', 2);
      final allocs = tracker.allocations;
      expect(() => allocs['newKey'] = 1, throwsUnsupportedError);
    });


    test('samples returns empty map when no samples taken', () {
      expect(tracker.samples, isEmpty);
    });

    test('samples returns all sampled labels with values', () {
      tracker.sampleBytes('alpha');
      tracker.sampleBytes('beta');
      tracker.sampleBytes('gamma');
      final s = tracker.samples;
      expect(s.containsKey('alpha'), isTrue);
      expect(s.containsKey('beta'), isTrue);
      expect(s.containsKey('gamma'), isTrue);
      expect(s.length, equals(3));
    });

    test('samples last value wins for duplicate labels', () {
      tracker.sampleBytes('dup');
      final second = tracker.sampleBytes('dup');
      final s = tracker.samples;
      expect(s['dup'], equals(second));
    });


    test('notes contains platform information', () {
      final note = tracker.notes;
      if (Platform.isLinux) {
        expect(note, contains('ProcessInfo.currentRss'));
      } else {
        expect(note, contains('unavailable'));
      }
    });
  });
}
