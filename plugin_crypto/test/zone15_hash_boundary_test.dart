import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

/// Creates a Uint8List of [length] bytes, each byte being `length` as well.
Uint8List _repeatedByte(int length, int byte) =>
    Uint8List.fromList(List.filled(length, byte));

/// Hex string → Uint8List (for expected-hash comparison).
Uint8List _bytes(String hex) {
  final len = hex.length;
  final result = Uint8List(len ~/ 2);
  for (var i = 0; i < len; i += 2) {
    result[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return result;
}

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone15', 'Hash Boundary');

  final api = PluginCryptoAPI.instance;


  group('SHA-256 padding boundary', () {
    test('55-byte input (fits in one block)', () {
      final data = _repeatedByte(55, 0x61); // 55 x 'a'
      final hash = api.sha256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha256(data);
      expect(hash, equals(hash2));
    });

    test('56-byte input (spans two blocks)', () {
      final data = _repeatedByte(56, 0x61); // 56 x 'a'
      final hash = api.sha256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha256(data);
      expect(hash, equals(hash2));
    });

    test('55 vs 56 bytes produce different hashes', () {
      final h55 = api.sha256(_repeatedByte(55, 0x61));
      final h56 = api.sha256(_repeatedByte(56, 0x61));
      expect(h55, isNot(equals(h56)));
    });
  });


  group('SHA-512 padding boundary', () {
    test('111-byte input (fits in one block)', () {
      final data = _repeatedByte(111, 0x61);
      final hash = api.sha512(data);
      expect(hash.length, equals(64));
      final hash2 = api.sha512(data);
      expect(hash, equals(hash2));
    });

    test('112-byte input (spans two blocks)', () {
      final data = _repeatedByte(112, 0x61);
      final hash = api.sha512(data);
      expect(hash.length, equals(64));
      final hash2 = api.sha512(data);
      expect(hash, equals(hash2));
    });

    test('111 vs 112 bytes produce different hashes', () {
      final h111 = api.sha512(_repeatedByte(111, 0x61));
      final h112 = api.sha512(_repeatedByte(112, 0x61));
      expect(h111, isNot(equals(h112)));
    });
  });


  group('SHA3-256 sponge boundary', () {
    test('135-byte input (one absorption round)', () {
      final data = _repeatedByte(135, 0x61);
      final hash = api.sha3_256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha3_256(data);
      expect(hash, equals(hash2));
    });

    test('136-byte input (exactly fills rate, triggers next round)', () {
      final data = _repeatedByte(136, 0x61);
      final hash = api.sha3_256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha3_256(data);
      expect(hash, equals(hash2));
    });

    test('137-byte input (spans two absorption rounds)', () {
      final data = _repeatedByte(137, 0x61);
      final hash = api.sha3_256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha3_256(data);
      expect(hash, equals(hash2));
    });

    test('135 vs 136 bytes produce different hashes', () {
      final h135 = api.sha3_256(_repeatedByte(135, 0x61));
      final h136 = api.sha3_256(_repeatedByte(136, 0x61));
      expect(h135, isNot(equals(h136)));
    });
  });


  group('SHA3-512 sponge boundary', () {
    test('71-byte input (one absorption round)', () {
      final data = _repeatedByte(71, 0x61);
      final hash = api.sha3_512(data);
      expect(hash.length, equals(64));
      final hash2 = api.sha3_512(data);
      expect(hash, equals(hash2));
    });

    test('72-byte input (exactly fills rate, triggers next round)', () {
      final data = _repeatedByte(72, 0x61);
      final hash = api.sha3_512(data);
      expect(hash.length, equals(64));
      final hash2 = api.sha3_512(data);
      expect(hash, equals(hash2));
    });

    test('73-byte input (spans two absorption rounds)', () {
      final data = _repeatedByte(73, 0x61);
      final hash = api.sha3_512(data);
      expect(hash.length, equals(64));
      final hash2 = api.sha3_512(data);
      expect(hash, equals(hash2));
    });

    test('71 vs 72 bytes produce different hashes', () {
      final h71 = api.sha3_512(_repeatedByte(71, 0x61));
      final h72 = api.sha3_512(_repeatedByte(72, 0x61));
      expect(h71, isNot(equals(h72)));
    });
  });


  group('Consecutive SHA-256 calls with same instance', () {
    test('repeated sha256 of same input yields identical results', () {
      final data = utf8.encode('consistent hashing');
      final results = <Uint8List>[];
      for (var i = 0; i < 10; i++) {
        results.add(api.sha256(data));
      }
      for (var i = 1; i < results.length; i++) {
        expect(results[i], equals(results[0]));
      }
    });

    test('repeated sha256 of different inputs works correctly', () {
      for (var i = 0; i < 10; i++) {
        final data = utf8.encode('message $i');
        final hash = api.sha256(data);
        expect(hash.length, equals(32));
      }
    });

    test('interleaved sha256 and sha512 do not corrupt state', () {
      final a = utf8.encode('hello');
      final b = utf8.encode('world');

      final sha256A = api.sha256(a);
      final sha512B = api.sha512(b);
      final sha256Aagain = api.sha256(a);
      final sha512Bagain = api.sha512(b);

      expect(sha256A, equals(sha256Aagain));
      expect(sha512B, equals(sha512Bagain));
      expect(sha256A.length, equals(32));
      expect(sha512B.length, equals(64));
    });
  });


  group('SHA-256 of 1-byte input', () {
    test('single byte 0x00', () {
      final hash = api.sha256(Uint8List.fromList([0x00]));
      expect(hash.length, equals(32));
      final expected = _bytes(
        '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
      );
      expect(hash, equals(expected));
    });

    test('single byte 0xFF', () {
      final hash = api.sha256(Uint8List.fromList([0xFF]));
      expect(hash.length, equals(32));
    });
  });

  group('SHA-256 of 64-byte input', () {
    test('exactly one block worth of data', () {
      final data = _repeatedByte(64, 0x41); // 64 x 'A'
      final hash = api.sha256(data);
      expect(hash.length, equals(32));
      final hash2 = api.sha256(data);
      expect(hash, equals(hash2));
    });
  });

  group('SHA-512 of 1-byte input', () {
    test('single byte 0x00', () {
      final hash = api.sha512(Uint8List.fromList([0x00]));
      expect(hash.length, equals(64));
    });

    test('single byte 0xFF', () {
      final hash = api.sha512(Uint8List.fromList([0xFF]));
      expect(hash.length, equals(64));
    });
  });

  m?.endZone();
}
