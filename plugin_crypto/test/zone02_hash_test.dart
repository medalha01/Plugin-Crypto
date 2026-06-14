import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

String _hex(Uint8List b) =>
    b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone02', 'Hash/Verification');

  final crypto = PluginCryptoAPI.instance;

  group('SHA-256', () {
    test('empty string', () {
      final hash = crypto.sha256(utf8.encode(''));
      expect(
        _hex(hash),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
      expect(hash.length, 32);
    });

    test('abc', () {
      final hash = crypto.sha256(utf8.encode('abc'));
      expect(
        _hex(hash),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', () {
      final hash = crypto.sha256(
        utf8.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
      );
      expect(
        _hex(hash),
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
      );
    });

    test('returns 32 bytes', () {
      final hash = crypto.sha256(utf8.encode('hello'));
      expect(hash.length, 32);
    });
  });

  group('SHA-512', () {
    test('empty string', () {
      final hash = crypto.sha512(utf8.encode(''));
      expect(
        _hex(hash),
        'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce'
        '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
      );
      expect(hash.length, 64);
    });

    test('abc', () {
      final hash = crypto.sha512(utf8.encode('abc'));
      expect(
        _hex(hash),
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      );
    });

    test('returns 64 bytes', () {
      final hash = crypto.sha512(utf8.encode('hello'));
      expect(hash.length, 64);
    });
  });

  group('SHA3-256', () {
    test('empty string', () {
      final hash = crypto.sha3_256(utf8.encode(''));
      expect(
        _hex(hash),
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
      );
      expect(hash.length, 32);
    });

    test('abc', () {
      final hash = crypto.sha3_256(utf8.encode('abc'));
      expect(
        _hex(hash),
        '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
      );
    });

    test('returns 32 bytes', () {
      final hash = crypto.sha3_256(utf8.encode('hello'));
      expect(hash.length, 32);
    });
  });

  group('SHA3-512', () {
    test('empty string', () {
      final hash = crypto.sha3_512(utf8.encode(''));
      expect(
        _hex(hash),
        'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
        '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
      );
      expect(hash.length, 64);
    });

    test('abc', () {
      final hash = crypto.sha3_512(utf8.encode('abc'));
      expect(
        _hex(hash),
        'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e'
        '10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
      );
    });

    test('returns 64 bytes', () {
      final hash = crypto.sha3_512(utf8.encode('hello'));
      expect(hash.length, 64);
    });
  });

  m?.endZone();
}
