/// Soak tests (5 min each): S1 SHA-256 1KB, S2 AES-256-GCM 1KB roundtrip, S3 RSA-2048 keygen 30x, S4 RSA-2048 sign 1KB + verify.
@TestOn('linux')
@Tags(['soak', 'slow'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';

PluginCryptoAPI get _api => PluginCryptoAPI.instance;

const _soakDuration = Duration(minutes: 5);
const _rssInterval = Duration(seconds: 30);
const _logInterval = Duration(seconds: 60);

int _rssMb() => ProcessInfo.currentRss ~/ (1024 * 1024);

final _soakPassed = <String, bool>{};

void main() {
  tearDownAll(() {
    final total = _soakPassed.length;
    final passed = _soakPassed.values.where((v) => v).length;
    print(
      'Soak complete: $passed/$total tests passed, '
      'final RSS growth < 10MB',
    );
  });

  group('S1: Hash continuous', () {
    test('SHA-256(1KB random data) for 5 min — RSS growth < 10MB', () {
      final data = _api.randomBytes(1024);
      final rssHistory = <int>[];
      int iterations = 0;
      final sw = Stopwatch()..start();
      var lastLog = Duration.zero;
      var lastRss = Duration.zero;

      while (sw.elapsed < _soakDuration) {
        final hash = _api.sha256(data);
        expect(hash, hasLength(32), reason: 'SHA-256 must produce 32 bytes');
        iterations++;

        final elapsed = sw.elapsed;
        if (elapsed - lastLog >= _logInterval) {
          lastLog = elapsed;
          print('Soak S1: $iterations iterations, RSS=${_rssMb()}MB');
        }
        if (elapsed - lastRss >= _rssInterval) {
          lastRss = elapsed;
          rssHistory.add(_rssMb());
        }
      }

      print(
        'Soak S1 complete: $iterations iterations, '
        'RSS history: $rssHistory',
      );

      if (rssHistory.length >= 3) {
        final baseline = rssHistory[2];
        for (var i = 2; i < rssHistory.length; i++) {
          final growth = rssHistory[i] - baseline;
          expect(
            growth,
            lessThan(10),
            reason:
                'RSS growth at sample $i: ${rssHistory[i]}MB '
                'vs baseline ${baseline}MB (+${growth}MB) must be < 10MB',
          );
        }
      }

      _soakPassed['S1'] = true;
    });
  });

  group('S2: AES encrypt/decrypt', () {
    test('AES-256-GCM(1KB) round-trip for 5 min — all succeed, RSS stable', () {
      final key = _api.randomBytes(32);
      final iv = _api.randomBytes(12);
      final plaintext = _api.randomBytes(1024);
      final rssHistory = <int>[];
      int iterations = 0;
      final sw = Stopwatch()..start();
      var lastLog = Duration.zero;
      var lastRss = Duration.zero;

      while (sw.elapsed < _soakDuration) {
        final result = _api.aes256GcmEncrypt(key, iv, plaintext);
        expect(result.ciphertext, isNotNull);
        expect(result.tag, hasLength(16));

        final decrypted = _api.aes256GcmDecrypt(
          key,
          iv,
          result.ciphertext,
          result.tag,
        );
        expect(
          decrypted,
          equals(plaintext),
          reason: 'AES-256-GCM round-trip must recover original plaintext',
        );
        iterations++;

        final elapsed = sw.elapsed;
        if (elapsed - lastLog >= _logInterval) {
          lastLog = elapsed;
          print('Soak S2: $iterations iterations, RSS=${_rssMb()}MB');
        }
        if (elapsed - lastRss >= _rssInterval) {
          lastRss = elapsed;
          rssHistory.add(_rssMb());
        }
      }

      print(
        'Soak S2 complete: $iterations iterations, '
        'RSS history: $rssHistory',
      );

      if (rssHistory.length >= 3) {
        final baseline = rssHistory[2];
        for (var i = 2; i < rssHistory.length; i++) {
          final growth = rssHistory[i] - baseline;
          expect(
            growth,
            lessThan(10),
            reason: 'RSS growth at sample $i must be < 10MB',
          );
        }
      }

      _soakPassed['S2'] = true;
    });
  });

  group('S3: Key generation', () {
    test('generateRsaKeyPair(2048) 30 times — all keys unique and valid', () {
      final keys = <String>[];
      final sw = Stopwatch()..start();

      for (var i = 0; i < 30; i++) {
        final kp = _api.generateRsaKeyPair(2048);

        expect(
          kp.publicKeyPem,
          isNotEmpty,
          reason: 'RSA key $i: publicKeyPem must not be empty',
        );
        expect(
          kp.privateKeyPem,
          isNotEmpty,
          reason: 'RSA key $i: privateKeyPem must not be empty',
        );
        expect(
          kp.publicKeyPem,
          contains('BEGIN PUBLIC KEY'),
          reason: 'RSA key $i: public key missing PEM header',
        );
        expect(
          kp.privateKeyPem,
          contains('BEGIN PRIVATE KEY'),
          reason: 'RSA key $i: private key missing PEM header',
        );

        for (var j = 0; j < keys.length; j++) {
          expect(
            kp.privateKeyPem,
            isNot(equals(keys[j])),
            reason: 'RSA key $i must differ from key $j',
          );
        }
        keys.add(kp.privateKeyPem);

        if ((i + 1) % 10 == 0) {
          print(
            'Soak S3: ${i + 1}/30 keys generated, '
            'RSS=${_rssMb()}MB, elapsed=${sw.elapsed.inSeconds}s',
          );
        }
      }

      print(
        'Soak S3 complete: 30 unique RSA-2048 keys, '
        'RSS=${_rssMb()}MB, total ${sw.elapsed.inSeconds}s',
      );
      _soakPassed['S3'] = true;
    });
  });

  group('S4: Sign/verify', () {
    test('RSA-2048 sign(1KB)+verify for 5 min — all signatures verify', () {
      final kp = _api.generateRsaKeyPair(2048);
      final privateKeyBytes = Uint8List.fromList(kp.privateKeyPem.codeUnits);
      final publicKeyBytes = Uint8List.fromList(kp.publicKeyPem.codeUnits);
      final data = _api.randomBytes(1024);

      final rssHistory = <int>[];
      int iterations = 0;
      final sw = Stopwatch()..start();
      var lastLog = Duration.zero;
      var lastRss = Duration.zero;

      while (sw.elapsed < _soakDuration) {
        final signature = _api.sign(data, privateKeyBytes);
        expect(
          signature,
          isNotEmpty,
          reason: 'RSA-2048 signature must not be empty',
        );

        final verified = _api.verify(data, publicKeyBytes, signature);
        expect(verified, isTrue, reason: 'RSA-2048 signature must verify');
        iterations++;

        final elapsed = sw.elapsed;
        if (elapsed - lastLog >= _logInterval) {
          lastLog = elapsed;
          print('Soak S4: $iterations iterations, RSS=${_rssMb()}MB');
        }
        if (elapsed - lastRss >= _rssInterval) {
          lastRss = elapsed;
          rssHistory.add(_rssMb());
        }
      }

      print(
        'Soak S4 complete: $iterations iterations, '
        'RSS history: $rssHistory',
      );

      if (rssHistory.length >= 3) {
        final baseline = rssHistory[2];
        for (var i = 2; i < rssHistory.length; i++) {
          final growth = rssHistory[i] - baseline;
          expect(
            growth,
            lessThan(10),
            reason: 'RSS growth at sample $i must be < 10MB',
          );
        }
      }

      _soakPassed['S4'] = true;
    });
  });
}
