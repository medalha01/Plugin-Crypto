/// Combinatorial tests: C1 AES key-size × CBC/GCM, C2 RSA key-size × sign/verify, C3 EC curve × sign/verify, C4 SHA size × streaming.
@TestOn('linux')
@Tags(['combinatorial', 'exhaustive'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';


PluginCryptoAPI get _api => PluginCryptoAPI.instance;

/// Pre-allocated 1 MB buffer for large-data tests.
final _buf1MB = Uint8List(1048576);

void main() {
  group('C1: Algorithm x Size', () {
    test('SHA-256/512/SHA3-256/SHA3-512 x [0,1,63,64,65,1024,1MB]', () {
      final algorithms = <String, Uint8List Function(Uint8List)>{
        'SHA-256': _api.sha256,
        'SHA-512': _api.sha512,
        'SHA3-256': _api.sha3_256,
        'SHA3-512': _api.sha3_512,
      };

      final expectedLen = <String, int>{
        'SHA-256': 32,
        'SHA-512': 64,
        'SHA3-256': 32,
        'SHA3-512': 64,
      };

      final sizes = <int>[0, 1, 63, 64, 65, 1024, 1048576];

      int passed = 0;
      int total = 0;
      final failures = <String>[];

      for (final algoEntry in algorithms.entries) {
        final algoName = algoEntry.key;
        final hashFn = algoEntry.value;

        for (final size in sizes) {
          total++;
          try {
            Uint8List data;
            if (size == 1048576) {
              data = _buf1MB;
            } else if (size == 0) {
              data = Uint8List(0);
            } else {
              data = _api.randomBytes(size);
            }

            final hash = hashFn(data);
            expect(
              hash,
              hasLength(expectedLen[algoName]),
              reason:
                  '$algoName($size bytes) must produce '
                  '${expectedLen[algoName]} bytes',
            );
            passed++;
          } catch (e) {
            failures.add('$algoName($size bytes): $e');
          }
        }
      }

      if (failures.isNotEmpty) {
        fail('Combinatorial C1 failures:\n${failures.join('\n')}');
      }

      print('Combinatorial C1: $passed/$total combinations passed');
      expect(passed, equals(total));
    });
  });

  group('C2: AES x Key x Mode x Plaintext', () {
    test('[128,256] x [GCM,CBC] x [0,1,16,17,1024] bytes — round-trip', () {
      final keySizes = <int>[128, 256];
      final plaintextSizes = <int>[0, 1, 16, 17, 1024];

      int passed = 0;
      int total = 0;
      final failures = <String>[];

      for (final keyBits in keySizes) {
        final keyLen = keyBits ~/ 8;
        final key = _api.randomBytes(keyLen);

        for (final ptSize in plaintextSizes) {
          total++;
          final label = 'AES-$keyBits-GCM(pt=$ptSize)';
          try {
            final iv = _api.randomBytes(12);
            final plaintext = ptSize == 0
                ? Uint8List(0)
                : _api.randomBytes(ptSize);

            Uint8List ciphertext;
            Uint8List tag;

            if (keyBits == 128) {
              final result = _api.aes128GcmEncrypt(key, iv, plaintext);
              ciphertext = result.ciphertext;
              tag = result.tag;
            } else {
              final result = _api.aes256GcmEncrypt(key, iv, plaintext);
              ciphertext = result.ciphertext;
              tag = result.tag;
            }

            expect(tag, hasLength(16), reason: '$label: tag must be 16 bytes');
            expect(
              ciphertext,
              hasLength(ptSize),
              reason:
                  '$label: ciphertext len=${ciphertext.length} '
                  'must equal plaintext len=$ptSize',
            );

            Uint8List decrypted;
            if (keyBits == 128) {
              decrypted = _api.aes128GcmDecrypt(key, iv, ciphertext, tag);
            } else {
              decrypted = _api.aes256GcmDecrypt(key, iv, ciphertext, tag);
            }

            expect(
              decrypted,
              equals(plaintext),
              reason: '$label: round-trip mismatch',
            );
            passed++;
          } catch (e) {
            failures.add('$label: $e');
          }
        }

        for (final ptSize in plaintextSizes) {
          total++;
          final label = 'AES-$keyBits-CBC(pt=$ptSize)';
          try {
            final iv = _api.randomBytes(16);
            final plaintext = ptSize == 0
                ? Uint8List(0)
                : _api.randomBytes(ptSize);

            Uint8List ciphertext;
            if (keyBits == 128) {
              ciphertext = _api.aes128CbcEncrypt(key, iv, plaintext);
            } else {
              ciphertext = _api.aes256CbcEncrypt(key, iv, plaintext);
            }

            final expectedCtLen = ((ptSize ~/ 16) + 1) * 16;
            expect(
              ciphertext,
              hasLength(expectedCtLen),
              reason:
                  '$label: ciphertext len=${ciphertext.length} '
                  'expected $expectedCtLen',
            );

            Uint8List decrypted;
            if (keyBits == 128) {
              decrypted = _api.aes128CbcDecrypt(key, iv, ciphertext);
            } else {
              decrypted = _api.aes256CbcDecrypt(key, iv, ciphertext);
            }

            expect(
              decrypted,
              equals(plaintext),
              reason: '$label: round-trip mismatch',
            );
            passed++;
          } catch (e) {
            failures.add('$label: $e');
          }
        }
      }

      if (failures.isNotEmpty) {
        fail('Combinatorial C2 failures:\n${failures.join('\n')}');
      }

      print('Combinatorial C2: $passed/$total combinations passed');
      expect(passed, equals(total));
    });
  });

  group('C3: RSA x Size x Hash', () {
    test('[2048,4096] x [sha256,sha384,sha512] — sign/verify round-trip', () {
      final sizes = <int>[2048, 4096];
      final hashes = <String>['sha256', 'sha384', 'sha512'];

      int passed = 0;
      int total = 0;
      final failures = <String>[];

      for (final bits in sizes) {
        final kp = _api.generateRsaKeyPair(bits);
        final privateKeyBytes = Uint8List.fromList(kp.privateKeyPem.codeUnits);
        final publicKeyBytes = Uint8List.fromList(kp.publicKeyPem.codeUnits);
        final data = _api.randomBytes(256);

        for (final hash in hashes) {
          total++;
          final label = 'RSA-$bits-Sign($hash)';
          try {
            final signature = _api.sign(
              data,
              privateKeyBytes,
              hashAlgorithm: hash,
            );
            expect(
              signature,
              isNotEmpty,
              reason: '$label: signature must not be empty',
            );

            final verified = _api.verify(
              data,
              publicKeyBytes,
              signature,
              hashAlgorithm: hash,
            );
            expect(verified, isTrue, reason: '$label: signature must verify');
            passed++;
          } catch (e) {
            failures.add('$label: $e');
          }
        }
      }

      if (failures.isNotEmpty) {
        fail('Combinatorial C3 failures:\n${failures.join('\n')}');
      }

      print('Combinatorial C3: $passed/$total combinations passed');
      expect(passed, equals(total));
    });
  });

  group('C4: EC x Curve x Hash', () {
    test('[prime256v1,secp384r1,secp521r1] x [sha256,sha384,sha512] '
        '— sign/verify round-trip', () {
      final curves = <String>['prime256v1', 'secp384r1', 'secp521r1'];
      final hashes = <String>['sha256', 'sha384', 'sha512'];

      int passed = 0;
      int total = 0;
      final failures = <String>[];

      for (final curve in curves) {
        final kp = _api.generateEcKeyPair(curve);
        final privateKeyBytes = Uint8List.fromList(kp.privateKeyPem.codeUnits);
        final publicKeyBytes = Uint8List.fromList(kp.publicKeyPem.codeUnits);
        final data = _api.randomBytes(256);

        for (final hash in hashes) {
          total++;
          final label = 'EC-$curve-Sign($hash)';
          try {
            final signature = _api.sign(
              data,
              privateKeyBytes,
              hashAlgorithm: hash,
            );
            expect(
              signature,
              isNotEmpty,
              reason: '$label: signature must not be empty',
            );

            final verified = _api.verify(
              data,
              publicKeyBytes,
              signature,
              hashAlgorithm: hash,
            );
            expect(verified, isTrue, reason: '$label: signature must verify');
            passed++;
          } catch (e) {
            failures.add('$label: $e');
          }
        }
      }

      if (failures.isNotEmpty) {
        fail('Combinatorial C4 failures:\n${failures.join('\n')}');
      }

      print('Combinatorial C4: $passed/$total combinations passed');
      expect(passed, equals(total));
    });
  });

  tearDownAll(() {
    print(
      'Combinatorial: all groups completed '
      '(see per-group C1-C4 pass counts above)',
    );
  });
}
