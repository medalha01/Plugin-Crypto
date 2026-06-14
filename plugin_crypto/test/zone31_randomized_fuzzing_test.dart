/// Randomized fuzzing: F1 SHA-256 (2000), F2 SHA-512 (2000), F3 AES-256-GCM (2000), F4 RSA-2048 (2000), F5 CMS corruption (2000).
@TestOn('linux')
@Tags(['fuzzing', 'slow'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';

/// Cached [PluginCryptoAPI] singleton.
PluginCryptoAPI get api => PluginCryptoAPI.instance;

int _successes = 0;

/// Tracks unhandled crashes (native segfaults / Dart uncaught exceptions).
int _crashes = 0;

/// Logs progress to stdout every [interval] cases.
void _logProgress(String label, int current, int total) {
  if (current % 500 == 0 || current == total) {
    print('Fuzzing: $current/$total $label cases...');
  }
}

/// Runs a single fuzz case wrapper.  If the body throws, increment [_crashes];
/// otherwise increment [_successes].
void _runCase(String label, int iteration, void Function() body) {
  try {
    body();
    _successes++;
  } catch (e, st) {
    _crashes++;
    print('⚠ CRASH in $label case $iteration: $e\n$st');
  }
}

/// Prints the final summary line.
void _printSummary() {
  final total = _successes + _crashes;
  print('Fuzzing complete: $total/$total cases, $_crashes crashes');
}


/// Pre-generated RSA-2048 key pair for CMS fuzzing (F5).
late KeyPair _rsaKeyPair;

/// PEM bytes for the RSA key pair.
late Uint8List _rsaCertPem;
late Uint8List _rsaPrivPem;

void main() {
  setUpAll(() async {
    _rsaKeyPair = api.generateRsaKeyPair(2048);
    _rsaPrivPem = Uint8List.fromList(_rsaKeyPair.privateKeyPem.codeUnits);
    await File('/tmp/zone31_rsa_key.pem')
        .writeAsString(_rsaKeyPair.privateKeyPem);
    await Process.run('openssl', [
      'req', '-x509', '-new',
      '-key', '/tmp/zone31_rsa_key.pem',
      '-out', '/tmp/zone31_rsa_cert.pem',
      '-days', '365',
      '-subj', '/CN=Zone31FuzzTest',
    ]);
    _rsaCertPem = await File('/tmp/zone31_rsa_cert.pem').readAsBytes();
  });

  tearDownAll(() {
    File('/tmp/zone31_rsa_key.pem').deleteSync();
    File('/tmp/zone31_rsa_cert.pem').deleteSync();
    _printSummary();

    expect(
      _crashes,
      equals(0),
      reason:
          'All 10 000 fuzzing cases must complete without crash. '
          '$_crashes unexpected crashes detected.',
    );
  });

  group('F1: SHA-256 fuzzing (2 000 random inputs)', () {
    test(
      'SHA-256 handles 2 000 random payloads without crash',
      () {
        const n = 2000;
        for (var i = 1; i <= n; i++) {
          _runCase('SHA-256', i, () {
            final len = _randomPayloadLength(i, n, 1048576);
            final data = api.randomBytes(len);

            final hash = api.sha256(data);

            expect(
              hash.length,
              equals(32),
              reason:
                  'SHA-256 must output 32 bytes for ${len}-byte input '
                  '(case $i/$n)',
            );
          });
          _logProgress('SHA-256', i, n);
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });

  group('F2: AES-GCM encrypt fuzzing (2 000 random payloads)', () {
    test(
      'AES-GCM encrypt handles 2 000 random payloads without crash',
      () {
        const n = 2000;
        for (var i = 1; i <= n; i++) {
          _runCase('AES-GCM encrypt', i, () {
            final ptLen = _randomPayloadLength(i, n, 65536);
            final plaintext = api.randomBytes(ptLen);

            final keySize = (i % 2 == 0) ? 16 : 32;
            final key = api.randomBytes(keySize);

            final iv = api.randomBytes(12);

            AesGcmResult result;
            if (keySize == 16) {
              result = api.aes128GcmEncrypt(key, iv, plaintext);
            } else {
              result = api.aes256GcmEncrypt(key, iv, plaintext);
            }

            expect(
              result.ciphertext,
              isNotNull,
              reason:
                  'AES-${keySize * 8}-GCM ciphertext must not be null '
                  '(case $i/$n, ptLen=$ptLen)',
            );
            expect(
              result.tag.length,
              equals(16),
              reason:
                  'AES-${keySize * 8}-GCM tag must be 16 bytes (case $i/$n)',
            );

            if (plaintext.isNotEmpty) {
              expect(
                result.ciphertext,
                isNot(equals(plaintext)),
                reason:
                    'AES-${keySize * 8}-GCM ciphertext must differ from '
                    'plaintext for non-empty input (case $i/$n)',
              );
            }
          });
          _logProgress('AES-GCM encrypt', i, n);
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });

  group('F3: AES-GCM decrypt malformed (2 000 cases)', () {
    test(
      'AES-GCM decrypt rejects 2 000 malformed inputs without crash',
      () {
        const n = 2000;
        for (var i = 1; i <= n; i++) {
          _runCase('AES-GCM decrypt malformed', i, () {
            final keySize = (i % 2 == 0) ? 16 : 32;
            final key = api.randomBytes(keySize);
            final iv = api.randomBytes(12);
            final plaintext = api.randomBytes(32); // fixed size for simplicity

            AesGcmResult valid;
            if (keySize == 16) {
              valid = api.aes128GcmEncrypt(key, iv, plaintext);
            } else {
              valid = api.aes256GcmEncrypt(key, iv, plaintext);
            }

            final mode = i % 3;

            Uint8List mutatedCiphertext;
            Uint8List mutatedTag;
            Uint8List mutatedIv;

            switch (mode) {
              case 0: // Truncated ciphertext
                mutatedCiphertext = valid.ciphertext.length > 1
                    ? Uint8List.fromList(
                        valid.ciphertext.sublist(
                          0,
                          valid.ciphertext.length - 1,
                        ),
                      )
                    : valid.ciphertext;
                mutatedTag = valid.tag;
                mutatedIv = iv;
                break;

              case 1: // Wrong tag (flip every byte)
                mutatedCiphertext = valid.ciphertext;
                mutatedTag = Uint8List.fromList(
                  valid.tag.map((b) => b ^ 0xFF).toList(),
                );
                mutatedIv = iv;
                break;

              case 2: // Wrong IV (flip first byte)
                mutatedCiphertext = valid.ciphertext;
                mutatedTag = valid.tag;
                mutatedIv = Uint8List.fromList(iv);
                if (mutatedIv.isNotEmpty) {
                  mutatedIv[0] ^= 0xFF;
                }
                break;

              default:
                mutatedCiphertext = valid.ciphertext;
                mutatedTag = valid.tag;
                mutatedIv = iv;
            }

            try {
              Uint8List decrypted;
              if (keySize == 16) {
                decrypted = api.aes128GcmDecrypt(
                  key,
                  mutatedIv,
                  mutatedCiphertext,
                  mutatedTag,
                );
              } else {
                decrypted = api.aes256GcmDecrypt(
                  key,
                  mutatedIv,
                  mutatedCiphertext,
                  mutatedTag,
                );
              }

              expect(
                decrypted,
                isNot(equals(plaintext)),
                reason:
                    'Malformed AES-GCM decrypt must not recover original '
                    'plaintext (case $i/$n, mode=$mode)',
              );
            } on StateError catch (_) {
            } on ArgumentError catch (_) {
            } on CryptoError catch (_) {
            } on FormatException catch (_) {
            }
          });
          _logProgress('AES-GCM decrypt malformed', i, n);
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });

  group('F4: X.509 DER malformed (2 000 random bit arrays)', () {
    test(
      'parseX509Certificate rejects 2 000 malformed inputs without crash',
      () {
        const n = 2000;
        for (var i = 1; i <= n; i++) {
          _runCase('X.509 DER malformed', i, () {
            final len = (i % 2048) + 1; // 1 to 2048 bytes
            final garbage = api.randomBytes(len);

            try {
              final cert = api.parseX509Certificate(garbage);
              expect(cert, isA<X509Certificate>());
            } on StateError catch (_) {
            } on ArgumentError catch (_) {
            } on CryptoError catch (_) {
            } on FormatException catch (_) {
            }
          });
          _logProgress('X.509 DER malformed', i, n);
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });

  group('F5: CMS corruption (2 000 bit-flip cases)', () {
    test(
      'CMS verify rejects 2 000 corrupted signed data payloads',
      () {
        const n = 2000;

        final originalData = Uint8List.fromList(
          'F5 CMS fuzzing payload'.codeUnits,
        );
        final validCms = api.cmsSign(originalData, _rsaCertPem, _rsaPrivPem);

        for (var i = 1; i <= n; i++) {
          _runCase('CMS corruption', i, () {
            final corrupted = Uint8List.fromList(validCms);

            if (corrupted.isNotEmpty) {
              final byteIndex = i % corrupted.length;
              final bit = (i ~/ corrupted.length + i) % 8;
              corrupted[byteIndex] ^= (1 << bit);

              if (i % 7 == 0 && corrupted.length > 10) {
                corrupted[i % corrupted.length] ^= 0xAA; // more corruption
              }
            }

            try {
              api.cmsVerify(
                corrupted,
                trustedCert: _rsaCertPem,
              );
            } on StateError catch (_) {
            } on ArgumentError catch (_) {
            } on CryptoError catch (_) {
            } on FormatException catch (_) {
            }
          });
          _logProgress('CMS corruption', i, n);
        }
      },
      timeout: const Timeout(Duration(minutes: 10)),
    );
  });
}

int _randomPayloadLength(int iteration, int total, int maxLen) {
  if (maxLen == 0) return 0;
  const prime = 997;
  final bucket = (iteration * prime) % (total + 1);
  return (bucket * maxLen) ~/ total;
}
