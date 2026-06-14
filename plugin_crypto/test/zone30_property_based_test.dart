/// Property-Based Testing (glados): 6 invariants — AES-GCM roundtrip, SHA-256 idempotency, RSA sign/verify, randomBytes length, SHA-256 collision resistance, RSA key pair invariants.
@TestOn('linux')
@Tags(['property'])
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:glados/glados.dart'
    hide test, group, setUp, setUpAll, tearDown, tearDownAll, expect;
import 'package:plugin_crypto/plugin_crypto.dart';

/// Cached [PluginCryptoAPI] singleton.
PluginCryptoAPI get api => PluginCryptoAPI.instance;

/// Returns a [Generator] that produces a [Uint8List] of the given length
/// filled with cryptographically random bytes (OpenSSL RAND_bytes).
Generator<Uint8List> anyRandomBytes(int minLength, int maxLength) =>
    any.intInRange(minLength, maxLength).map((len) => api.randomBytes(len));

/// Returns a [Generator] for an AES key: 16 B (128-bit) or 32 B (256-bit).
Generator<Uint8List> anyAesKey() =>
    any.choose([16, 32]).map((len) => api.randomBytes(len));

/// Returns a [Generator] for a 12-byte GCM IV.
Generator<Uint8List> anyGcmIv() =>
    any.listWithLength(12, any.uint8).map(Uint8List.fromList);


void main() {
  late KeyPair rsaKeyPair;

  setUpAll(() {
    rsaKeyPair = api.generateRsaKeyPair(2048);
  });

  group('P1: AES-GCM encrypt/decrypt roundtrip', () {
    Glados3<Uint8List, Uint8List, Uint8List>(
      anyRandomBytes(0, 1024),
      anyAesKey(),
      anyGcmIv(),
    ).test('decrypt(key, iv, encrypt(key, iv, pt)) == pt', (
      plaintext,
      key,
      iv,
    ) {
      final keySize = key.length;
      AesGcmResult encrypted;
      Uint8List decrypted;

      if (keySize == 16) {
        encrypted = api.aes128GcmEncrypt(key, iv, plaintext);
        decrypted = api.aes128GcmDecrypt(
          key,
          iv,
          encrypted.ciphertext,
          encrypted.tag,
        );
      } else {
        encrypted = api.aes256GcmEncrypt(key, iv, plaintext);
        decrypted = api.aes256GcmDecrypt(
          key,
          iv,
          encrypted.ciphertext,
          encrypted.tag,
        );
      }

      expect(
        encrypted.ciphertext,
        isNotNull,
        reason:
            'AES-${keySize * 8}-GCM encrypt must produce non-null '
            'ciphertext (plaintext ${plaintext.length} B)',
      );
      expect(
        encrypted.tag.length,
        equals(16),
        reason: 'AES-${keySize * 8}-GCM tag must be exactly 16 bytes',
      );
      expect(
        decrypted,
        equals(plaintext),
        reason:
            'AES-${keySize * 8}-GCM roundtrip must recover exact '
            'plaintext (${plaintext.length} bytes, key ${keySize * 8} bits)',
      );
    });
  });

  group('P2: SHA-256 idempotency', () {
    Glados<Uint8List>(anyRandomBytes(0, 1048576)).test(
      'sha256(data) is deterministic — identical output on repeated call',
      (data) {
        final h1 = api.sha256(data);
        final h2 = api.sha256(data);

        expect(
          h1.length,
          equals(32),
          reason: 'SHA-256 must always produce 32 bytes',
        );
        expect(
          h2.length,
          equals(32),
          reason: 'SHA-256 must always produce 32 bytes',
        );
        expect(
          h1,
          equals(h2),
          reason:
              'SHA-256 must be deterministic — same ${data.length}-byte '
              'input => same digest',
        );
      },
    );
  });

  group('P3: RSA-2048 sign/verify roundtrip', () {
    Glados<Uint8List>(
      anyRandomBytes(1, 10240),
    ).test('verify(pub, sign(priv, data), data) == true', (data) {
      final privKeyBytes = Uint8List.fromList(
        rsaKeyPair.privateKeyPem.codeUnits,
      );
      final pubKeyBytes = Uint8List.fromList(rsaKeyPair.publicKeyPem.codeUnits);

      final signature = api.sign(data, privKeyBytes);
      final verified = api.verify(data, pubKeyBytes, signature);

      expect(
        signature,
        isNotEmpty,
        reason: 'RSA-2048 signature must not be empty (data ${data.length} B)',
      );
      expect(
        verified,
        isTrue,
        reason:
            'RSA-2048 sign/verify must roundtrip for '
            '${data.length} bytes of random data',
      );
    });
  });

  group('P4: randomBytes length correctness', () {
    Glados<int>(any.intInRange(1, 65536)).test('randomBytes(n).length == n', (
      n,
    ) {
      final bytes = api.randomBytes(n);
      expect(
        bytes.length,
        equals(n),
        reason:
            'randomBytes($n) must produce exactly $n bytes, '
            'got ${bytes.length}',
      );
    });
  });

  group('P5: SHA-256 collision resistance (1-bit differ)', () {
    Glados2<int, int>(any.intInRange(0, 1024), any.intInRange(0, 7)).test(
      'flipping a single bit changes SHA-256 output',
      (dataLength, bitPosition) {
        final data1 = api.randomBytes(dataLength);

        if (data1.isEmpty) {
          final h = api.sha256(data1);
          expect(h.length, equals(32));
          return;
        }

        final byteIndex = bitPosition.clamp(0, data1.length - 1);
        final data2 = Uint8List.fromList(data1);
        data2[byteIndex] ^= (1 << (bitPosition % 8));

        final h1 = api.sha256(data1);
        final h2 = api.sha256(data2);

        var differ = false;
        for (var i = 0; i < 32; i++) {
          if (h1[i] != h2[i]) {
            differ = true;
            break;
          }
        }

        expect(
          differ,
          isTrue,
          reason:
              'SHA-256 must produce different digests for inputs '
              'differing by exactly 1 bit (byte $byteIndex, '
              'input length $dataLength)',
        );
      },
    );
  });

  group('P6: RSA-2048 key pair invariants', () {
    test(
      '100 RSA-2048 key pairs: pub != priv, both non-empty',
      () {
        for (var i = 0; i < 100; i++) {
          final kp = api.generateRsaKeyPair(2048);

          expect(
            kp.publicKeyPem,
            isNotEmpty,
            reason: 'RSA-2048 public key must not be empty (iteration $i)',
          );
          expect(
            kp.privateKeyPem,
            isNotEmpty,
            reason: 'RSA-2048 private key must not be empty (iteration $i)',
          );
          expect(
            kp.publicKeyPem,
            isNot(equals(kp.privateKeyPem)),
            reason:
                'RSA-2048 public key must differ from private key '
                '(iteration $i)',
          );

          expect(
            kp.publicKeyPem,
            contains('BEGIN PUBLIC KEY'),
            reason: 'RSA-2048 public key must be valid PEM (iteration $i)',
          );
          expect(
            kp.privateKeyPem,
            contains('BEGIN PRIVATE KEY'),
            reason: 'RSA-2048 private key must be valid PEM (iteration $i)',
          );
        }
      },
      timeout: const Timeout(Duration(minutes: 5)),
    );
  });
}
