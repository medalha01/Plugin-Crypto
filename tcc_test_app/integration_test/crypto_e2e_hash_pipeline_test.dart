/// Hash algorithm distinction, determinism, tampering, streaming, interleaving tests.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/file_signing/streaming_file_signer.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';


/// Converts a PEM string to [Uint8List].
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Generates random bytes of [length] for file content testing.
Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)));
}

/// Decode a hexadecimal string to [Uint8List].
Uint8List _fromHex(String s) {
  if (s.length.isOdd) throw ArgumentError('Odd length hex string: $s');
  final bytes = Uint8List(s.length ~/ 2);
  for (var i = 0; i < s.length; i += 2) {
    bytes[i ~/ 2] = int.parse(s.substring(i, i + 2), radix: 16);
  }
  return bytes;
}

File _createTempFileBytes(Uint8List bytes) {
  final dir = Directory.systemTemp;
  final suffix = Random.secure().nextInt(999999).toString().padLeft(6, '0');
  final file = File('${dir.path}/tcc_e2e_hash_${suffix}_test.bin');
  file.writeAsBytesSync(bytes);
  return file;
}

/// Convenience wrapper: creates a temp file and returns its path.
String _createTempFileBytesPath(Uint8List bytes) {
  return _createTempFileBytes(bytes).path;
}

/// Checks whether the `openssl` CLI binary is available on the system PATH.
Future<bool> _isOpenSslAvailable() async {
  try {
    final result = await Process.run('which', ['openssl']);
    return result.exitCode == 0;
  } catch (_) {
    return false;
  }
}

Future<Uint8List> _opensslDigest(String algorithm, String filePath) async {
  final result = await Process.run(
    'openssl',
    ['dgst', '-$algorithm', filePath],
  );
  if (result.exitCode != 0) {
    throw StateError('openssl dgst failed: ${result.stderr}');
  }
  final output = (result.stdout as String).trim();
  final eqIndex = output.lastIndexOf('= ');
  if (eqIndex < 0) {
    throw StateError('Unexpected openssl dgst output format: $output');
  }
  final hexDigest = output.substring(eqIndex + 2).trim();
  return _fromHex(hexDigest);
}

/// Helper: creates an RSA-2048 key pair via [KeyCreatorFactory].
KeyPair _createRsaKeyPair(KeyCreatorFactory factory) {
  final spec = RsaKeySpec(2048);
  final creator = factory.createOrThrow(spec);
  final result = creator.create(spec);
  expect(result, isA<CryptoSuccess<KeyPair>>(),
      reason: 'RSA-2048 key creation should succeed');
  return (result as CryptoSuccess<KeyPair>).value;
}

/// Helper: signs a file using [StreamingFileSigner] and returns the signature.
Uint8List _signFile(
  StreamingFileSigner signer,
  String filePath,
  String privateKeyPem,
  String hashAlgorithm,
) {
  final request = FileSigningRequest(
    filePath: filePath,
    privateKeyPem: privateKeyPem,
    hashAlgorithm: hashAlgorithm,
  );
  final result = signer.sign(request);
  expect(result, isA<CryptoSuccess<Uint8List>>(),
      reason: 'File signing should succeed');
  return (result as CryptoSuccess<Uint8List>).value;
}


void main() {
  late PluginCryptoAPI api;
  late OpenSslBindings bindings;
  late KeyCreatorFactory factory;
  late bool opensslAvailable;

  setUpAll(() async {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    factory = KeyCreatorFactory(bindings);
    api = PluginCryptoAPI.instance;
    opensslAvailable = await _isOpenSslAvailable();
    if (!opensslAvailable) {
      // ignore: avoid_print
      print('[INFO] OpenSSL CLI not found — skipping CLI cross-verification '
          'tests (A4, A8). Install openssl package to enable these tests.');
    }
  });


  group('Hash Algorithm Distinction', () {
    test('A1: SHA-256 vs SHA-512 on same input produce different outputs', () {
      final data = Uint8List.fromList(utf8.encode('hello'));
      final sha256 = api.sha256(data);
      final sha512 = api.sha512(data);

      expect(sha256.length, equals(32));
      expect(sha512.length, equals(64));

      expect(sha256, isNot(equals(sha512.sublist(0, 32))),
          reason: 'SHA-256 output must differ from SHA-512 prefix');
    });

    test('A6: SHA3-256 vs SHA-256 on same input produce different outputs',
        () {
      final data = _randomBytes(1024);
      final sha256 = api.sha256(data);
      final sha3 = api.sha3_256(data);

      expect(sha256.length, equals(32));
      expect(sha3.length, equals(32));

      expect(sha256, isNot(equals(sha3)),
          reason: 'SHA-256 and SHA3-256 must produce different digests '
              'for the same input');
    });

    test('A7: SHA3-256 known-answer test (empty string) matches NIST vector',
        () {
      final hash = api.sha3_256(Uint8List(0));
      final expected = _fromHex(
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
      );

      expect(hash.length, equals(32));
      expect(hash, equals(expected),
          reason: 'SHA3-256 of empty string must match NIST test vector');
    });
  });


  group('Hash Determinism', () {
    test('A3: SHA-256 determinism — 5 runs on same data produce identical '
        'output', () {
      final data = _randomBytes(1024);

      Uint8List? first;
      for (var i = 0; i < 5; i++) {
        final hash = api.sha256(data);
        if (first == null) {
          first = hash;
        } else {
          expect(hash, equals(first),
              reason: 'Run $i produced different hash — SHA-256 must be '
                  'deterministic');
        }
      }
      expect(first, isNotNull);
    });

    test('A5: SHA-256 of 0-byte empty data returns known hash '
        '(e3b0c44298fc...)', () {
      final hash = api.sha256(Uint8List(0));
      final expected = _fromHex(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );

      expect(hash.length, equals(32));
      expect(hash, equals(expected),
          reason: 'SHA-256 of empty string must match known-answer test '
              'vector (RFC 6234)');
    });
  });


  group('Hash Tampering Detection', () {
    test('A2: SHA-256 of data vs SHA-256 of tampered data (1-byte flip) '
        'differ', () {
      final data = _randomBytes(1024);
      final tampered = Uint8List.fromList(data);
      tampered[0] = tampered[0] ^ 0x01;

      final hash1 = api.sha256(data);
      final hash2 = api.sha256(tampered);

      expect(hash1, isNot(equals(hash2)),
          reason: 'A single-bit change must produce a completely different '
              'hash (avalanche effect)');
    });

    test('C2: Sign file, prepend 10 bytes to content, verify → false', () {
      final keyPair = _createRsaKeyPair(factory);
      final signer = StreamingFileSigner(bindings);

      final data = _randomBytes(1024);
      final filePath = _createTempFileBytesPath(data);
      addTearDown(() => File(filePath).delete().ignore());

      final signature = _signFile(
          signer, filePath, keyPair.privateKeyPem, 'sha256');

      final prepended = Uint8List(data.length + 10);
      prepended.setRange(0, 10, _randomBytes(10));
      prepended.setRange(10, 10 + data.length, data);

      final verified = api.verify(
        prepended,
        _pem(keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isFalse,
          reason: 'Signature must not verify when content is prepended');
    });

    test('C3: Sign file, truncate last 10 bytes, verify → false', () {
      final keyPair = _createRsaKeyPair(factory);
      final signer = StreamingFileSigner(bindings);

      final data = _randomBytes(1024);
      final filePath = _createTempFileBytesPath(data);
      addTearDown(() => File(filePath).delete().ignore());

      final signature = _signFile(
          signer, filePath, keyPair.privateKeyPem, 'sha256');

      final truncated = Uint8List.fromList(data.sublist(0, data.length - 10));

      final verified = api.verify(
        truncated,
        _pem(keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isFalse,
          reason: 'Signature must not verify when content is truncated');
    });

    test('C4: Sign file, replace middle 100 bytes, verify → false', () {
      final keyPair = _createRsaKeyPair(factory);
      final signer = StreamingFileSigner(bindings);

      final data = _randomBytes(2048);
      final filePath = _createTempFileBytesPath(data);
      addTearDown(() => File(filePath).delete().ignore());

      final signature = _signFile(
          signer, filePath, keyPair.privateKeyPem, 'sha256');

      final middleStart = data.length ~/ 2 - 50;
      final replaced = Uint8List.fromList(data);
      replaced.setRange(middleStart, middleStart + 100, _randomBytes(100));

      final verified = api.verify(
        replaced,
        _pem(keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isFalse,
          reason: 'Signature must not verify when middle bytes are replaced');
    });
  });


  group('Hash Algorithm Mismatch in Signing', () {
    test('C5: Sign with sha256, verify with sha512 hash param → observe '
        'behavior', () {
      final keyPair = _createRsaKeyPair(factory);
      final signer = StreamingFileSigner(bindings);

      final data = _randomBytes(1024);
      final filePath = _createTempFileBytesPath(data);
      addTearDown(() => File(filePath).delete().ignore());

      final signature = _signFile(
          signer, filePath, keyPair.privateKeyPem, 'sha256');

      final verified = api.verify(
        data,
        _pem(keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha512',
      );
      expect(verified, isFalse,
          reason: 'Signature computed with sha256 must not verify when '
              'sha512 is specified as the hash algorithm');
    });
  });


  group('Streamed / Chunked Hash Integrity', () {
    test('A4: SHA-256 of 1MB file matches OpenSSL CLI output', () async {
      if (!opensslAvailable) {
        // ignore: avoid_print
        print('[SKIP] OpenSSL CLI not available');
        return;
      }

      final data = _randomBytes(1024 * 1024); // 1 MB
      final file = _createTempFileBytes(data);
      addTearDown(() => file.delete().ignore());

      final apiHash = api.sha256(data);

      final cliHash = await _opensslDigest('sha256', file.path);

      expect(apiHash.length, equals(32));
      expect(apiHash, equals(cliHash),
          reason: 'Plugin SHA-256 must match OpenSSL CLI output for 1MB data');
    }, tags: ['slow']);

    test('A8: SHA-512 of 64KB data matches OpenSSL CLI', () async {
      if (!opensslAvailable) {
        // ignore: avoid_print
        print('[SKIP] OpenSSL CLI not available');
        return;
      }

      final data = _randomBytes(64 * 1024); // 64 KB
      final file = _createTempFileBytes(data);
      addTearDown(() => file.delete().ignore());

      final apiHash = api.sha512(data);

      final cliHash = await _opensslDigest('sha512', file.path);

      expect(apiHash.length, equals(64));
      expect(apiHash, equals(cliHash),
          reason: 'Plugin SHA-512 must match OpenSSL CLI output for 64KB data');
    });

    test('H2: Hash 10MB file via manual chunking (1MB chunks), compare to '
        'single-pass hash', () {
      const chunkSize = 1024 * 1024; // 1 MB chunks
      const totalSize = 10 * 1024 * 1024; // 10 MB

      final fileBytes = _randomBytes(totalSize);
      final file = _createTempFileBytes(fileBytes);
      addTearDown(() => file.delete().ignore());

      final singlePassHash = api.sha256(fileBytes);
      expect(singlePassHash.length, equals(32));

      final md = bindings.evpSha256();
      final ctx = bindings.evpMdCtxNew();
      expect(ctx, isNot(nullptr),
          reason: 'EVP_MD_CTX_new must return a valid context');

      try {
        final initResult = bindings.evpDigestInitEx(ctx, md, nullptr);
        expect(initResult, equals(1),
            reason: 'EVP_DigestInit_ex must succeed');

        final raf = file.openSync(mode: FileMode.read);
        try {
          final chunkBuf = Uint8List(chunkSize);
          while (true) {
            final bytesRead = raf.readIntoSync(chunkBuf);
            if (bytesRead == 0) break; // EOF

            final nativeBuf = calloc<Uint8>(bytesRead);
            try {
              nativeBuf.asTypedList(bytesRead)
                  .setAll(0, chunkBuf.sublist(0, bytesRead));
              final updateResult =
                  bindings.evpDigestUpdate(ctx, nativeBuf.cast(), bytesRead);
              expect(updateResult, equals(1),
                  reason: 'EVP_DigestUpdate must succeed for each chunk');
            } finally {
              calloc.free(nativeBuf);
            }
          }
        } finally {
          raf.closeSync();
        }

        const digestLen = 32;
        final mdBuf = calloc<Uint8>(digestLen);
        final mdLenOut = calloc<Uint32>();
        try {
          final finalResult =
              bindings.evpDigestFinalEx(ctx, mdBuf, mdLenOut);
          expect(finalResult, equals(1),
              reason: 'EVP_DigestFinal_ex must succeed');

          final chunkedHash =
              Uint8List.fromList(mdBuf.asTypedList(mdLenOut.value));
          expect(chunkedHash.length, equals(32));

          expect(chunkedHash, equals(singlePassHash),
              reason: 'Manual chunked SHA-256 (1MB chunks) must match '
                  'single-pass SHA-256 for 10MB data');
        } finally {
          calloc.free(mdBuf);
          calloc.free(mdLenOut);
        }
      } finally {
        bindings.evpMdCtxFree(ctx);
      }
    }, tags: ['slow']);

    test('H4: Interleaved operations — sha256 → sign → sha256 → verify → '
        'sha256 (no state corruption)', () {
      final keyPair = _createRsaKeyPair(factory);
      final signer = StreamingFileSigner(bindings);

      final data1 = _randomBytes(512);
      final hash1 = api.sha256(data1);
      expect(hash1.length, equals(32));

      final fileContent = _randomBytes(1024);
      final filePath = _createTempFileBytesPath(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signature = _signFile(
          signer, filePath, keyPair.privateKeyPem, 'sha256');
      expect(signature, isNotEmpty);

      final data2 = _randomBytes(512);
      final hash2 = api.sha256(data2);
      expect(hash2.length, equals(32));
      expect(hash2, isNot(equals(hash1)),
          reason: 'Different inputs should produce different hashes');

      final verified = api.verify(
        fileContent,
        _pem(keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isTrue,
          reason: 'Signature must verify after interleaved hash operations');

      final hash3 = api.sha256(data1);
      expect(hash3, equals(hash1),
          reason: 'SHA-256 must be deterministic after interleaved sign '
              'and verify operations (no state corruption)');

      final fileHash = api.sha256(fileContent);
      expect(fileHash.length, equals(32));
    });
  });
}
