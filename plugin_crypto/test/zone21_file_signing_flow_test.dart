@TestOn('linux')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';
import 'package:plugin_crypto/src/crypto/models/signing_algorithm.dart';
import 'package:plugin_crypto/src/crypto/flows/file_signing/file_signing_request.dart';
import 'package:plugin_crypto/src/crypto/flows/file_signing/streaming_file_signer.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/file_signing_fixtures.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone21', 'File Signing Flow');

  late OpenSslBindings bindings;
  late PluginCryptoAPI api;
  late StreamingFileSigner signer;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    api = PluginCryptoAPI.instance;
    signer = StreamingFileSigner(bindings);
  });

  group('Signing with RSA key', () {
    late String smallFilePath;

    setUp(() {
      smallFilePath = tempSmallFile();
    });

    tearDown(() {
      deleteTempFile(smallFilePath);
    });

    test('signs a small file with RSA key', () {
      final keyPair = rsaKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final sig = (result as CryptoSuccess<Uint8List>).value;
      expect(sig, isNotEmpty);
    });

    test('signature verifies successfully with corresponding public key', () {
      final keyPair = rsaKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      final sig = (result as CryptoSuccess<Uint8List>).value;

      final fileData = File(smallFilePath).readAsBytesSync();

      final pubKeyBytes = Uint8List.fromList(utf8.encode(keyPair.publicKeyPem));
      final verified = api.verify(
        fileData,
        pubKeyBytes,
        sig,
        hashAlgorithm: 'sha256',
      );

      expect(verified, isTrue);
    });

    test('signature does NOT verify with wrong public key', () {
      final keyPair = rsaKeyPair();
      final wrongKeyPair = rsaKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      final sig = (result as CryptoSuccess<Uint8List>).value;

      final fileData = File(smallFilePath).readAsBytesSync();
      final wrongPubKeyBytes = Uint8List.fromList(
        utf8.encode(wrongKeyPair.publicKeyPem),
      );
      final verified = api.verify(
        fileData,
        wrongPubKeyBytes,
        sig,
        hashAlgorithm: 'sha256',
      );

      expect(verified, isFalse);
    });

    test('signature does NOT verify with tampered file content', () {
      final keyPair = rsaKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      final sig = (result as CryptoSuccess<Uint8List>).value;

      final tamperedData = Uint8List.fromList(
        utf8.encode('This is tampered content.'),
      );
      final pubKeyBytes = Uint8List.fromList(utf8.encode(keyPair.publicKeyPem));
      final verified = api.verify(
        tamperedData,
        pubKeyBytes,
        sig,
        hashAlgorithm: 'sha256',
      );

      expect(verified, isFalse);
    });
  });

  group('Signing with EC key', () {
    late String smallFilePath;

    setUp(() {
      smallFilePath = tempSmallFile();
    });

    tearDown(() {
      deleteTempFile(smallFilePath);
    });

    test('signs a small file with EC key', () {
      final keyPair = ecKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final sig = (result as CryptoSuccess<Uint8List>).value;
      expect(sig, isNotEmpty);
    });

    test('signature verifies successfully with EC public key', () {
      final keyPair = ecKeyPair();
      final request = FileSigningRequest(
        filePath: smallFilePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      final sig = (result as CryptoSuccess<Uint8List>).value;

      final fileData = File(smallFilePath).readAsBytesSync();
      final pubKeyBytes = Uint8List.fromList(utf8.encode(keyPair.publicKeyPem));
      final verified = api.verify(
        fileData,
        pubKeyBytes,
        sig,
        hashAlgorithm: 'sha256',
      );

      expect(verified, isTrue);
    });
  });

  group('Streaming large files', () {
    test('signs a 1 MB file with RSA key (streaming path)', () {
      final largePath = tempLargeFile(1024 * 1024);
      try {
        final keyPair = rsaKeyPair();
        final request = FileSigningRequest(
          filePath: largePath,
          privateKeyPem: keyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);

        expect(result, isA<CryptoSuccess<Uint8List>>());
        final sig = (result as CryptoSuccess<Uint8List>).value;
        expect(sig, isNotEmpty);

        final fileData = File(largePath).readAsBytesSync();
        final pubKeyBytes = Uint8List.fromList(
          utf8.encode(keyPair.publicKeyPem),
        );
        final verified = api.verify(
          fileData,
          pubKeyBytes,
          sig,
          hashAlgorithm: 'sha256',
        );
        expect(verified, isTrue);
      } finally {
        deleteTempFile(largePath);
      }
    }, tags: ['sign', 'slow']);

    test('signs a 10 MB file with EC key (streaming path)', () {
      final largePath = tempLargeFile(10 * 1024 * 1024);
      try {
        final keyPair = ecKeyPair();
        final request = FileSigningRequest(
          filePath: largePath,
          privateKeyPem: keyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);

        expect(result, isA<CryptoSuccess<Uint8List>>());
        final sig = (result as CryptoSuccess<Uint8List>).value;
        expect(sig, isNotEmpty);

        final fileData = File(largePath).readAsBytesSync();
        final pubKeyBytes = Uint8List.fromList(
          utf8.encode(keyPair.publicKeyPem),
        );
        final verified = api.verify(
          fileData,
          pubKeyBytes,
          sig,
          hashAlgorithm: 'sha256',
        );
        expect(verified, isTrue);
      } finally {
        deleteTempFile(largePath);
      }
    }, tags: ['sign', 'slow']);
  });

  group('Edge cases', () {
    test('handles empty file (0 bytes)', () {
      final emptyPath = '/tmp/plugin_crypto_test_empty.bin';
      File(emptyPath).writeAsBytesSync([]);
      try {
        final keyPair = rsaKeyPair();
        final request = FileSigningRequest(
          filePath: emptyPath,
          privateKeyPem: keyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);

        expect(result, isA<CryptoSuccess<Uint8List>>());
        final sig = (result as CryptoSuccess<Uint8List>).value;
        expect(sig, isNotEmpty);
      } finally {
        deleteTempFile(emptyPath);
      }
    });

    test('respects custom chunk size', () {
      final smallPath = tempSmallFile();
      try {
        final keyPair = rsaKeyPair();
        final request = FileSigningRequest(
          filePath: smallPath,
          privateKeyPem: keyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
          chunkSize: 8192, // 8 KB chunks
        );

        final result = signer.sign(request);

        expect(result, isA<CryptoSuccess<Uint8List>>());
      } finally {
        deleteTempFile(smallPath);
      }
    });
  });

  group('Input validation', () {
    test('validates non-existent file path → CryptoFailure', () {
      final keyPair = rsaKeyPair();
      final request = FileSigningRequest(
        filePath: '/tmp/plugin_crypto_nonexistent_file.bin',
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);

      expect(result, isA<CryptoFailure<Uint8List>>());
      final error = (result as CryptoFailure<Uint8List>).error;
      expect(error, isA<FileSigningError>());
    });

    test('validates invalid hash algorithm at construction', () {
      expect(
        () => FileSigningRequest(
          filePath: '/tmp/test.bin',
          privateKeyPem:
              '-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----',
          hashAlgorithm: 'md5',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('validates invalid private key PEM at construction', () {
      expect(
        () => FileSigningRequest(
          filePath: '/tmp/test.bin',
          privateKeyPem: 'not a valid key',
          hashAlgorithm: 'sha256',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('validates empty file path', () {
      expect(
        () => FileSigningRequest(
          filePath: '',
          privateKeyPem:
              '-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----',
          hashAlgorithm: 'sha256',
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('FileSigner.supportedAlgorithms', () {
    test('returns non-empty list', () {
      expect(signer.supportedAlgorithms, isNotEmpty);
    });

    test('includes sha256 with RSA', () {
      final hasRsaSha256 = signer.supportedAlgorithms.any(
        (a) =>
            a.hash == HashAlgorithm.sha256 && a.keyType == SigningKeyType.rsa,
      );
      expect(hasRsaSha256, isTrue);
    });

    test('includes sha256 with EC', () {
      final hasEcSha256 = signer.supportedAlgorithms.any(
        (a) => a.hash == HashAlgorithm.sha256 && a.keyType == SigningKeyType.ec,
      );
      expect(hasEcSha256, isTrue);
    });
  });

  m?.endZone();
}
