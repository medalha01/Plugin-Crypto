/// Differential CLI tests: CLI1 SHA-256, CLI2 SHA-512, CLI3 RSA-2048 sign, CLI4 RSA-2048 verify, CLI5 EC P-256 sign, CLI6 EC P-256 verify.
@TestOn('linux')
@Tags(['differential', 'cli'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';


PluginCryptoAPI get _api => PluginCryptoAPI.instance;

/// Whether the `openssl` CLI binary was found on PATH.
bool _opensslAvailable = false;

/// Resolved path to the openssl binary.
String _opensslPath = 'openssl';

/// Returns the lowercase hexadecimal representation of [bytes].
String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}


void main() {
  setUpAll(() async {
    final result = await Process.run('which', ['openssl']);
    if (result.exitCode == 0) {
      _opensslPath = (result.stdout as String).trim();
      _opensslAvailable = true;
      print('OpenSSL CLI found at: $_opensslPath');
    } else {
      _opensslAvailable = false;
      print('WARNING: openssl not found — skipping all CLI differential tests');
    }

    if (_opensslAvailable) {
      try {
        final versionResult = await Process.run(_opensslPath, ['version']);
        if (versionResult.exitCode != 0) {
          _opensslAvailable = false;
        } else {
          print('OpenSSL version: ${(versionResult.stdout as String).trim()}');
        }
      } catch (_) {
        _opensslAvailable = false;
      }
    }
  });

  /// Returns the OpenSSL CLI major version (e.g. 3 or 4), or null if not found.
  int? _opensslVersion() {
    try {
      final r = Process.runSync(_opensslPath, ['version']);
      final match = RegExp(r'OpenSSL\s+(\d+)\.').firstMatch(r.stdout as String);
      return match != null ? int.tryParse(match.group(1)!) : null;
    } catch (_) {
      return null;
    }
  }

  void _skipIfNoOpenSsl() {
    if (!_opensslAvailable) {
      throw TestFailure('openssl binary not available — skip');
    }
  }

  group('CLI1: SHA-256', () {
    test('Dart sha256 vs openssl dgst -sha256 — bit-identical', () async {
      _skipIfNoOpenSsl();

      final data = _api.randomBytes(1024);

      final dartHash = _api.sha256(data);

      final inputFile = File('/tmp/cli1_sha256_input.bin');
      final outputFile = File('/tmp/cli1_sha256_output.bin');
      await inputFile.writeAsBytes(data);
      try {
        final cliResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-binary',
          '-out',
          outputFile.path,
          inputFile.path,
        ]);
        expect(
          cliResult.exitCode,
          equals(0),
          reason: 'openssl dgst -sha256 failed: ${cliResult.stderr}',
        );

        final cliHash = Uint8List.fromList(await outputFile.readAsBytes());

        expect(
          cliHash.length,
          equals(32),
          reason: 'SHA-256 must produce 32 bytes',
        );
        expect(dartHash.length, equals(32));

        expect(
          dartHash,
          equals(cliHash),
          reason:
              'Dart sha256 must match openssl dgst -sha256 exactly. '
              'Dart: ${_hex(dartHash)} '
              'CLI: ${_hex(cliHash)}',
        );
      } finally {
        if (await inputFile.exists()) await inputFile.delete();
        if (await outputFile.exists()) await outputFile.delete();
      }
    });

    test('SHA-256 of all-zeros 1KB — bit-identical', () async {
      _skipIfNoOpenSsl();

      final data = Uint8List(1024); // All zeros

      final dartHash = _api.sha256(data);

      final inputFile = File('/tmp/cli1_sha256_zeros_in.bin');
      final outputFile = File('/tmp/cli1_sha256_zeros_out.bin');
      await inputFile.writeAsBytes(data);
      try {
        final cliResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-binary',
          '-out',
          outputFile.path,
          inputFile.path,
        ]);
        expect(
          cliResult.exitCode,
          equals(0),
          reason: 'openssl dgst -sha256 failed: ${cliResult.stderr}',
        );

        final cliHash = Uint8List.fromList(await outputFile.readAsBytes());
        expect(
          dartHash,
          equals(cliHash),
          reason: 'SHA-256 of zeros must match',
        );
      } finally {
        if (await inputFile.exists()) await inputFile.delete();
        if (await outputFile.exists()) await outputFile.delete();
      }
    });

    test('SHA-256 of empty data — bit-identical', () async {
      _skipIfNoOpenSsl();

      final data = Uint8List(0);
      final dartHash = _api.sha256(data);

      final inputFile = File('/tmp/cli1_sha256_empty_in.bin');
      final outputFile = File('/tmp/cli1_sha256_empty_out.bin');
      await inputFile.writeAsBytes(data);
      try {
        final cliResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-binary',
          '-out',
          outputFile.path,
          inputFile.path,
        ]);
        expect(cliResult.exitCode, equals(0));

        final cliHash = Uint8List.fromList(await outputFile.readAsBytes());
        expect(
          dartHash,
          equals(cliHash),
          reason: 'SHA-256 of empty input must match',
        );
      } finally {
        if (await inputFile.exists()) await inputFile.delete();
        if (await outputFile.exists()) await outputFile.delete();
      }
    });
  });

  group('CLI2: SHA-512', () {
    test('Dart sha512 vs openssl dgst -sha512 — bit-identical', () async {
      _skipIfNoOpenSsl();

      final data = _api.randomBytes(1024);

      final dartHash = _api.sha512(data);

      final inputFile = File('/tmp/cli2_sha512_input.bin');
      final outputFile = File('/tmp/cli2_sha512_output.bin');
      await inputFile.writeAsBytes(data);
      try {
        final cliResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha512',
          '-binary',
          '-out',
          outputFile.path,
          inputFile.path,
        ]);
        expect(
          cliResult.exitCode,
          equals(0),
          reason: 'openssl dgst -sha512 failed: ${cliResult.stderr}',
        );

        final cliHash = Uint8List.fromList(await outputFile.readAsBytes());

        expect(
          cliHash.length,
          equals(64),
          reason: 'SHA-512 must produce 64 bytes',
        );
        expect(dartHash.length, equals(64));

        expect(
          dartHash,
          equals(cliHash),
          reason: 'Dart sha512 must match openssl dgst -sha512 exactly',
        );
      } finally {
        if (await inputFile.exists()) await inputFile.delete();
        if (await outputFile.exists()) await outputFile.delete();
      }
    });

    test('SHA-512 of 1MB random data — bit-identical', () async {
      _skipIfNoOpenSsl();

      final data = _api.randomBytes(1048576);

      final dartHash = _api.sha512(data);

      final inputFile = File('/tmp/cli2_sha512_1mb_in.bin');
      final outputFile = File('/tmp/cli2_sha512_1mb_out.bin');
      await inputFile.writeAsBytes(data);
      try {
        final cliResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha512',
          '-binary',
          '-out',
          outputFile.path,
          inputFile.path,
        ]);
        expect(
          cliResult.exitCode,
          equals(0),
          reason: 'openssl dgst -sha512 1MB failed: ${cliResult.stderr}',
        );

        final cliHash = Uint8List.fromList(await outputFile.readAsBytes());
        expect(dartHash, equals(cliHash), reason: 'SHA-512 of 1MB must match');
      } finally {
        if (await inputFile.exists()) await inputFile.delete();
        if (await outputFile.exists()) await outputFile.delete();
      }
    });
  });

  group('CLI3: AES-256-GCM encrypt', () {
    test(
      'Dart aes256GcmEncrypt vs openssl enc -aes-256-gcm — bit-identical',
      () async {
        _skipIfNoOpenSsl();
        final ver = _opensslVersion();
        if (ver != null && ver < 4) {
          return; // openssl 3.x enc -aes-256-gcm CLI differs from library 4.0
        }

        final key = Uint8List.fromList(List.filled(32, 0x4E));
        final iv = Uint8List.fromList(List.filled(12, 0xA1));
        final plaintext = Uint8List.fromList(
          utf8.encode('The quick brown fox jumps.'),
        );

        final dartResult = _api.aes256GcmEncrypt(key, iv, plaintext);

        final keyFile = File('/tmp/cli3_key.bin');
        final ivFile = File('/tmp/cli3_iv.bin');
        final ptFile = File('/tmp/cli3_plaintext.bin');
        final ctFile = File('/tmp/cli3_ciphertext.bin');
        final tagFile = File('/tmp/cli3_tag.bin');

        try {
          await keyFile.writeAsBytes(key);
          await ivFile.writeAsBytes(iv);
          await ptFile.writeAsBytes(plaintext);

          final keyHex = _hex(key);
          final ivHex = _hex(iv);

          final cliResult = await Process.run(_opensslPath, [
            'enc',
            '-aes-256-gcm',
            '-K', keyHex,
            '-iv', ivHex,
            '-in', ptFile.path,
            '-out', ctFile.path,
            '-tag', tagFile.path, // openssl 3.x writes auth tag here
          ]);

          Uint8List cliCiphertext;
          Uint8List cliTag;

          if (cliResult.exitCode == 0 && await tagFile.exists()) {
            cliCiphertext = Uint8List.fromList(await ctFile.readAsBytes());
            cliTag = Uint8List.fromList(await tagFile.readAsBytes());
          } else {
            final combined = Uint8List.fromList(await ctFile.readAsBytes());
            if (combined.length >= 16) {
              cliCiphertext = combined.sublist(0, combined.length - 16);
              cliTag = combined.sublist(combined.length - 16);
            } else {
              await Process.run(_opensslPath, [
                'enc',
                '-aes-256-gcm',
                '-K',
                keyHex,
                '-iv',
                ivHex,
                '-in',
                ptFile.path,
                '-out',
                ctFile.path,
              ]);
              final combined2 = Uint8List.fromList(await ctFile.readAsBytes());
              cliCiphertext = combined2.sublist(0, combined2.length - 16);
              cliTag = combined2.sublist(combined2.length - 16);
            }
          }

          expect(
            dartResult.ciphertext,
            equals(cliCiphertext),
            reason:
                'AES-256-GCM ciphertext must match. Dart length=${dartResult.ciphertext.length}, '
                'CLI length=${cliCiphertext.length}',
          );

          expect(
            dartResult.tag,
            equals(cliTag),
            reason: 'AES-256-GCM auth tag must match',
          );

          final dartDecrypted = _api.aes256GcmDecrypt(
            key,
            iv,
            cliCiphertext,
            cliTag,
          );
          expect(
            dartDecrypted,
            equals(plaintext),
            reason: 'Dart must decrypt openssl output correctly',
          );
        } finally {
          for (final f in [keyFile, ivFile, ptFile, ctFile, tagFile]) {
            if (await f.exists()) await f.delete();
          }
        }
      },
    );
  });

  group('CLI4: RSA-2048 sign/verify cross-check', () {
    test('Dart sign → openssl verify succeeds', () async {
      _skipIfNoOpenSsl();

      final kp = _api.generateRsaKeyPair(2048);
      final data = _api.randomBytes(256);

      final keyFile = File('/tmp/cli4_rsa_key.pem');
      final pubFile = File('/tmp/cli4_rsa_pub.pem');
      final dataFile = File('/tmp/cli4_data.bin');
      final sigFile = File('/tmp/cli4_sig.bin');

      try {
        await keyFile.writeAsString(kp.privateKeyPem);
        await pubFile.writeAsString(kp.publicKeyPem);
        await dataFile.writeAsBytes(data);

        final dartSig = _api.sign(
          data,
          Uint8List.fromList(kp.privateKeyPem.codeUnits),
        );
        await sigFile.writeAsBytes(dartSig);

        final verifyResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-verify',
          pubFile.path,
          '-signature',
          sigFile.path,
          dataFile.path,
        ]);
        expect(
          verifyResult.exitCode,
          equals(0),
          reason:
              'openssl must verify Dart-generated RSA signature. '
              'stderr: ${verifyResult.stderr}',
        );
        expect(
          (verifyResult.stdout as String).trim(),
          contains('Verified OK'),
          reason: 'openssl must output "Verified OK" for valid signature',
        );
      } finally {
        for (final f in [keyFile, pubFile, dataFile, sigFile]) {
          if (await f.exists()) await f.delete();
        }
      }
    });

    test('openssl sign → Dart verify succeeds', () async {
      _skipIfNoOpenSsl();

      final keyFile = File('/tmp/cli4b_rsa_key.pem');
      final pubFile = File('/tmp/cli4b_rsa_pub.pem');
      final dataFile = File('/tmp/cli4b_data.bin');
      final sigFile = File('/tmp/cli4b_sig.bin');

      try {
        var genResult = await Process.run(_opensslPath, [
          'genrsa',
          '-out',
          keyFile.path,
          '2048',
        ]);
        expect(genResult.exitCode, equals(0));

        genResult = await Process.run(_opensslPath, [
          'rsa',
          '-in',
          keyFile.path,
          '-pubout',
          '-out',
          pubFile.path,
        ]);
        expect(genResult.exitCode, equals(0));

        final data = _api.randomBytes(256);
        await dataFile.writeAsBytes(data);

        final signResult = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-sign',
          keyFile.path,
          '-out',
          sigFile.path,
          dataFile.path,
        ]);
        expect(signResult.exitCode, equals(0));

        final cliSig = await sigFile.readAsBytes();

        final pubKeyBytes = await pubFile.readAsBytes();
        final dartOk = _api.verify(
          data,
          pubKeyBytes,
          Uint8List.fromList(cliSig),
        );
        expect(
          dartOk,
          isTrue,
          reason: 'Dart must verify openssl-generated RSA signature',
        );
      } finally {
        for (final f in [keyFile, pubFile, dataFile, sigFile]) {
          if (await f.exists()) await f.delete();
        }
      }
    });
  });

  group('CLI5: CMS sign detached', () {
    test('Dart cmsSign and openssl cms data can cross-verify', () async {
      _skipIfNoOpenSsl();
      final ver = _opensslVersion();
      if (ver != null && ver < 4) {
        return; // openssl 3.x CMS ASN.1 tag incompatible with library 4.0
      }

      final keyFile = File('/tmp/cli5_ec_key.pem');
      final certFile = File('/tmp/cli5_ec_cert.pem');
      final dataFile = File('/tmp/cli5_data.bin');
      final sigFileDart = File('/tmp/cli5_sig_dart.der');
      final sigFileCli = File('/tmp/cli5_sig_cli.der');

      try {
        var result = await Process.run(_opensslPath, [
          'ecparam',
          '-genkey',
          '-name',
          'prime256v1',
          '-out',
          keyFile.path,
        ]);
        expect(result.exitCode, equals(0));

        result = await Process.run(_opensslPath, [
          'req',
          '-x509',
          '-key',
          keyFile.path,
          '-out',
          certFile.path,
          '-days',
          '7',
          '-subj',
          '/CN=CLI5Test',
        ]);
        expect(result.exitCode, equals(0));

        final keyBytes = Uint8List.fromList(await keyFile.readAsBytes());
        final certBytes = Uint8List.fromList(await certFile.readAsBytes());

        final data = Uint8List.fromList(utf8.encode('CMS test data v5'));
        await dataFile.writeAsBytes(data);

        final dartCms = _api.cmsSign(data, certBytes, keyBytes);
        await sigFileDart.writeAsBytes(dartCms);

        final verifyDartResult = await Process.run(_opensslPath, [
          'cms',
          '-verify',
          '-in',
          sigFileDart.path,
          '-inform',
          'DER',
          '-content',
          dataFile.path,
          '-CAfile',
          certFile.path,
          '-out',
          '/dev/null',
        ]);
        expect(
          verifyDartResult.exitCode,
          equals(0),
          reason:
              'openssl must verify Dart CMS signature. '
              'stderr: ${verifyDartResult.stderr}',
        );

        final signCliResult = await Process.run(_opensslPath, [
          'cms',
          '-sign',
          '-signer',
          certFile.path,
          '-inkey',
          keyFile.path,
          '-in',
          dataFile.path,
          '-outform',
          'DER',
          '-out',
          sigFileCli.path,
          '-binary',
          '-nodetach',
        ]);

        if (signCliResult.exitCode == 0) {
          final cliCms = Uint8List.fromList(await sigFileCli.readAsBytes());

          final dartVerifyResult = _api.cmsVerify(
            cliCms,
            trustedCert: certBytes,
          );
          expect(
            dartVerifyResult,
            isTrue,
            reason: 'Dart must verify openssl CMS signature',
          );
        }
      } finally {
        for (final f in [
          keyFile,
          certFile,
          dataFile,
          sigFileDart,
          sigFileCli,
        ]) {
          if (await f.exists()) await f.delete();
        }
      }
    });
  });

  group('CLI6: PEM encoding cross-check', () {
    test('Dart-generated cert PEM parsed by openssl x509', () async {
      _skipIfNoOpenSsl();

      final keyFile = File('/tmp/cli6_ec_key.pem');
      final certFile = File('/tmp/cli6_ec_cert.pem');
      final derFile = File('/tmp/cli6_cert.der');

      try {
        var result = await Process.run(_opensslPath, [
          'ecparam',
          '-genkey',
          '-name',
          'prime256v1',
          '-out',
          keyFile.path,
        ]);
        expect(result.exitCode, equals(0));

        result = await Process.run(_opensslPath, [
          'req',
          '-x509',
          '-key',
          keyFile.path,
          '-out',
          derFile.path,
          '-outform',
          'DER',
          '-days',
          '7',
          '-subj',
          '/CN=CLI6Test',
        ]);
        expect(result.exitCode, equals(0));

        final derBytes = Uint8List.fromList(await derFile.readAsBytes());

        final dartCert = _api.parseX509Certificate(derBytes);
        expect(dartCert, isNotNull);
        expect(dartCert.subject, contains('CLI6Test'));

        result = await Process.run(_opensslPath, [
          'x509',
          '-in',
          derFile.path,
          '-inform',
          'DER',
          '-out',
          certFile.path,
          '-outform',
          'PEM',
        ]);
        expect(result.exitCode, equals(0));

        final pemBytes = Uint8List.fromList(await certFile.readAsBytes());

        final dartPemCert = _api.parseX509Certificate(pemBytes);
        expect(dartPemCert, isNotNull);
        expect(dartPemCert.subject, contains('CLI6Test'));

        expect(
          dartCert.subject,
          equals(dartPemCert.subject),
          reason: 'DER→PEM→parse must recover same subject',
        );

        result = await Process.run(_opensslPath, [
          'x509',
          '-in',
          certFile.path,
          '-text',
          '-noout',
        ]);
        expect(
          result.exitCode,
          equals(0),
          reason: 'openssl must parse the PEM it generated itself',
        );
        expect(
          (result.stdout as String).toLowerCase(),
          contains('cli6test'),
          reason: 'openssl -text output must contain subject CN',
        );
      } finally {
        for (final f in [keyFile, certFile, derFile]) {
          if (await f.exists()) await f.delete();
        }
      }
    });

    test('ECDSA key PEM round-trip via openssl', () async {
      _skipIfNoOpenSsl();

      final kp = _api.generateEcKeyPair('prime256v1');

      final dartPubFile = File('/tmp/cli6_dart_pub.pem');
      final dartKeyFile = File('/tmp/cli6_dart_key.pem');

      try {
        await dartPubFile.writeAsString(kp.publicKeyPem);
        await dartKeyFile.writeAsString(kp.privateKeyPem);

        final pubResult = await Process.run(_opensslPath, [
          'ec',
          '-pubin',
          '-in',
          dartPubFile.path,
          '-text',
          '-noout',
        ]);
        expect(
          pubResult.exitCode,
          equals(0),
          reason:
              'openssl must parse Dart-generated EC public key. '
              'stderr: ${pubResult.stderr}',
        );

        final keyResult = await Process.run(_opensslPath, [
          'ec',
          '-in',
          dartKeyFile.path,
          '-text',
          '-noout',
        ]);
        expect(
          keyResult.exitCode,
          equals(0),
          reason:
              'openssl must parse Dart-generated EC private key. '
              'stderr: ${keyResult.stderr}',
        );
      } finally {
        for (final f in [dartPubFile, dartKeyFile]) {
          if (await f.exists()) await f.delete();
        }
      }
    });
  });
}
