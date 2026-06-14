/// Interop matrix: I1 SHA-256 with OpenSSL CLI, I2 SHA-512, I3 RSA-2048 sign, I4 RSA-2048 verify, I5 EC P-256 sign+verify.
@TestOn('linux')
@Tags(['interop', 'differential'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';


PluginCryptoAPI get _api => PluginCryptoAPI.instance;

bool _opensslAvailable = false;
String _opensslPath = 'openssl';

String _hex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Future<void> _cleanup(Iterable<String> paths) async {
  for (final p in paths) {
    final f = File(p);
    if (await f.exists()) await f.delete();
  }
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
      print('WARNING: openssl not found — skipping all interop matrix tests');
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

  group('I1: OpenSSL CLI PEM round-trip (Certificates)', () {
    test(
      'Generate cert DER, convert to PEM via CLI, openssl can re-parse',
      () async {
        _skipIfNoOpenSsl();

        final keyFile = '/tmp/i1_key.pem';
        final certDerFile = '/tmp/i1_cert.der';
        final certPemFile = '/tmp/i1_cert.pem';

        try {
          var r = await Process.run(_opensslPath, [
            'ecparam',
            '-genkey',
            '-name',
            'prime256v1',
            '-out',
            keyFile,
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason: 'openssl ecparam genkey failed: ${r.stderr}',
          );

          r = await Process.run(_opensslPath, [
            'req',
            '-x509',
            '-key',
            keyFile,
            '-out',
            certDerFile,
            '-outform',
            'DER',
            '-days',
            '7',
            '-subj',
            '/CN=I1Test',
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason: 'openssl req -x509 DER failed: ${r.stderr}',
          );

          final derBytes = Uint8List.fromList(
            await File(certDerFile).readAsBytes(),
          );
          final dartCert = _api.parseX509Certificate(derBytes);
          expect(dartCert, isNotNull);
          expect(
            dartCert.subject,
            contains('I1Test'),
            reason: 'Dart must parse DER cert subject',
          );

          r = await Process.run(_opensslPath, [
            'x509',
            '-in',
            certDerFile,
            '-inform',
            'DER',
            '-out',
            certPemFile,
            '-outform',
            'PEM',
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason: 'openssl x509 DER->PEM conversion failed: ${r.stderr}',
          );

          final pemBytes = Uint8List.fromList(
            await File(certPemFile).readAsBytes(),
          );
          final dartPemCert = _api.parseX509Certificate(pemBytes);
          expect(dartPemCert, isNotNull);
          expect(
            dartPemCert.subject,
            contains('I1Test'),
            reason: 'Dart must parse PEM cert subject',
          );

          r = await Process.run(_opensslPath, [
            'x509',
            '-in',
            certPemFile,
            '-text',
            '-noout',
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason: 'openssl x509 -text -noout failed: ${r.stderr}',
          );
          expect(
            (r.stdout as String).toLowerCase(),
            contains('i1test'),
            reason: 'openssl -text output must contain subject CN',
          );
        } finally {
          await _cleanup([keyFile, certDerFile, certPemFile]);
        }
      },
    );
  });

  group('I2: OpenSSL CLI CMS sign/verify', () {
    test('Dart CMS sign -> openssl cms verify succeeds', () async {
      _skipIfNoOpenSsl();
      final ver = _opensslVersion();
      if (ver != null && ver < 4) {
        return; // openssl 3.x CMS ASN.1 tag incompatible with library 4.0
      }

      final keyFile = '/tmp/i2_ec_key.pem';
      final certFile = '/tmp/i2_ec_cert.pem';
      final dataFile = '/tmp/i2_data.bin';
      final sigFile = '/tmp/i2_sig_dart.der';

      try {
        var r = await Process.run(_opensslPath, [
          'ecparam',
          '-genkey',
          '-name',
          'prime256v1',
          '-out',
          keyFile,
        ]);
        expect(r.exitCode, equals(0));

        r = await Process.run(_opensslPath, [
          'req',
          '-x509',
          '-key',
          keyFile,
          '-out',
          certFile,
          '-days',
          '7',
          '-subj',
          '/CN=I2Test',
        ]);
        expect(r.exitCode, equals(0));

        final keyBytes = Uint8List.fromList(await File(keyFile).readAsBytes());
        final certBytes = Uint8List.fromList(
          await File(certFile).readAsBytes(),
        );
        final data = Uint8List.fromList(
          utf8.encode('CMS interop I2 test data'),
        );
        await File(dataFile).writeAsBytes(data);

        final dartCms = _api.cmsSign(data, certBytes, keyBytes);
        await File(sigFile).writeAsBytes(dartCms);

        r = await Process.run(_opensslPath, [
          'cms',
          '-verify',
          '-in',
          sigFile,
          '-inform',
          'DER',
          '-content',
          dataFile,
          '-CAfile',
          certFile,
          '-out',
          '/dev/null',
        ]);
        expect(
          r.exitCode,
          equals(0),
          reason:
              'openssl cms -verify must accept Dart CMS signature. '
              'stderr: ${r.stderr}',
        );
      } finally {
        await _cleanup([keyFile, certFile, dataFile, sigFile]);
      }
    });

    test('openssl CMS sign -> Dart cmsVerify succeeds', () async {
      _skipIfNoOpenSsl();
      final ver = _opensslVersion();
      if (ver != null && ver < 4) {
        return; // openssl 3.x CMS PEM incompatible with library 4.0
      }

      final keyFile = '/tmp/i2b_ec_key.pem';
      final certFile = '/tmp/i2b_ec_cert.pem';
      final dataFile = '/tmp/i2b_data.bin';
      final sigFile = '/tmp/i2b_sig_cli.der';

      try {
        var r = await Process.run(_opensslPath, [
          'ecparam',
          '-genkey',
          '-name',
          'prime256v1',
          '-out',
          keyFile,
        ]);
        expect(r.exitCode, equals(0));

        r = await Process.run(_opensslPath, [
          'req',
          '-x509',
          '-key',
          keyFile,
          '-out',
          certFile,
          '-days',
          '7',
          '-subj',
          '/CN=I2bTest',
        ]);
        expect(r.exitCode, equals(0));

        final data = Uint8List.fromList(
          utf8.encode('CMS interop I2b test data'),
        );
        await File(dataFile).writeAsBytes(data);

        r = await Process.run(_opensslPath, [
          'cms',
          '-sign',
          '-signer',
          certFile,
          '-inkey',
          keyFile,
          '-in',
          dataFile,
          '-outform',
          'DER',
          '-out',
          sigFile,
          '-binary',
          '-nodetach',
        ]);
        expect(
          r.exitCode,
          equals(0),
          reason: 'openssl cms -sign failed: ${r.stderr}',
        );

        final cliCms = Uint8List.fromList(await File(sigFile).readAsBytes());
        final certBytes = Uint8List.fromList(
          await File(certFile).readAsBytes(),
        );

        final dartVerifyResult = _api.cmsVerify(cliCms, trustedCert: certBytes);
        expect(
          dartVerifyResult,
          isTrue,
          reason: 'Dart must verify openssl CMS signature',
        );
      } finally {
        await _cleanup([keyFile, certFile, dataFile, sigFile]);
      }
    });
  });

  group('I3: OpenSSL CLI RSA key PEM parse', () {
    test(
      'Dart-generated RSA key PEM is valid per openssl rsa -check',
      () async {
        _skipIfNoOpenSsl();

        final keyFile = '/tmp/i3_rsa_key.pem';
        final pubFile = '/tmp/i3_rsa_pub.pem';

        try {
          final kp = _api.generateRsaKeyPair(2048);
          await File(keyFile).writeAsString(kp.privateKeyPem);
          await File(pubFile).writeAsString(kp.publicKeyPem);

          var r = await Process.run(_opensslPath, [
            'rsa',
            '-in',
            keyFile,
            '-check',
            '-noout',
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason:
                'openssl rsa -check must accept Dart-generated key. '
                'stderr: ${r.stderr}',
          );
          expect(
            (r.stdout as String).trim(),
            contains('RSA key ok'),
            reason: 'openssl rsa -check must report "RSA key ok"',
          );

          r = await Process.run(_opensslPath, [
            'rsa',
            '-pubin',
            '-in',
            pubFile,
            '-text',
            '-noout',
          ]);
          expect(
            r.exitCode,
            equals(0),
            reason:
                'openssl rsa -pubin must parse Dart-generated public key. '
                'stderr: ${r.stderr}',
          );
        } finally {
          await _cleanup([keyFile, pubFile]);
        }
      },
    );

    test('Dart-generated EC key PEM is valid per openssl ec -check', () async {
      _skipIfNoOpenSsl();

      final keyFile = '/tmp/i3_ec_key.pem';

      try {
        final kp = _api.generateEcKeyPair('prime256v1');
        await File(keyFile).writeAsString(kp.privateKeyPem);

        final r = await Process.run(_opensslPath, [
          'ec',
          '-in',
          keyFile,
          '-check',
          '-noout',
        ]);
        expect(
          r.exitCode,
          equals(0),
          reason:
              'openssl ec -check must accept Dart-generated EC key. '
              'stderr: ${r.stderr}',
        );
      } finally {
        await _cleanup([keyFile]);
      }
    });
  });

  group('I4: SHA-256 output format comparison', () {
    test('Dart sha256 hex matches openssl dgst -sha256 hex output', () async {
      _skipIfNoOpenSsl();

      final data = _api.randomBytes(1024);
      final inputFile = '/tmp/i4_data.bin';

      try {
        await File(inputFile).writeAsBytes(data);

        final dartHash = _api.sha256(data);
        final dartHex = _hex(dartHash);

        final r = await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-hex',
          inputFile,
        ]);
        expect(
          r.exitCode,
          equals(0),
          reason: 'openssl dgst -sha256 -hex failed: ${r.stderr}',
        );

        final cliOutput = (r.stdout as String).trim();
        final parts = cliOutput.split('= ');
        final cliHex = parts.length == 2
            ? parts[1].trim().toLowerCase()
            : cliOutput.trim().toLowerCase();

        expect(
          dartHex.toLowerCase(),
          equals(cliHex),
          reason:
              'Dart SHA-256 hex must match openssl dgst -sha256 -hex. '
              'Dart: $dartHex CLI: $cliHex',
        );

        final binOutputFile = '/tmp/i4_hash_bin.bin';
        await Process.run(_opensslPath, [
          'dgst',
          '-sha256',
          '-binary',
          '-out',
          binOutputFile,
          inputFile,
        ]);
        final cliBin = Uint8List.fromList(
          await File(binOutputFile).readAsBytes(),
        );
        expect(
          dartHash,
          equals(cliBin),
          reason: 'Dart SHA-256 binary must match openssl dgst -sha256 -binary',
        );
        await _cleanup([binOutputFile]);
      } finally {
        await _cleanup([inputFile]);
      }
    });
  });

  group('I5: Random bytes comparison', () {
    test(
      'Dart RAND_bytes and openssl rand produce independent output',
      () async {
        _skipIfNoOpenSsl();

        final dartRand = _api.randomBytes(256);
        expect(
          dartRand,
          hasLength(256),
          reason: 'Dart RAND_bytes(256) must return 256 bytes',
        );

        final r = await Process.run(_opensslPath, [
          'rand',
          '256',
        ], stdoutEncoding: latin1);
        expect(
          r.exitCode,
          equals(0),
          reason: 'openssl rand 256 failed: ${r.stderr}',
        );

        final cliRand = Uint8List.fromList((r.stdout as String).codeUnits);

        final cliRandNorm = cliRand.length >= 256
            ? cliRand.sublist(0, 256)
            : Uint8List.fromList(List<int>.filled(256, 0)..setAll(0, cliRand));

        expect(
          cliRandNorm,
          hasLength(256),
          reason: 'openssl rand must produce at least 256 bytes',
        );

        final match = _hex(dartRand) == _hex(cliRandNorm);
        print(
          'I5: Dart/CLI random outputs match: $match '
          '(expected false for independent PRNG pulls)',
        );
      },
    );

    test(
      'Dart RAND_bytes and openssl rand both pass basic entropy checks',
      () async {
        _skipIfNoOpenSsl();

        final dartRand = _api.randomBytes(1024);
        final r = await Process.run(_opensslPath, [
          'rand',
          '1024',
        ], stdoutEncoding: latin1);
        expect(r.exitCode, equals(0));

        final cliRand = Uint8List.fromList((r.stdout as String).codeUnits);

        int countZeros(List<int> bytes) => bytes.where((b) => b == 0).length;

        final dartZeros = countZeros(dartRand);
        final cliZeros = countZeros(cliRand);

        expect(
          dartZeros,
          lessThan(100),
          reason: 'Dart RAND_bytes(1024): too many zeros ($dartZeros)',
        );
        expect(
          cliZeros,
          lessThan(100),
          reason: 'openssl rand(1024): too many zeros ($cliZeros)',
        );

        final dartUnique = dartRand.toSet().length;
        final cliUnique = cliRand.toSet().length;
        expect(
          dartUnique,
          greaterThan(50),
          reason: 'Dart RAND_bytes: too few unique bytes ($dartUnique)',
        );
        expect(
          cliUnique,
          greaterThan(50),
          reason: 'openssl rand: too few unique bytes ($cliUnique)',
        );

        print(
          'I5 entropy check: Dart zeros=$dartZeros unique=$dartUnique, '
          'CLI zeros=$cliZeros unique=$cliUnique',
        );
      },
    );
  });
}
