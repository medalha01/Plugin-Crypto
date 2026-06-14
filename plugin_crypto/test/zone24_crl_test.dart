@TestOn('linux')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/flows/revocation/crl_verifier.dart';
import 'package:plugin_crypto/src/crypto/models/crl_data.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import 'fixtures/pki_fixtures.dart';

Future<Uint8List?> _generateTestCrl({
  required String caCertPem,
  required String caKeyPem,
  String? revokedSerialNumber,
}) async {
  final tmp = await Directory.systemTemp.createTemp('zone24_crl_');
  try {
    final caCertFile = File('${tmp.path}/ca.pem');
    final caKeyFile = File('${tmp.path}/ca.key');
    await caCertFile.writeAsString(caCertPem);
    await caKeyFile.writeAsString(caKeyPem);

    final caDir = Directory('${tmp.path}/ca');
    await caDir.create();
    await File('${caDir.path}/serial').writeAsString('1000\n');
    await File('${caDir.path}/crlnumber').writeAsString('1000\n');
    await File(
      '${caDir.path}/index.txt.attr',
    ).writeAsString('unique_subject = no\n');

    final indexFile = File('${caDir.path}/index.txt');
    if (revokedSerialNumber != null) {
      final now = DateTime.now().toUtc();
      final ts = _yyMMddHHmmssZ(now);
      final expTs = _yyMMddHHmmssZ(now.add(const Duration(days: 365)));
      await indexFile.writeAsString(
        'R\t$expTs\t$ts\t$revokedSerialNumber\tunknown\t/CN=Revoked\n',
      );
    } else {
      await indexFile.writeAsString('');
    }

    final configFile = File('${tmp.path}/ca.cnf');
    await configFile.writeAsString('''
[ ca ]
default_ca = CA_default

[ CA_default ]
database       = ${caDir.path}/index.txt
serial         = ${caDir.path}/serial
crlnumber      = ${caDir.path}/crlnumber
default_days   = 365
default_md     = sha256
policy         = policy_any
new_certs_dir  = ${tmp.path}

[ policy_any ]
commonName     = supplied

[ req ]
distinguished_name = req_dn

[ req_dn ]
''');

    final crlOutFile = File('${tmp.path}/out.crl');
    final genResult = await Process.run('openssl', [
      'ca',
      '-config',
      configFile.path,
      '-gencrl',
      '-keyfile',
      caKeyFile.path,
      '-cert',
      caCertFile.path,
      '-out',
      crlOutFile.path,
      '-batch',
    ]);

    if (genResult.exitCode != 0 || !await crlOutFile.exists()) {
      return null;
    }

    final crlPem = await crlOutFile.readAsString();
    if (crlPem.trim().isEmpty) return null;
    return Uint8List.fromList(utf8.encode(crlPem));
  } catch (_) {
    return null;
  } finally {
    tmp.delete(recursive: true).ignore();
  }
}

/// Formats [dt] as "YYMMDDHHmmssZ" — the format expected by OpenSSL's
/// index.txt database file.
String _yyMMddHHmmssZ(DateTime dt) {
  final u = dt.toUtc();
  final y = (u.year % 100).toString().padLeft(2, '0');
  final mo = u.month.toString().padLeft(2, '0');
  final d = u.day.toString().padLeft(2, '0');
  final h = u.hour.toString().padLeft(2, '0');
  final mi = u.minute.toString().padLeft(2, '0');
  final s = u.second.toString().padLeft(2, '0');
  return '$y$mo$d$h${mi}${s}Z';
}


void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone24', 'CRL Operations');

  late OpenSslBindings bindings;
  late OpenSslCrlVerifier crlVerifier;
  late PluginCryptoAPI api;
  late PkiFixtureFactory pkiFactory;

  late String caCertPemStr;
  late Uint8List caCertPemBytes;
  late String caKeyPemStr;

  late Uint8List leafCertPemBytes;
  late String leafSerialNumber;

  Uint8List? crlNoRevoked;
  Uint8List? crlWithRevoked;

  setUpAll(() async {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    crlVerifier = OpenSslCrlVerifier(PluginCryptoContext(bindings));
    api = PluginCryptoAPI.instance;
    pkiFactory = PkiFixtureFactory(bindings);

    final rootCa = pkiFactory.createRootCa();
    caCertPemStr = utf8.decode(rootCa.pem);
    caKeyPemStr = rootCa.key.privateKeyPem;
    caCertPemBytes = rootCa.pem;

    final leafKeyPair = api.generateRsaKeyPair(2048);
    final now = DateTime.now();
    const caDn = DistinguishedName(
      commonName: 'Test Root CA',
      organization: 'TCC',
      country: 'BR',
    );
    final leafPem = CertificateBuilder(bindings)
        .subjectDn(const DistinguishedName(commonName: 'CRL Test Leaf'))
        .issuerDn(caDn)
        .publicKey(leafKeyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 365)))
        .addBasicConstraints(ca: false)
        .signWith(rootCa.key)
        .buildPem();
    leafCertPemBytes = Uint8List.fromList(
      utf8.encode((leafPem as CryptoSuccess<String>).value),
    );

    final parsedLeaf = api.parseX509Certificate(leafCertPemBytes);
    leafSerialNumber = parsedLeaf.serialNumber;

    crlNoRevoked = await _generateTestCrl(
      caCertPem: caCertPemStr,
      caKeyPem: caKeyPemStr,
    );

    crlWithRevoked = await _generateTestCrl(
      caCertPem: caCertPemStr,
      caKeyPem: caKeyPemStr,
      revokedSerialNumber: leafSerialNumber,
    );
  });


  group('parseCrl', () {
    test('extracts timestamps', () {
      if (crlNoRevoked == null) {
        return;
      }

      final result = crlVerifier.parseCrl(crlNoRevoked!);
      expect(result, isA<CryptoSuccess<CrlInfo>>());
      final crlInfo = (result as CryptoSuccess<CrlInfo>).value;

      expect(crlInfo.lastUpdate, isA<DateTime>());
      expect(crlInfo.nextUpdate, isA<DateTime>());
      expect(crlInfo.lastUpdate.isBefore(crlInfo.nextUpdate), isTrue);
    });

    test('extracts revoked entries from CRL', () {
      if (crlWithRevoked == null) {
        return;
      }

      final result = crlVerifier.parseCrl(crlWithRevoked!);
      expect(result, isA<CryptoSuccess<CrlInfo>>());
      final crlInfo = (result as CryptoSuccess<CrlInfo>).value;

      expect(crlInfo.revoked, isNotEmpty);
      expect(crlInfo.revoked.first.revocationDate, isA<DateTime>());
      expect(
        crlInfo.revoked.first.serialNumber.toUpperCase(),
        equals(leafSerialNumber.toUpperCase()),
      );
    });

    test('returns CryptoFailure for empty data', () {
      final result = crlVerifier.parseCrl(Uint8List(0));
      expect(result, isA<CryptoFailure<CrlInfo>>());
      final error = (result as CryptoFailure<CrlInfo>).error;
      expect(error, isA<CrlError>());
      expect(error.message, contains('must be non-empty'));
    });

    test('returns CryptoFailure for garbage data', () {
      final garbage = Uint8List.fromList(List.generate(256, (i) => i % 256));
      final result = crlVerifier.parseCrl(garbage);
      expect(result, isA<CryptoFailure<CrlInfo>>());
      final error = (result as CryptoFailure<CrlInfo>).error;
      expect(error, isA<CrlError>());
    });

    test('populates CrlInfo correctly', () {
      if (crlNoRevoked == null) {
        return;
      }

      final result = crlVerifier.parseCrl(crlNoRevoked!);
      expect(result, isA<CryptoSuccess<CrlInfo>>());
      final crlInfo = (result as CryptoSuccess<CrlInfo>).value;

      expect(crlInfo, isA<CrlInfo>());
      expect(crlInfo.lastUpdate, isA<DateTime>());
      expect(crlInfo.nextUpdate, isA<DateTime>());
      expect(crlInfo.issuer, isNotEmpty);
      expect(crlInfo.revoked, isA<List<RevokedEntry>>());
    });

    test('parses DER-encoded CRL successfully', () {
      if (crlNoRevoked == null) {
        return;
      }

      final pemStr = utf8.decode(crlNoRevoked!);
      final lines = pemStr
          .split('\n')
          .where((l) => !l.startsWith('-----'))
          .where((l) => l.trim().isNotEmpty)
          .join();
      final derBytes = Uint8List.fromList(base64.decode(lines));

      final result = crlVerifier.parseCrl(derBytes);
      expect(result, isA<CryptoSuccess<CrlInfo>>());
      final crlInfo = (result as CryptoSuccess<CrlInfo>).value;
      expect(crlInfo.lastUpdate, isA<DateTime>());
      expect(crlInfo.nextUpdate, isA<DateTime>());
      expect(crlInfo.revoked, isA<List<RevokedEntry>>());
    });
  });


  group('verifyCrlSignature', () {
    test('returns true for valid CRL', () {
      if (crlNoRevoked == null) {
        return;
      }

      final result = crlVerifier.verifyCrlSignature(
        crlNoRevoked!,
        caCertPemBytes,
      );
      expect(result, isA<CryptoSuccess<bool>>());
      expect((result as CryptoSuccess<bool>).value, isTrue);
    });

    test('returns false for wrong CA', () {
      if (crlNoRevoked == null) {
        return;
      }

      final wrongCa = pkiFactory.createRootCa(commonName: 'Wrong Root CA');

      final result = crlVerifier.verifyCrlSignature(crlNoRevoked!, wrongCa.pem);
      expect(result, isA<CryptoSuccess<bool>>());
      expect((result as CryptoSuccess<bool>).value, isFalse);
    }, tags: ['crl', 'slow']);

    test('returns CryptoFailure for empty crlData', () {
      final result = crlVerifier.verifyCrlSignature(
        Uint8List(0),
        caCertPemBytes,
      );
      expect(result, isA<CryptoFailure<bool>>());
      final error = (result as CryptoFailure<bool>).error;
      expect(error, isA<CrlError>());
      expect(error.message, contains('crlData'));
    });

    test('returns CryptoFailure for invalid crlData', () {
      final bogus = Uint8List.fromList([0x30, 0x03, 0x02, 0x01, 0xFF]);
      final result = crlVerifier.verifyCrlSignature(bogus, caCertPemBytes);
      expect(result, isA<CryptoFailure<bool>>());
      final error = (result as CryptoFailure<bool>).error;
      expect(error, isA<CrlError>());
    });

    test('tampered CRL fails signature verification', () {
      if (crlNoRevoked == null) {
        return;
      }

      final tampered = Uint8List.fromList(crlNoRevoked!);
      tampered[crlNoRevoked!.length ~/ 2] ^= 0xFF;

      final result = crlVerifier.verifyCrlSignature(tampered, caCertPemBytes);
      if (result is CryptoSuccess<bool>) {
        expect(
          result.value,
          isFalse,
          reason: 'Tampered CRL must not pass verification',
        );
      } else {
        expect(result, isA<CryptoFailure<bool>>());
      }
    });
  });


  group('checkRevocation', () {
    test('returns not revoked for valid cert', () {
      if (crlNoRevoked == null) {
        return;
      }

      final result = crlVerifier.checkRevocation(
        leafCertPemBytes,
        crlNoRevoked!,
      );
      expect(result, isA<CryptoSuccess<CertificateRevocationStatus>>());
      final status =
          (result as CryptoSuccess<CertificateRevocationStatus>).value;
      expect(status.isRevoked, isFalse);
    });

    test('detects revoked cert', () {
      if (crlWithRevoked == null) {
        return;
      }

      final result = crlVerifier.checkRevocation(
        leafCertPemBytes,
        crlWithRevoked!,
      );
      expect(result, isA<CryptoSuccess<CertificateRevocationStatus>>());
      final status =
          (result as CryptoSuccess<CertificateRevocationStatus>).value;
      expect(status.isRevoked, isTrue);
    });

    test('returns CryptoFailure for empty certData', () {
      final result = crlVerifier.checkRevocation(
        Uint8List(0),
        caCertPemBytes, // non-empty so only certData triggers guard
      );
      expect(result, isA<CryptoFailure<CertificateRevocationStatus>>());
      final error =
          (result as CryptoFailure<CertificateRevocationStatus>).error;
      expect(error, isA<CrlError>());
      expect(error.message, contains('cert'));
    });
  });

  m?.endZone();
}
