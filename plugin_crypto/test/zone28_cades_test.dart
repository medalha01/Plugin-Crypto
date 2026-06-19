@TestOn('linux')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/cms_operations.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

const testDn = DistinguishedName(commonName: 'CAdES Test');

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone28', 'CAdES-BES Signing');

  late OpenSslBindings bindings;
  late PluginCryptoAPI api;
  late CmsOperations cms;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    api = PluginCryptoAPI.instance;
    cms = CmsOperations(bindings);
  });

  /// Creates a self-signed RSA certificate and returns (cert PEM bytes,
  /// key PEM bytes).
  ({Uint8List certPem, Uint8List keyPem}) _createRsaCert({
    String commonName = 'CAdES RSA',
  }) {
    final keyPair = api.generateRsaKeyPair(2048);
    final now = DateTime.now();
    final result = CertificateBuilder(bindings)
        .subjectDn(DistinguishedName(commonName: commonName))
        .issuerDn(DistinguishedName(commonName: commonName))
        .publicKey(keyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 365)))
        .signWith(keyPair)
        .buildPem();
    final pem = (result as CryptoSuccess<String>).value;

    return (
      certPem: Uint8List.fromList(utf8.encode(pem)),
      keyPem: Uint8List.fromList(utf8.encode(keyPair.privateKeyPem)),
    );
  }

  /// Creates a self-signed EC certificate.
  ({Uint8List certPem, Uint8List keyPem}) _createEcCert() {
    final keyPair = api.generateEcKeyPair('prime256v1');
    final now = DateTime.now();
    final result = CertificateBuilder(bindings)
        .subjectDn(const DistinguishedName(commonName: 'CAdES EC'))
        .issuerDn(const DistinguishedName(commonName: 'CAdES EC'))
        .publicKey(keyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 365)))
        .signWith(keyPair)
        .buildPem();
    final pem = (result as CryptoSuccess<String>).value;

    return (
      certPem: Uint8List.fromList(utf8.encode(pem)),
      keyPem: Uint8List.fromList(utf8.encode(keyPair.privateKeyPem)),
    );
  }

  group('cmsSignCades basic output', () {
    test('produces valid non-empty DER output', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('CAdES basic output test'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotNull);
      expect(signed, isNotEmpty);
      expect(signed, isA<Uint8List>());
      expect(signed.length, greaterThan(100));
      expect(signed.first, 0x30, reason: 'CAdES output must be DER');
    });

    test('produces DER output for small data', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('x'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      expect(signed.length, greaterThan(100));
    });

    test('produces DER output for larger data', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('large payload ' * 200));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      expect(signed.length, greaterThan(100));
    });
  });

  group('CAdES-BES structure', () {
    test('contains SigningCertificateV2 and parses independently', () async {
      final (:certPem, :keyPem) = _createRsaCert();
      final signed = cms.cmsSignCadesBes(
        Uint8List.fromList(utf8.encode('CAdES structure test')),
        certPem,
        keyPem,
      );
      final directory = await Directory.systemTemp.createTemp('cades-bes-');
      final file = File('${directory.path}/signature.der');
      try {
        await file.writeAsBytes(signed);
        final result = await Process.run('openssl', [
          'cms',
          '-cmsout',
          '-inform',
          'DER',
          '-in',
          file.path,
          '-print',
        ]);
        expect(result.exitCode, 0, reason: '${result.stderr}');
        final output = '${result.stdout}';
        expect(
          output.contains('signingCertificateV2') ||
              output.contains('1.2.840.113549.1.9.16.2.47'),
          isTrue,
          reason: 'ESS SigningCertificateV2 attribute is required for CAdES-BES',
        );
      } finally {
        await directory.delete(recursive: true);
      }
    });
  });

  group('cmsSignCades signed attributes', () {
    test('signs with signingTime and messageDigest (defaults)', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('signed attrs test'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });

    test('rejects disabling mandatory messageDigest', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('signing time only'));

      expect(
        () => cms.cmsSignCades(
          data,
          certPem,
          keyPem,
          addSigningTime: true,
          addMessageDigest: false,
        ),
        throwsArgumentError,
      );
    });

    test('rejects disabling mandatory CAdES attributes', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('no signed attrs'));

      expect(
        () => cms.cmsSignCades(
          data,
          certPem,
          keyPem,
          addSigningTime: false,
          addMessageDigest: false,
        ),
        throwsArgumentError,
      );
    });
  });

  group('cmsSignCades embedded certs', () {
    test('embeds CA certificate in CMS cert bag', () {
      final signer = _createRsaCert(commonName: 'Signer');
      final ca = _createRsaCert(commonName: 'CA');

      final data = Uint8List.fromList(utf8.encode('CA embed test'));

      final signed = cms.cmsSignCades(
        data,
        signer.certPem,
        signer.keyPem,
        caCertPem: ca.certPem,
      );

      expect(signed, isNotEmpty);
      expect(signed.length, greaterThan(100));
      final verified = api.cmsVerify(signed, trustedCert: signer.certPem);
      expect(verified, isTrue);
    });

    test('embeds intermediate certificates in CMS cert bag', () {
      final signer = _createRsaCert(commonName: 'Signer');
      final intermediate = _createRsaCert(commonName: 'Intermediate');

      final data = Uint8List.fromList(utf8.encode('intermediates test'));

      final signed = cms.cmsSignCades(
        data,
        signer.certPem,
        signer.keyPem,
        intermediates: [intermediate.certPem],
      );

      expect(signed, isNotEmpty);
      final signedNoInt = cms.cmsSignCades(data, signer.certPem, signer.keyPem);
      expect(signed.length, greaterThan(signedNoInt.length));
      final verified = api.cmsVerify(signed, trustedCert: signer.certPem);
      expect(verified, isTrue);
    });

    test('embedded CA cert increases output size', () {
      final signer = _createRsaCert(commonName: 'Signer');
      final ca = _createRsaCert(commonName: 'Root CA');

      final data = Uint8List.fromList(utf8.encode('size comparison'));

      final signedNoCa = cms.cmsSignCades(data, signer.certPem, signer.keyPem);
      final signedWithCa = cms.cmsSignCades(
        data,
        signer.certPem,
        signer.keyPem,
        caCertPem: ca.certPem,
      );

      expect(signedWithCa.length, greaterThan(signedNoCa.length));
    });
  });

  group('cmsSignCades round-trip', () {
    test('CAdES sign and verify round-trip with RSA', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('RSA CAdES round-trip'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);
      expect(signed, isNotEmpty);

      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });

    test('CAdES sign and verify round-trip with EC', () {
      final (:certPem, :keyPem) = _createEcCert();
      final data = Uint8List.fromList(utf8.encode('EC CAdES round-trip'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);
      expect(signed, isNotEmpty);

      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });

    test('CAdES verify fails with wrong trusted cert', () {
      final signer = _createRsaCert();
      final wrong = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('wrong cert test'));

      final signed = cms.cmsSignCades(data, signer.certPem, signer.keyPem);
      final verified = api.cmsVerify(signed, trustedCert: wrong.certPem);

      expect(verified, isFalse);
    });
  });

  group('cmsSignCades key types', () {
    test('signs with RSA 2048 key', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('RSA 2048'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });

    test('signs with EC prime256v1 key', () {
      final (:certPem, :keyPem) = _createEcCert();
      final data = Uint8List.fromList(utf8.encode('EC prime256v1'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });

    test('signs with RSA 4096 key', () {
      final keyPair = api.generateRsaKeyPair(4096);
      final now = DateTime.now();
      final result = CertificateBuilder(bindings)
          .subjectDn(const DistinguishedName(commonName: 'RSA 4096'))
          .issuerDn(const DistinguishedName(commonName: 'RSA 4096'))
          .publicKey(keyPair)
          .notBefore(now)
          .notAfter(now.add(const Duration(days: 365)))
          .signWith(keyPair)
          .buildPem();
      final certPem = Uint8List.fromList(
        utf8.encode((result as CryptoSuccess<String>).value),
      );
      final keyPem = Uint8List.fromList(utf8.encode(keyPair.privateKeyPem));
      final data = Uint8List.fromList(utf8.encode('RSA 4096 CAdES'));

      final signed = cms.cmsSignCades(data, certPem, keyPem);

      expect(signed, isNotEmpty);
      final verified = api.cmsVerify(signed, trustedCert: certPem);
      expect(verified, isTrue);
    });
  });

  group('cmsSignCades input validation', () {
    test('throws ArgumentError for empty data', () {
      final (:certPem, :keyPem) = _createRsaCert();
      final emptyData = Uint8List(0);

      expect(
        () => cms.cmsSignCades(emptyData, certPem, keyPem),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError for empty certPem', () {
      final r = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('no cert'));
      final emptyCert = Uint8List(0);

      expect(
        () => cms.cmsSignCades(data, emptyCert, r.keyPem),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError for empty keyPem', () {
      final r = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('no key'));
      final emptyKey = Uint8List(0);

      expect(
        () => cms.cmsSignCades(data, r.certPem, emptyKey),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws StateError for invalid key (garbage bytes)', () {
      final r = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('invalid key'));
      final garbageKey = Uint8List.fromList(
        utf8.encode(
          '-----BEGIN PRIVATE KEY-----\nnot a valid key\n-----END PRIVATE KEY-----',
        ),
      );

      expect(
        () => cms.cmsSignCades(data, r.certPem, garbageKey),
        throwsA(isA<StateError>()),
      );
    });

    test('throws StateError for invalid cert (garbage bytes)', () {
      final r = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('invalid cert'));
      final garbageCert = Uint8List.fromList(
        utf8.encode(
          '-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----',
        ),
      );

      expect(
        () => cms.cmsSignCades(data, garbageCert, r.keyPem),
        throwsA(isA<StateError>()),
      );
    });

    test('throws StateError for mismatched cert and key', () {
      final signer = _createRsaCert();
      final other = _createRsaCert();
      final data = Uint8List.fromList(utf8.encode('mismatch test'));

      expect(
        () => cms.cmsSignCades(data, signer.certPem, other.keyPem),
        throwsA(isA<StateError>()),
      );
    });
  });

  m?.endZone();
}
