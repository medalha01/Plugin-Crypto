/// Cross-algorithm, corrupted keys, platform coverage, and ML-KEM adversarial tests.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/self_signed_cert_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/file_signing/streaming_file_signer.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';


/// Converts a PEM string to [Uint8List] for API calls that expect bytes.
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Generates random bytes of [length] for test content.
Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)));
}

/// Creates a temporary file with the given [bytes] content and returns the
/// file path.
String _createTempFileBytes(Uint8List bytes) {
  final dir = Directory.systemTemp;
  final suffix = Random.secure().nextInt(999999).toString().padLeft(6, '0');
  final file = File('${dir.path}/tcc_e2e_adv_${suffix}_test.bin');
  file.writeAsBytesSync(bytes);
  return file.path;
}

/// Result of [_createCert] helper containing all generated artifacts.
class _CertResult {
  final KeyPair keyPair;
  final Uint8List derBytes;
  final X509Certificate parsed;
  final String pemString;
  final DateTime notBefore;
  final DateTime notAfter;

  const _CertResult({
    required this.keyPair,
    required this.derBytes,
    required this.parsed,
    required this.pemString,
    required this.notBefore,
    required this.notAfter,
  });
}

/// Helper: generates a key pair and creates a self-signed certificate.
_CertResult _createCert(
  KeyCreatorFactory factory,
  OpenSslBindings bindings,
  KeySpec spec,
  DistinguishedName dn,
) {
  final creator = factory.createOrThrow(spec);
  final keyResult = creator.create(spec);
  expect(keyResult, isA<CryptoSuccess<KeyPair>>());
  final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

  final now = DateTime.now();
  final certCreator = SelfSignedCertCreator(bindings);
  final request = CertificateRequest(
    subject: dn,
    issuer: dn,
    subjectPublicKey: keyPair,
    issuerPrivateKey: keyPair,
    notBefore: now,
    notAfter: now.add(const Duration(days: 365)),
  );

  final result = certCreator.create(request);
  expect(result, isA<CryptoSuccess<CertificateData>>());
  final certData = (result as CryptoSuccess<CertificateData>).value;
  expect(certData.derBytes, isNotEmpty);
  expect(certData.pemString, isNotEmpty);

  return _CertResult(
    keyPair: keyPair,
    derBytes: certData.derBytes,
    parsed: certData.parsed,
    pemString: certData.pemString,
    notBefore: certData.notBefore,
    notAfter: certData.notAfter,
  );
}

/// Creates a certificate via [SelfSignedCertCreator] with explicit validity.
_CertResult _createCertWithValidity(
  KeyCreatorFactory factory,
  OpenSslBindings bindings,
  KeySpec spec,
  DistinguishedName dn,
  DateTime notBefore,
  DateTime notAfter,
) {
  final creator = factory.createOrThrow(spec);
  final keyResult = creator.create(spec);
  expect(keyResult, isA<CryptoSuccess<KeyPair>>());
  final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

  final certCreator = SelfSignedCertCreator(bindings);
  final request = CertificateRequest(
    subject: dn,
    issuer: dn,
    subjectPublicKey: keyPair,
    issuerPrivateKey: keyPair,
    notBefore: notBefore,
    notAfter: notAfter,
  );

  final result = certCreator.create(request);
  expect(result, isA<CryptoSuccess<CertificateData>>());
  final certData = (result as CryptoSuccess<CertificateData>).value;

  return _CertResult(
    keyPair: keyPair,
    derBytes: certData.derBytes,
    parsed: certData.parsed,
    pemString: certData.pemString,
    notBefore: certData.notBefore,
    notAfter: certData.notAfter,
  );
}

/// Creates a certificate via [CertificateBuilder] for custom extensions.
_CertResult _createCertWithBuilder(
  OpenSslBindings bindings,
  KeyPair keyPair,
  DistinguishedName dn,
  CertificateBuilder Function(CertificateBuilder) config,
) {
  final builder = CertificateBuilder(bindings)
      .subjectDn(dn)
      .issuerDn(dn)
      .publicKey(keyPair)
      .signWith(keyPair);

  final configured = config(builder);
  final pemResult = configured.buildPem();
  expect(pemResult, isA<CryptoSuccess<String>>());
  final pemStr = (pemResult as CryptoSuccess<String>).value;

  final parsed = PluginCryptoAPI.instance
      .parseX509Certificate(Uint8List.fromList(utf8.encode(pemStr)));

  return _CertResult(
    keyPair: keyPair,
    derBytes: Uint8List.fromList(utf8.encode(pemStr)),
    parsed: parsed,
    pemString: pemStr,
    notBefore: parsed.notBefore,
    notAfter: parsed.notAfter,
  );
}


void main() {
  late OpenSslBindings bindings;
  late KeyCreatorFactory factory;
  late PluginCryptoAPI api;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    factory = KeyCreatorFactory(bindings);
    api = PluginCryptoAPI.instance;
  });


  group('B: Cross-Algorithm Key Rejection', () {
    test('B1: RSA-signed data verified with EC-P256 key returns false', () {
      final rsaSpec = RsaKeySpec(2048);
      final rsaCreator = factory.createOrThrow(rsaSpec);
      final rsaResult = rsaCreator.create(rsaSpec);
      final rsaKey = (rsaResult as CryptoSuccess<KeyPair>).value;

      final ecSpec = EcKeySpec('prime256v1');
      final ecCreator = factory.createOrThrow(ecSpec);
      final ecResult = ecCreator.create(ecSpec);
      final ecKey = (ecResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(rsaKey.privateKeyPem), hashAlgorithm: 'sha256');
      expect(signature, isNotEmpty);

      final verified = api.verify(data, _pem(ecKey.publicKeyPem), signature,
          hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason:
              'RSA-signed data must not verify with an EC-P256 public key');
    });

    test('B2: EC-signed data verified with ML-DSA key returns false', () {
      final ecSpec = EcKeySpec('prime256v1');
      final ecCreator = factory.createOrThrow(ecSpec);
      final ecResult = ecCreator.create(ecSpec);
      final ecKey = (ecResult as CryptoSuccess<KeyPair>).value;

      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final mlDsaCreator = factory.createOrThrow(mlDsaSpec);
      final mlDsaResult = mlDsaCreator.create(mlDsaSpec);
      final mlDsaKey = (mlDsaResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(ecKey.privateKeyPem), hashAlgorithm: 'sha256');
      expect(signature, isNotEmpty);

      final v2 = api.verify(data, _pem(mlDsaKey.publicKeyPem), signature,
          hashAlgorithm: 'sha256');
      expect(v2, isFalse,
          reason:
              'EC-signed data must not verify with an ML-DSA public key');
    });

    test('B3: RSA-signed data verified with ML-DSA key returns false', () {
      final rsaSpec = RsaKeySpec(2048);
      final rsaCreator = factory.createOrThrow(rsaSpec);
      final rsaResult = rsaCreator.create(rsaSpec);
      final rsaKey = (rsaResult as CryptoSuccess<KeyPair>).value;

      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final mlDsaCreator = factory.createOrThrow(mlDsaSpec);
      final mlDsaResult = mlDsaCreator.create(mlDsaSpec);
      final mlDsaKey = (mlDsaResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(rsaKey.privateKeyPem), hashAlgorithm: 'sha256');
      expect(signature, isNotEmpty);

      final v3 = api.verify(data, _pem(mlDsaKey.publicKeyPem), signature,
          hashAlgorithm: 'sha256');
      expect(v3, isFalse,
          reason:
              'RSA-signed data must not verify with an ML-DSA public key');
    });

    test('B4: Corrupted PEM private key produces graceful error', () {
      const corruptedPem = '''
-----BEGIN PRIVATE KEY-----
THIS_IS_TOTALLY_CORRUPTED_BASE64_DATA_NOT_VALID_AT_ALL
-----END PRIVATE KEY-----
''';

      final data = _randomBytes(64);

      expect(
        () => api.sign(data, _pem(corruptedPem), hashAlgorithm: 'sha256'),
        throwsA(isA<StateError>()),
        reason: 'Corrupted PEM should cause a StateError, not a crash',
      );
    });

    test('B5: Verify with garbage bytes returns false (does not crash)', () {
      final rsaSpec = RsaKeySpec(2048);
      final rsaCreator = factory.createOrThrow(rsaSpec);
      final rsaResult = rsaCreator.create(rsaSpec);
      final rsaKey = (rsaResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(128);

      final signature =
          api.sign(data, _pem(rsaKey.privateKeyPem), hashAlgorithm: 'sha256');

      final garbageKey = _randomBytes(128);

      expect(
        () => api.verify(data, garbageKey, signature,
            hashAlgorithm: 'sha256'),
        throwsA(isA<StateError>()),
        reason: 'Garbage bytes as public key should throw StateError, '
            'not crash',
      );
    });

    test(
        'B6: Sign with RSA key k1, verify with different RSA key k2 '
        'returns false', () {
      final rsaSpec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(rsaSpec);

      final k1Result = creator.create(rsaSpec);
      final k2Result = creator.create(rsaSpec);
      final k1 = (k1Result as CryptoSuccess<KeyPair>).value;
      final k2 = (k2Result as CryptoSuccess<KeyPair>).value;

      expect(k1.privateKeyPem, isNot(equals(k2.privateKeyPem)));

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(k1.privateKeyPem), hashAlgorithm: 'sha256');

      final verified =
          api.verify(data, _pem(k2.publicKeyPem), signature,
              hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason:
              'Signature from k1 must not verify with k2 public key');
    });

    test('B7: Verify with truncated signature returns false', () {
      final rsaSpec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(rsaSpec);
      final keyResult = creator.create(rsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(keyPair.privateKeyPem),
              hashAlgorithm: 'sha256');
      expect(signature, isNotEmpty);

      final halfLen = signature.length ~/ 2;
      final truncatedSig = Uint8List.fromList(signature.sublist(0, halfLen));

      final verified =
          api.verify(data, _pem(keyPair.publicKeyPem), truncatedSig,
              hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason: 'Truncated signature must not verify');
    });

    test('B8: Verify with extra bytes appended to signature returns false',
        () {
      final rsaSpec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(rsaSpec);
      final keyResult = creator.create(rsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final signature =
          api.sign(data, _pem(keyPair.privateKeyPem),
              hashAlgorithm: 'sha256');

      final extra = _randomBytes(32);
      final extendedSig = Uint8List.fromList([...signature, ...extra]);

      final verified =
          api.verify(data, _pem(keyPair.publicKeyPem), extendedSig,
              hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason:
              'Signature with extra bytes appended must not verify');
    });
  });


  group('D: Untrusted/Bad Certificate Validation', () {
    test('D1: Expired certificate — notAfter is in the past', () {
      const dn = DistinguishedName(commonName: 'ExpiredCert');
      final spec = RsaKeySpec(2048);

      final now = DateTime.now();
      final notBefore = now.subtract(const Duration(days: 30));
      final notAfter = now.subtract(const Duration(days: 1));

      final cert = _createCertWithValidity(
          factory, bindings, spec, dn, notBefore, notAfter);

      expect(cert.notAfter.isBefore(now), isTrue,
          reason:
              'Certificate notAfter (${cert.notAfter}) should be before '
              'now ($now) — it is expired');
      expect(cert.notBefore.isBefore(cert.notAfter), isTrue,
          reason: 'notBefore should still precede notAfter');
      expect(cert.parsed.subject, contains('ExpiredCert'));
      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
    });

    test('D2: Not-yet-valid certificate — notBefore is in the future', () {
      const dn = DistinguishedName(commonName: 'FutureCert');
      final spec = RsaKeySpec(2048);

      final now = DateTime.now();
      final notBefore = now.add(const Duration(days: 1));
      final notAfter = now.add(const Duration(days: 365 + 1));

      final cert = _createCertWithValidity(
          factory, bindings, spec, dn, notBefore, notAfter);

      expect(cert.notBefore.isAfter(now), isTrue,
          reason:
              'Certificate notBefore (${cert.notBefore}) should be after '
              'now ($now) — it is not yet valid');
      expect(cert.parsed.subject, contains('FutureCert'));
      expect(cert.derBytes, isNotEmpty);
    });

    test(
        'D3: Certificate with keyEncipherment only (no digitalSignature) '
        'still parses correctly', () {
      const dn = DistinguishedName(commonName: 'EncOnlyCert');
      final spec = RsaKeySpec(2048);

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final cert = _createCertWithBuilder(bindings, keyPair, dn, (builder) {
        return builder
            .validityPeriod(const Duration(days: 365))
            .addKeyUsage(
                digitalSignature: false, keyEncipherment: true)
            .addBasicConstraints(ca: false);
      });

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.parsed.subject, contains('EncOnlyCert'));

    });

    test('D4: Self-signed cert with mismatched issuer/subject domain names',
        () {
      const subjectDn =
          DistinguishedName(commonName: 'SubjectCN', organization: 'OrgA');
      const issuerDn =
          DistinguishedName(commonName: 'IssuerCN', organization: 'OrgB');
      final spec = RsaKeySpec(2048);

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final now = DateTime.now();
      final certCreator = SelfSignedCertCreator(bindings);
      final request = CertificateRequest(
        subject: subjectDn,
        issuer: issuerDn,
        subjectPublicKey: keyPair,
        issuerPrivateKey: keyPair,
        notBefore: now,
        notAfter: now.add(const Duration(days: 365)),
      );

      final result = certCreator.create(request);
      expect(result, isA<CryptoSuccess<CertificateData>>());
      final certData = (result as CryptoSuccess<CertificateData>).value;

      expect(certData.derBytes, isNotEmpty);
      expect(certData.parsed.subject, contains('SubjectCN'));
      expect(certData.parsed.issuer, contains('IssuerCN'));
      expect(certData.parsed.subject,
          isNot(equals(certData.parsed.issuer)),
          reason:
              'Subject and issuer DNs should differ for '
              'mismatched certificate');
    });

    test('D5: Certificate with 100-year validity parses correctly', () {
      const dn = DistinguishedName(commonName: 'CenturyCert');
      final spec = RsaKeySpec(2048);

      final now = DateTime.now();
      final notAfter = now.add(const Duration(days: 365 * 100));

      final cert = _createCertWithValidity(
          factory, bindings, spec, dn, now, notAfter);

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.parsed.subject, contains('CenturyCert'));

      final yearsDiff = cert.notAfter.year - cert.notBefore.year;
      expect(yearsDiff, greaterThanOrEqualTo(99),
          reason:
              '100-year cert should have ~100 years of validity, '
              'got $yearsDiff years');
    });

    test('D6: Certificate without basicConstraints parses correctly', () {
      const dn = DistinguishedName(commonName: 'NoBC');
      final spec = RsaKeySpec(2048);

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final cert = _createCertWithBuilder(bindings, keyPair, dn, (builder) {
        return builder
            .validityPeriod(const Duration(days: 365))
            .addKeyUsage();
      });

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.parsed.subject, contains('NoBC'));
    });

    test('D7: Certificate with critical unknown extension is rejected', () {
      const dn = DistinguishedName(commonName: 'UnknownExt');
      final spec = RsaKeySpec(2048);

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final der = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(keyPair)
          .validityPeriod(const Duration(days: 365))
          .addKeyUsage()
          .addBasicConstraints(ca: false)
          .addExtension('1.2.3.4.5.6.7.8.9.10', 'test_value',
              critical: true)
          .signWith(keyPair)
          .build();

      expect(der, isA<CryptoFailure<Uint8List>>(),
          reason:
              'Certificate with unknown critical extension must be '
              'rejected by OpenSSL');
      final failure = der as CryptoFailure<Uint8List>;
      expect(failure.error, isA<CertificateError>());
    });
  });


  group('E: Signature Nondeterminism', () {
    test('E1: RSA PKCS#1 v1.5 signatures are deterministic (standards-compliant)', () {
      final rsaSpec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(rsaSpec);
      final keyResult = creator.create(rsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);
      final signatures = <Uint8List>[];

      for (var i = 0; i < 5; i++) {
        final sig = api.sign(data, _pem(keyPair.privateKeyPem),
            hashAlgorithm: 'sha256');
        expect(sig, isNotEmpty);
        signatures.add(sig);
      }

      for (var i = 0; i < signatures.length; i++) {
        final verified = api.verify(
            data, _pem(keyPair.publicKeyPem), signatures[i],
            hashAlgorithm: 'sha256');
        expect(verified, isTrue,
            reason: 'Signature $i must verify with correct key');
      }

      final uniqueBase64 =
          signatures.map((s) => base64.encode(s)).toSet();
      expect(uniqueBase64.length, equals(1),
          reason:
              'RSA PKCS#1 v1.5 produces deterministic signatures '
              '(standards-compliant). Only 1 unique signature expected '
              'from 5 calls with same data and key.');
    });

    test('E2: ECDSA signs same data 5 times producing unique signatures',
        () {
      final ecSpec = EcKeySpec('prime256v1');
      final creator = factory.createOrThrow(ecSpec);
      final keyResult = creator.create(ecSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);
      final signatures = <Uint8List>[];

      for (var i = 0; i < 5; i++) {
        final sig = api.sign(data, _pem(keyPair.privateKeyPem),
            hashAlgorithm: 'sha256');
        expect(sig, isNotEmpty);
        signatures.add(sig);
      }

      for (var i = 0; i < signatures.length; i++) {
        final verified = api.verify(
            data, _pem(keyPair.publicKeyPem), signatures[i],
            hashAlgorithm: 'sha256');
        expect(verified, isTrue,
            reason: 'Signature $i must verify with correct key');
      }

      final uniqueBase64 =
          signatures.map((s) => base64.encode(s)).toSet();
      expect(uniqueBase64.length, equals(5),
          reason:
              'All 5 ECDSA signatures must be unique '
              '(non-deterministic nonce)');
    });

    test('E3: ML-DSA-44 sign/verify round-trip with nullptr digest', () {
      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final creator = factory.createOrThrow(mlDsaSpec);
      final keyResult = creator.create(mlDsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);

      final sig = api.sign(data, _pem(keyPair.privateKeyPem),
          hashAlgorithm: 'sha256');
      expect(sig, isNotEmpty,
          reason: 'ML-DSA-44 must produce a non-empty signature');
      expect(sig.length, greaterThan(100),
          reason: 'ML-DSA-44 signature must be > 100 bytes');

      final verified = api.verify(
          data, _pem(keyPair.publicKeyPem), sig,
          hashAlgorithm: 'sha256');
      expect(verified, isTrue,
          reason: 'ML-DSA-44 signature must verify with correct key');
    });

    test('E3b: ML-DSA-44 tampered signature fails verification', () {
      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final creator = factory.createOrThrow(mlDsaSpec);
      final keyResult = creator.create(mlDsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);
      final sig = api.sign(data, _pem(keyPair.privateKeyPem),
          hashAlgorithm: 'sha256');

      final tampered = Uint8List.fromList(sig);
      tampered[tampered.length ~/ 2] ^= 0xFF;

      final verified = api.verify(
          data, _pem(keyPair.publicKeyPem), tampered,
          hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason: 'Tampered ML-DSA-44 signature must not verify');
    });

    test('E3c: ML-DSA-65 sign/verify round-trip', () {
      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa65);
      final creator = factory.createOrThrow(mlDsaSpec);
      final keyResult = creator.create(mlDsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);
      final sig = api.sign(data, _pem(keyPair.privateKeyPem),
          hashAlgorithm: 'sha256');
      expect(sig, isNotEmpty);
      expect(sig.length, greaterThan(100));

      final verified = api.verify(
          data, _pem(keyPair.publicKeyPem), sig,
          hashAlgorithm: 'sha256');
      expect(verified, isTrue,
          reason: 'ML-DSA-65 signature must verify with correct key');
    });

    test('E3d: ML-DSA-87 sign/verify round-trip', () {
      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa87);
      final creator = factory.createOrThrow(mlDsaSpec);
      final keyResult = creator.create(mlDsaSpec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(256);
      final sig = api.sign(data, _pem(keyPair.privateKeyPem),
          hashAlgorithm: 'sha256');
      expect(sig, isNotEmpty);
      expect(sig.length, greaterThan(100));

      final verified = api.verify(
          data, _pem(keyPair.publicKeyPem), sig,
          hashAlgorithm: 'sha256');
      expect(verified, isTrue,
          reason: 'ML-DSA-87 signature must verify with correct key');
    });

    test('E3e: ML-DSA key used with RSA signature fails verify', () {
      final mlDsaSpec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final creator = factory.createOrThrow(mlDsaSpec);
      final keyResult = creator.create(mlDsaSpec);
      final mlDsaKey = (keyResult as CryptoSuccess<KeyPair>).value;

      final rsaKey = api.generateRsaKeyPair(2048);

      final data = _randomBytes(256);
      final sig = api.sign(data, _pem(mlDsaKey.privateKeyPem),
          hashAlgorithm: 'sha256');

      final verified = api.verify(
          data, _pem(rsaKey.publicKeyPem), sig,
          hashAlgorithm: 'sha256');
      expect(verified, isFalse,
          reason: 'ML-DSA signature must not verify with RSA key');
    });
  });


  group('F: Platform Coverage', () {
    test('F1: All key types generate successfully on current platform', () {
      final keySpecs = <KeySpec>[
        RsaKeySpec(2048),
        EcKeySpec('prime256v1'),
        const MlKemKeySpec(MlKemParameterSet.mlKem768),
        const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
      ];

      for (final spec in keySpecs) {
        final creator = factory.createOrThrow(spec);
        final result = creator.create(spec);

        expect(result, isA<CryptoSuccess<KeyPair>>(),
            reason:
                '${spec.runtimeType} key generation must succeed on '
                'this platform');
        final keyPair = (result as CryptoSuccess<KeyPair>).value;
        expect(keyPair.publicKeyPem, isNotEmpty,
            reason:
                '${spec.runtimeType} public key PEM must not be empty');
        expect(keyPair.privateKeyPem, isNotEmpty,
            reason:
                '${spec.runtimeType} private key PEM must not be empty');
        expect(keyPair.publicKeyPem, contains('BEGIN'),
            reason:
                '${spec.runtimeType} public key must have PEM header');
        expect(keyPair.privateKeyPem, contains('BEGIN'),
            reason:
                '${spec.runtimeType} private key must have PEM header');
      }
    }, tags: ['android']);

    test("F2: SHA-256('test') produces known NIST test vector", () {
      const expectedHex =
          '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

      final data = Uint8List.fromList(utf8.encode('test'));
      final hash = api.sha256(data);

      expect(hash, isNotEmpty);
      expect(hash.length, equals(32),
          reason: 'SHA-256 output must be 32 bytes');

      final hashHex = hash
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      expect(hashHex, equals(expectedHex),
          reason:
              "SHA-256('test') must match the known NIST test vector");
    }, tags: ['android']);

    test('F3: loadCrypto() and loadSsl() succeed', () {
      DynamicLibrary? cryptoLib;
      DynamicLibrary? sslLib;

      try {
        cryptoLib = loadCrypto();
        expect(cryptoLib, isNotNull,
            reason: 'loadCrypto() must return a valid DynamicLibrary');

        sslLib = loadSsl();
        expect(sslLib, isNotNull,
            reason: 'loadSsl() must return a valid DynamicLibrary');
      } catch (e) {
        fail('Native library loading failed: $e');
      }
    }, tags: ['android']);
  });


  group('G: ML-KEM KEM Properties', () {
    test('G1: ML-KEM-768 encapsulate/decapsulate round-trip', () {
      final spec = const MlKemKeySpec(MlKemParameterSet.mlKem768);
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      expect(keyPair.publicKeyPem, isNotEmpty);
      expect(keyPair.privateKeyPem, isNotEmpty);

      final result = api.mlKemEncapsulate(_pem(keyPair.publicKeyPem));
      expect(result.ciphertext, isNotEmpty,
          reason:
              'ML-KEM encapsulation must produce non-empty ciphertext');
      expect(result.sharedSecret, isNotEmpty,
          reason:
              'ML-KEM encapsulation must produce non-empty shared '
              'secret');

      final recoveredSecret = api.mlKemDecapsulate(
          _pem(keyPair.privateKeyPem), result.ciphertext);
      expect(recoveredSecret, isNotEmpty,
          reason:
              'ML-KEM decapsulation must produce non-empty shared '
              'secret');

      expect(recoveredSecret, equals(result.sharedSecret),
          reason:
              'ML-KEM decapsulation must recover the same shared '
              'secret');

      expect(result.sharedSecret.length, equals(32),
          reason:
              'ML-KEM-768 (NIST level 3) produces 32-byte shared '
              'secrets');
    });

    test('G2: ML-KEM-768 encapsulation produces unique ciphertexts', () {
      final spec = const MlKemKeySpec(MlKemParameterSet.mlKem768);
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final r1 = api.mlKemEncapsulate(_pem(keyPair.publicKeyPem));
      final r2 = api.mlKemEncapsulate(_pem(keyPair.publicKeyPem));

      expect(r1.ciphertext, isNotEmpty);
      expect(r2.ciphertext, isNotEmpty);

      expect(r1.ciphertext, isNot(equals(r2.ciphertext)),
          reason:
              'Two ML-KEM encapsulations on the same key must produce '
              'different ciphertexts');

      expect(r1.sharedSecret, isNot(equals(r2.sharedSecret)),
          reason:
              'Different encapsulations must produce different shared '
              'secrets');

      final ss1 = api.mlKemDecapsulate(
          _pem(keyPair.privateKeyPem), r1.ciphertext);
      final ss2 = api.mlKemDecapsulate(
          _pem(keyPair.privateKeyPem), r2.ciphertext);

      expect(ss1, equals(r1.sharedSecret),
          reason: 'First decapsulation must match first shared secret');
      expect(ss2, equals(r2.sharedSecret),
          reason:
              'Second decapsulation must match second shared secret');
    });

    test('G3: ML-KEM key used for signing fails gracefully', () {
      final spec = const MlKemKeySpec(MlKemParameterSet.mlKem768);
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final data = _randomBytes(64);

      expect(
        () => api.sign(data, _pem(keyPair.privateKeyPem),
            hashAlgorithm: 'sha256'),
        throwsA(isA<StateError>()),
        reason:
            'ML-KEM key must not be usable for signing — should throw '
            'StateError',
      );
    });

    test('G4: ML-KEM-512/768/1024 all produce valid key pairs', () {
      final specs = <MlKemKeySpec>[
        const MlKemKeySpec(MlKemParameterSet.mlKem512),
        const MlKemKeySpec(MlKemParameterSet.mlKem768),
        const MlKemKeySpec(MlKemParameterSet.mlKem1024),
      ];

      for (final spec in specs) {
        final creator = factory.createOrThrow(spec);
        final result = creator.create(spec);

        expect(result, isA<CryptoSuccess<KeyPair>>(),
            reason:
                'ML-KEM-${spec.parameterSet.name} key generation '
                'must succeed');
        final keyPair = (result as CryptoSuccess<KeyPair>).value;

        expect(keyPair.publicKeyPem, isNotEmpty,
            reason:
                'ML-KEM-${spec.parameterSet.name} public key PEM '
                'must not be empty');
        expect(keyPair.privateKeyPem, isNotEmpty,
            reason:
                'ML-KEM-${spec.parameterSet.name} private key PEM '
                'must not be empty');
        expect(keyPair.publicKeyPem, contains('BEGIN'),
            reason:
                'ML-KEM-${spec.parameterSet.name} public key must '
                'have PEM header');
        expect(keyPair.privateKeyPem, contains('BEGIN'),
            reason:
                'ML-KEM-${spec.parameterSet.name} private key must '
                'have PEM header');

        final pubLength = keyPair.publicKeyPem.length;
        final privLength = keyPair.privateKeyPem.length;
        expect(pubLength, greaterThan(100),
            reason:
                'ML-KEM-${spec.parameterSet.name} public key PEM '
                'should be > 100 chars, got $pubLength');
        expect(privLength, greaterThan(100),
            reason:
                'ML-KEM-${spec.parameterSet.name} private key PEM '
                'should be > 100 chars, got $privLength');
      }
    });
  });


  group('H: Stress Tests', () {
    test('H1: Sign 10MB file via streaming and verify succeeds', () {
      const dn = DistinguishedName(
        commonName: 'Stress10MB',
        organization: 'TCC',
      );
      final spec = RsaKeySpec(2048);
      final cert = _createCert(factory, bindings, spec, dn);

      final tenMb = 10 * 1024 * 1024;
      final fileContent = _randomBytes(tenMb);
      final filePath = _createTempFileBytes(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: cert.keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>(),
          reason: 'Streaming sign of 10MB file must succeed');
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty,
          reason: '10MB file signature must not be empty');

      final verified = api.verify(
        fileContent,
        _pem(cert.keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha256',
      );
      expect(verified, isTrue,
          reason:
              '10MB file signature must verify with correct key');
    }, tags: ['slow']);

    test('H3: 100 rapid key generations — no crash, no memory leak', () {
      const iterationsPerType = 20;

      final specs = <KeySpec>[
        RsaKeySpec(2048),
        EcKeySpec('prime256v1'),
        const MlKemKeySpec(MlKemParameterSet.mlKem512),
        const MlKemKeySpec(MlKemParameterSet.mlKem768),
        const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
      ];

      var totalKeys = 0;

      for (final spec in specs) {
        final creator = factory.createOrThrow(spec);
        for (var i = 0; i < iterationsPerType; i++) {
          final result = creator.create(spec);
          expect(result, isA<CryptoSuccess<KeyPair>>(),
              reason:
                  'Key gen #${i + 1} for '
                  '${spec.runtimeType} must succeed');
          final keyPair =
              (result as CryptoSuccess<KeyPair>).value;
          expect(keyPair.publicKeyPem, isNotEmpty);
          expect(keyPair.privateKeyPem, isNotEmpty);
          totalKeys++;
        }
      }

      expect(totalKeys, equals(100),
          reason: 'Must have generated exactly 100 keys (5×20)');
    }, tags: ['slow']);
  });
}
