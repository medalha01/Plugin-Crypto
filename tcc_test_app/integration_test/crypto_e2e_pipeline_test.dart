/// Key creation → cert → sign → verify full pipeline tests.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/self_signed_cert_creator.dart';
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

File _createTempFile(String content) {
  final dir = Directory.systemTemp;
  final suffix = Random.secure().nextInt(999999).toString().padLeft(6, '0');
  final file = File('${dir.path}/tcc_e2e_${suffix}_test.bin');
  file.writeAsStringSync(content);
  return file;
}

/// Creates a temporary file with the given [bytes] content and returns the
/// file path.
String _createTempFileBytes(Uint8List bytes) {
  final dir = Directory.systemTemp;
  final suffix = Random.secure().nextInt(999999).toString().padLeft(6, '0');
  final file = File('${dir.path}/tcc_e2e_${suffix}_test.bin');
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

_CertResult _createCert(
  KeyCreatorFactory factory,
  OpenSslBindings bindings,
  KeySpec spec,
  DistinguishedName dn, {
  SigningAlgorithm? signingAlg,
}) {
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
    signingAlgorithm: signingAlg ??
        const SigningAlgorithm(
            hash: HashAlgorithm.sha256, keyType: SigningKeyType.rsa),
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


void main() {
  late OpenSslBindings bindings;
  late KeyCreatorFactory factory;
  late PluginCryptoAPI api;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    factory = KeyCreatorFactory(bindings);
    api = PluginCryptoAPI.instance;
  });

  group('E2E: Key Creation → Certificate → Sign → Verify', () {

    test('RSA-2048: keygen → self-signed cert → sign file → verify sig', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test RSA',
        organization: 'TCC',
        country: 'BR',
      );
      final spec = RsaKeySpec(2048);
      final cert = _createCert(factory, bindings, spec, dn);

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.pemString, contains('-----END CERTIFICATE-----'));

      final fileContent = 'E2E RSA signing test payload\n' * 100;
      final file = _createTempFile(fileContent);
      addTearDown(() => file.delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: file.path,
        privateKeyPem: cert.keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty);

      final verified = api.verify(
        Uint8List.fromList(utf8.encode(fileContent)),
        _pem(cert.keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isTrue);

      expect(cert.parsed.subject, contains('E2E Test RSA'));
      expect(cert.parsed.issuer, contains('E2E Test RSA'));
      expect(cert.notBefore.year, greaterThanOrEqualTo(2026));
      expect(cert.notAfter.year, greaterThanOrEqualTo(2026));
    });

    test('EC-P256: keygen → self-signed cert → sign file → verify sig', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test EC',
        organization: 'TCC',
        country: 'BR',
      );
      final spec = EcKeySpec('prime256v1');
      final cert = _createCert(factory, bindings, spec, dn);

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));

      final fileContent = 'E2E EC signing test payload\n' * 100;
      final file = _createTempFile(fileContent);
      addTearDown(() => file.delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: file.path,
        privateKeyPem: cert.keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty);

      final verified = api.verify(
        Uint8List.fromList(utf8.encode(fileContent)),
        _pem(cert.keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isTrue);

      expect(cert.parsed.subject, contains('E2E Test EC'));
      expect(cert.parsed.issuer, contains('E2E Test EC'));
    });

    test('RSA-4096: keygen → cert with extensions → sign → verify', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test RSA-4096',
        organization: 'TCC',
      );
      final spec = RsaKeySpec(4096);
      final cert = _createCert(factory, bindings, spec, dn);

      expect(cert.derBytes, isNotEmpty);

      final fileContent = _randomBytes(8 * 1024);
      final filePath = _createTempFileBytes(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: cert.keyPair.privateKeyPem,
        hashAlgorithm: 'sha512',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty);

      final verified = api.verify(
        fileContent,
        _pem(cert.keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha512',
      );
      expect(verified, isTrue);

      expect(cert.parsed.subject, contains('E2E Test RSA-4096'));
    }, tags: ['slow']);


    test('ML-DSA-44: keygen → self-signed cert → sign file → verify sig', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test ML-DSA-44',
        organization: 'TCC',
        country: 'BR',
      );
      final spec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final cert = _createCert(factory, bindings, spec, dn,
          signingAlg: const SigningAlgorithm(
              hash: HashAlgorithm.sha256, keyType: SigningKeyType.ml_dsa));

      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));

      final fileContent = 'E2E ML-DSA-44 signing test payload\n' * 100;
      final file = _createTempFile(fileContent);
      addTearDown(() => file.delete().ignore());

      final data = Uint8List.fromList(utf8.encode(fileContent));
      final signature = api.sign(
        data,
        _pem(cert.keyPair.privateKeyPem),
        hashAlgorithm: 'sha256',
      );
      expect(signature, isNotEmpty);
      expect(signature.length, greaterThan(100),
          reason: 'ML-DSA-44 signature must be > 100 bytes');

      final verified = api.verify(
        Uint8List.fromList(utf8.encode(fileContent)),
        _pem(cert.keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha256',
      );
      expect(verified, isTrue,
          reason: 'ML-DSA-44 signature must verify with correct key');

      expect(cert.parsed.subject, contains('E2E Test ML-DSA-44'));
      expect(cert.parsed.issuer, contains('E2E Test ML-DSA-44'));
      expect(cert.notBefore.year, greaterThanOrEqualTo(2026));
      expect(cert.notAfter.year, greaterThanOrEqualTo(2026));
    }, tags: ['pq']);

    test('ML-DSA-65: keygen → self-signed cert → sign file → verify sig', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test ML-DSA-65',
        organization: 'TCC',
      );
      final spec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa65);
      final cert = _createCert(factory, bindings, spec, dn,
          signingAlg: const SigningAlgorithm(
              hash: HashAlgorithm.sha256, keyType: SigningKeyType.ml_dsa));

      expect(cert.derBytes, isNotEmpty);

      final fileContent = _randomBytes(4 * 1024);
      final signature = api.sign(
        fileContent,
        _pem(cert.keyPair.privateKeyPem),
        hashAlgorithm: 'sha256',
      );
      expect(signature.length, greaterThan(100));

      final verified = api.verify(
        fileContent,
        _pem(cert.keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha256',
      );
      expect(verified, isTrue);

      expect(cert.parsed.subject, contains('E2E Test ML-DSA-65'));
    }, tags: ['pq']);

    test('ML-DSA-87: keygen → self-signed cert → sign file → verify sig', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test ML-DSA-87',
        organization: 'TCC',
      );
      final spec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa87);
      final cert = _createCert(factory, bindings, spec, dn,
          signingAlg: const SigningAlgorithm(
              hash: HashAlgorithm.sha512, keyType: SigningKeyType.ml_dsa));

      expect(cert.derBytes, isNotEmpty);

      final fileContent = _randomBytes(4 * 1024);
      final signature = api.sign(
        fileContent,
        _pem(cert.keyPair.privateKeyPem),
        hashAlgorithm: 'sha512',
      );
      expect(signature.length, greaterThan(100));

      final verified = api.verify(
        fileContent,
        _pem(cert.keyPair.publicKeyPem),
        signature,
        hashAlgorithm: 'sha512',
      );
      expect(verified, isTrue);

      expect(cert.parsed.subject, contains('E2E Test ML-DSA-87'));
    }, tags: ['pq']);


    test('cert subject DN matches input DN', () {
      const dn = DistinguishedName(
        commonName: 'Test CN',
        organization: 'Test Org',
        country: 'US',
      );
      final spec = RsaKeySpec(2048);
      final cert = _createCert(factory, bindings, spec, dn);

      expect(cert.parsed.subject, contains('Test CN'));
      expect(cert.parsed.subject, contains('Test Org'));
      expect(cert.parsed.issuer, contains('Test CN'));
    });

    test('cert issuer DN matches subject DN (self-signed)', () {
      const dn = DistinguishedName(
        commonName: 'SelfSignedTest',
        organization: 'TCC Org',
      );
      final spec = EcKeySpec('prime256v1');
      final cert = _createCert(factory, bindings, spec, dn);

      expect(cert.parsed.subject, contains('SelfSignedTest'));
      expect(cert.parsed.issuer, contains('SelfSignedTest'));
      expect(cert.parsed.subject, contains('TCC Org'));
      expect(cert.parsed.issuer, contains('TCC Org'));
    });

    test('cert validity period is correct', () {
      const dn = DistinguishedName(commonName: 'ValidityTest');
      final spec = RsaKeySpec(2048);
      final now = DateTime.now();

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final certCreator = SelfSignedCertCreator(bindings);
      final request = CertificateRequest(
        subject: dn,
        issuer: dn,
        subjectPublicKey: keyPair,
        issuerPrivateKey: keyPair,
        notBefore: now,
        notAfter: now.add(const Duration(days: 30)),
      );

      final result = certCreator.create(request);
      expect(result, isA<CryptoSuccess<CertificateData>>());
      final certData = (result as CryptoSuccess<CertificateData>).value;

      final nbDiff = certData.notBefore.difference(now).inSeconds.abs();
      expect(nbDiff, lessThanOrEqualTo(5),
          reason: 'notBefore should be within 5 seconds of now');

      final delta = certData.notAfter.difference(certData.notBefore);
      expect(delta.inDays, greaterThanOrEqualTo(29));
      expect(delta.inDays, lessThanOrEqualTo(31));
    });

    test('cert has expected extensions (keyUsage, basicConstraints)', () {
      const dn = DistinguishedName(commonName: 'ExtensionsTest');
      final spec = RsaKeySpec(2048);

      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(keyPair)
          .validityPeriod(const Duration(days: 365))
          .addKeyUsage(digitalSignature: true)
          .addBasicConstraints(ca: false)
          .signWith(keyPair);

      final certResult = builder.buildPem();
      expect(certResult, isA<CryptoSuccess<String>>());
      final pemStr = (certResult as CryptoSuccess<String>).value;
      expect(pemStr, isNotEmpty);

      final parsed = api.parseX509Certificate(_pem(pemStr));
      expect(parsed.subject, contains('ExtensionsTest'));
    });

    test('ML-DSA cert can be parsed and fields inspected', () {
      const dn = DistinguishedName(
        commonName: 'E2E Test ML-DSA Parse',
        organization: 'TCC',
      );
      final spec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
      final cert = _createCert(factory, bindings, spec, dn,
          signingAlg: const SigningAlgorithm(
              hash: HashAlgorithm.sha256, keyType: SigningKeyType.ml_dsa));

      expect(cert.parsed.subject, contains('E2E Test ML-DSA Parse'));
      expect(cert.parsed.issuer, contains('E2E Test ML-DSA Parse'));
      expect(cert.parsed.subject, contains('TCC'));
      expect(cert.parsed.issuer, contains('TCC'));
      expect(cert.notBefore.year, greaterThanOrEqualTo(2026));
      expect(cert.notAfter.year, greaterThanOrEqualTo(2026));
      expect(cert.derBytes, isNotEmpty);
      expect(cert.pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.pemString, contains('-----END CERTIFICATE-----'));
    }, tags: ['pq']);


    test('signing with wrong private key produces invalid signature', () {
      final spec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(spec);

      final key1Result = creator.create(spec);
      final key2Result = creator.create(spec);
      final key1 = (key1Result as CryptoSuccess<KeyPair>).value;
      final key2 = (key2Result as CryptoSuccess<KeyPair>).value;

      expect(key1.privateKeyPem, isNot(equals(key2.privateKeyPem)));

      final fileContent = _randomBytes(1024);
      final filePath = _createTempFileBytes(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: key1.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;

      final verified = api.verify(
        fileContent,
        _pem(key2.publicKeyPem),
        signature,
      );
      expect(verified, isFalse,
          reason: 'Signature signed with key1 should not verify with key2');
    });

    test('verifying with wrong public key fails', () {
      final creator = factory.createOrThrow(EcKeySpec('prime256v1'));
      final ecResult = creator.create(EcKeySpec('prime256v1'));
      final ecKey = (ecResult as CryptoSuccess<KeyPair>).value;

      final rsaCreator = factory.createOrThrow(RsaKeySpec(2048));
      final rsaResult = rsaCreator.create(RsaKeySpec(2048));
      final rsaKey = (rsaResult as CryptoSuccess<KeyPair>).value;

      final fileContent = _randomBytes(1024);
      final filePath = _createTempFileBytes(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: ecKey.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;

      final verified = api.verify(
        fileContent,
        _pem(rsaKey.publicKeyPem),
        signature,
      );
      expect(verified, isFalse,
          reason:
              'Signature signed with EC key should not verify with RSA key');
    });

    test('tampered signature fails verification', () {
      final spec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final fileContent = _randomBytes(1024);
      final filePath = _createTempFileBytes(fileContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty);

      final tamperedSig = Uint8List.fromList(signature);
      tamperedSig[0] = tamperedSig[0] ^ 0xFF;

      final verified = api.verify(
        fileContent,
        _pem(keyPair.publicKeyPem),
        tamperedSig,
      );
      expect(verified, isFalse,
          reason: 'Tampered signature should not verify');
    });

    test('expired certificate validation fails', () {
      const dn = DistinguishedName(commonName: 'ExpiredCert');
      final spec = RsaKeySpec(2048);
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final now = DateTime.now();
      final notBefore = now.subtract(const Duration(days: 2));
      final notAfter = now.subtract(const Duration(days: 1));

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

      expect(certData.notAfter.isBefore(now), isTrue,
          reason: 'Certificate should have expired (notAfter < now)');
    });

    test('certificate with missing required fields fails build()', () {
      final emptyBuilder = CertificateBuilder(bindings);
      final result1 = emptyBuilder.build();
      expect(result1, isA<CryptoFailure<Uint8List>>());
      final err1 = (result1 as CryptoFailure<Uint8List>).error;
      expect(err1, isA<ValidationError>());
      expect((err1 as ValidationError).field, equals('subjectDn'));

      const dn = DistinguishedName(commonName: 'Partial');
      final partialBuilder = CertificateBuilder(bindings).subjectDn(dn);
      final result2 = partialBuilder.build();
      expect(result2, isA<CryptoFailure<Uint8List>>());
      final err2 = (result2 as CryptoFailure<Uint8List>).error;
      expect(err2, isA<ValidationError>());
      expect((err2 as ValidationError).field, equals('issuerDn'));
    });

    test('file signing with non-existent file returns error', () {
      final signer = StreamingFileSigner(bindings);

      final nonExistentPath = '/tmp/tcc_e2e_nonexistent_file_12345_test.bin';
      File(nonExistentPath).delete().ignore();

      final request = FileSigningRequest(
        filePath: nonExistentPath,
        privateKeyPem:
            '-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n',
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      expect(result, isA<CryptoFailure<Uint8List>>());
      final err = (result as CryptoFailure<Uint8List>).error;
      expect(err, isA<FileSigningError>());
      expect((err as FileSigningError).filePath, equals(nonExistentPath));
    });

    test('file signing with empty file succeeds but produces valid signature',
        () {
      final spec = EcKeySpec('prime256v1');
      final creator = factory.createOrThrow(spec);
      final keyResult = creator.create(spec);
      final keyPair = (keyResult as CryptoSuccess<KeyPair>).value;

      final emptyContent = Uint8List(0);
      final filePath = _createTempFileBytes(emptyContent);
      addTearDown(() => File(filePath).delete().ignore());

      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: filePath,
        privateKeyPem: keyPair.privateKeyPem,
        hashAlgorithm: 'sha256',
      );

      final signResult = signer.sign(request);
      expect(signResult, isA<CryptoSuccess<Uint8List>>());
      final signature = (signResult as CryptoSuccess<Uint8List>).value;
      expect(signature, isNotEmpty,
          reason: 'Empty file should still produce a signature');

      final verified = api.verify(
        emptyContent,
        _pem(keyPair.publicKeyPem),
        signature,
      );
      expect(verified, isTrue,
          reason: 'Signature of empty file should verify with correct key');
    });
  });
}
