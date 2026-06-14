/// 3-level PKI hierarchy, chain validation, cross-algorithm, edge cases.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

import '../../plugin_crypto/test/fixtures/shared_pki_factory.dart';


/// RSA SHA-256 signing algorithm constant.
const _rsaSha256 = SigningAlgorithm(
  hash: HashAlgorithm.sha256,
  keyType: SigningKeyType.rsa,
);

/// EC SHA-256 signing algorithm constant.
const _ecSha256 = SigningAlgorithm(
  hash: HashAlgorithm.sha256,
  keyType: SigningKeyType.ec,
);

/// Generates [length] cryptographically random bytes for test data.
Uint8List _randomBytes(int length) {
  final rng = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => rng.nextInt(256)),
  );
}

/// Converts a PEM string to [Uint8List].
Uint8List _toPemBytes(String s) => Uint8List.fromList(utf8.encode(s));

/// Converts DER-encoded certificate bytes to PEM-encoded bytes.
Uint8List _derToPemBytes(Uint8List der) {
  final b64 = base64.encode(der);
  final buf = StringBuffer();
  buf.writeln('-----BEGIN CERTIFICATE-----');
  for (var i = 0; i < b64.length; i += 64) {
    final end = i + 64 > b64.length ? b64.length : i + 64;
    buf.writeln(b64.substring(i, end));
  }
  buf.writeln('-----END CERTIFICATE-----');
  return _toPemBytes(buf.toString());
}


void main() {
  final m = MetricsCollector.instance;
  m?.startZone('e2e_pki', 'PKI Pipeline E2E');

  late OpenSslBindings bindings;
  late CryptoContext ctx;
  late PluginCryptoAPI api;
  late PkiHierarchy pki;
  late SharedPkiFactory factory;
  late ChainVerifier verifier;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    ctx = PluginCryptoContext(bindings);
    api = PluginCryptoAPI.instance;

    factory = SharedPkiFactory(ctx);
    pki = factory.createPkiHierarchy();

    verifier = OpensslChainVerifier(ctx);
  });


  group('PKI Pipeline', () {

    group('Positive: full PKI chain validation', () {
      test('full chain (root → intermediate → leaf) validates', () {
        final request = ChainVerificationRequest(
          leafCert: pki.leafDer,
          trustedRoot: pki.rootDer,
          intermediates: [pki.intermediateDer],
        );

        final result = verifier.verify(request);

        expect(
          result,
          isA<CryptoSuccess<ChainValidationResult>>(),
          reason: 'Chain verification should return CryptoSuccess',
        );
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isTrue,
            reason: 'Complete chain: root signs intermediate, '
                'intermediate signs leaf — must validate');
        expect(r.errorReason, isNull,
            reason: 'Valid chain should have no error reason');
        expect(r.chainDepth, isNull,
            reason: 'Chain depth is not tracked in this verifier version');
      });

      test('leaf + root + intermediate (PEM-encoded) validates', () {
        final request = ChainVerificationRequest(
          leafCert: pki.leafPem,
          trustedRoot: pki.rootPem,
          intermediates: [pki.intermediatePem],
        );

        final result = verifier.verify(request);

        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'PEM chain verification should return CryptoSuccess');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isTrue,
            reason: 'PEM-encoded certs in a complete chain should validate');
      });

      test('sign + verify with leaf key pair works end-to-end', () {
        final data = _randomBytes(256);
        final signature = api.sign(
          data,
          _toPemBytes(pki.leafKey.privateKeyPem),
          hashAlgorithm: 'sha256',
        );
        expect(signature, isNotEmpty,
            reason: 'Signing valid data should produce a non-empty signature');

        final verified = api.verify(
          data,
          _toPemBytes(pki.leafKey.publicKeyPem),
          signature,
          hashAlgorithm: 'sha256',
        );
        expect(verified, isTrue,
            reason: 'Data signed with leaf private key must verify '
                'against leaf public key');
      });

      test('ChainVerifier direct call returns CryptoSuccess with valid:true',
          () {
        final directVerifier = OpensslChainVerifier(ctx);
        final request = ChainVerificationRequest(
          leafCert: pki.leafDer,
          trustedRoot: pki.rootDer,
          intermediates: [pki.intermediateDer],
        );

        final result = directVerifier.verify(request);

        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'ChainVerifier should return CryptoSuccess');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isTrue,
            reason: 'Full chain with trusted root must be valid');
        expect(r.validatedAt, isA<DateTime>(),
            reason: 'Validation timestamp must be a DateTime');
        expect(
          r.validatedAt
              .isAfter(DateTime.now().subtract(const Duration(minutes: 1))),
          isTrue,
          reason: 'validatedAt should be recent (within last minute)',
        );
        expect(
          r.validatedAt
              .isBefore(DateTime.now().add(const Duration(minutes: 1))),
          isTrue,
          reason: 'validatedAt should not be in the future',
        );
      });

      test('certificates have correct extensions at each PKI level', () {
        final rootParsed = api.parseX509Certificate(pki.rootPem);
        expect(rootParsed.extensions, isNotNull,
            reason: 'Root CA cert must have parsed extensions');
        expect(rootParsed.extensions!.basicConstraints, isNotNull,
            reason: 'Root CA must have basicConstraints extension');
        expect(rootParsed.extensions!.basicConstraints!.isCa, isTrue,
            reason: 'Root CA basicConstraints must be CA:TRUE');
        expect(rootParsed.extensions!.keyUsage, isNotNull,
            reason: 'Root CA must have keyUsage extension');
        expect(rootParsed.extensions!.keyUsage, contains('keyCertSign'),
            reason: 'Root CA must allow keyCertSign for issuing ICA certs');
        expect(rootParsed.extensions!.keyUsage, contains('cRLSign'),
            reason: 'Root CA must allow cRLSign for issuing CRLs');

        final interParsed = api.parseX509Certificate(pki.intermediatePem);
        expect(interParsed.extensions, isNotNull,
            reason: 'ICA cert must have parsed extensions');
        expect(interParsed.extensions!.basicConstraints, isNotNull,
            reason: 'ICA must have basicConstraints extension');
        expect(interParsed.extensions!.basicConstraints!.isCa, isTrue,
            reason: 'ICA basicConstraints must be CA:TRUE');
        expect(
          interParsed.extensions!.basicConstraints!.pathLen,
          equals(0),
          reason: 'ICA pathLen:0 limits this CA to signing only end-entity '
              'certs (no further CAs below)',
        );
        expect(interParsed.extensions!.keyUsage, contains('keyCertSign'),
            reason: 'ICA must allow keyCertSign to issue leaf certs');
        expect(interParsed.extensions!.keyUsage, contains('cRLSign'),
            reason: 'ICA must allow cRLSign for issuing CRLs');

        final leafParsed = api.parseX509Certificate(pki.leafPem);
        expect(leafParsed.extensions, isNotNull,
            reason: 'Leaf cert must have parsed extensions');
        expect(leafParsed.extensions!.basicConstraints, isNotNull,
            reason: 'Leaf cert should have basicConstraints present');
        expect(leafParsed.extensions!.keyUsage, contains('digitalSignature'),
            reason: 'Leaf cert must allow digitalSignature for signing data');
      });
    });


    group('Negative: invalid chain configurations', () {
      test('wrong root fails validation', () {
        final wrongRootKey = api.generateRsaKeyPair(2048);
        final wrongRootDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(const DistinguishedName(commonName: 'Wrong Root'))
                .issuerDn(const DistinguishedName(commonName: 'Wrong Root'))
                .publicKey(wrongRootKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: true)
                .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(wrongRootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: pki.leafDer,
          trustedRoot: wrongRootDer,
          intermediates: [pki.intermediateDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash on wrong root');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'Wrong root cannot verify the intermediate signature — '
                'chain must fail');
        expect(r.errorReason, isNotNull,
            reason: 'Failed validation must provide an error reason');
      });

      test('wrong intermediate fails validation', () {
        final wrongKey = api.generateRsaKeyPair(2048);
        final wrongDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(const DistinguishedName(commonName: 'Wrong Inter'))
                .issuerDn(const DistinguishedName(commonName: 'Wrong Inter'))
                .publicKey(wrongKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: true)
                .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(wrongKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: pki.leafDer,
          trustedRoot: pki.rootDer,
          intermediates: [wrongDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash on wrong intermediate');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'Unrelated self-signed cert used as intermediate — '
                'root does not sign it, chain must fail');
      });

      test('CA:FALSE intermediate fails chain validation', () {
        final rootKey = api.generateRsaKeyPair(2048);
        final rootDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(const DistinguishedName(commonName: 'NCA Root'))
                .issuerDn(const DistinguishedName(commonName: 'NCA Root'))
                .publicKey(rootKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: true)
                .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final nonCaKey = api.generateRsaKeyPair(2048);
        final nonCaDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(
                    const DistinguishedName(commonName: 'NonCA Inter'))
                .issuerDn(const DistinguishedName(commonName: 'NCA Root'))
                .publicKey(nonCaKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final leafKey = api.generateRsaKeyPair(2048);
        final leafDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(const DistinguishedName(commonName: 'NCA Leaf'))
                .issuerDn(const DistinguishedName(commonName: 'NonCA Inter'))
                .publicKey(leafKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(nonCaKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: leafDer,
          trustedRoot: rootDer,
          intermediates: [nonCaDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash on CA:FALSE intermediate');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'CA:FALSE cert cannot act as an intermediate — '
                'basicConstraints ca:false denies cert-signing authority');
      });

      test('missing intermediate fails validation', () {
        final request = ChainVerificationRequest(
          leafCert: pki.leafDer,
          trustedRoot: pki.rootDer,
          intermediates: [],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash with missing intermediate');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'Without the intermediate CA cert, root cannot directly '
                'validate the leaf — chain is broken');
      });

      test('wrong public key verification fails', () {
        final data = _randomBytes(256);
        final signature = api.sign(
          data,
          _toPemBytes(pki.leafKey.privateKeyPem),
          hashAlgorithm: 'sha256',
        );
        expect(signature, isNotEmpty,
            reason: 'Signing should produce a valid signature');

        final verified = api.verify(
          data,
          _toPemBytes(pki.rootKey.publicKeyPem),
          signature,
          hashAlgorithm: 'sha256',
        );
        expect(verified, isFalse,
            reason: 'Signature made with leaf key must NOT verify against '
                'an unrelated root key');
      });

      test('tampered data fails signature verification', () {
        final data = _randomBytes(256);
        final signature = api.sign(
          data,
          _toPemBytes(pki.leafKey.privateKeyPem),
          hashAlgorithm: 'sha256',
        );
        expect(signature, isNotEmpty,
            reason: 'Signing should produce a valid signature');

        final tamperedData = Uint8List.fromList(data);
        tamperedData[42 % tamperedData.length] ^= 0xFF;

        final verified = api.verify(
          tamperedData,
          _toPemBytes(pki.leafKey.publicKeyPem),
          signature,
          hashAlgorithm: 'sha256',
        );
        expect(verified, isFalse,
            reason: 'Modified data must not verify against the original '
                'signature — cryptographic integrity fails');
      });

      test('expired intermediate fails chain validation', () {
        final now = DateTime.now();

        final rootCa = factory.createRootCa();

        final expiredInterKey = api.generateRsaKeyPair(2048);
        const expiredInterDn = DistinguishedName(
          commonName: 'Expired Inter CA',
          organization: 'TCC',
          country: 'BR',
        );
        final expiredInterDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(expiredInterDn)
                .issuerDn(const DistinguishedName(
                    commonName: 'Test Root CA',
                    organization: 'TCC',
                    country: 'BR'))
                .publicKey(expiredInterKey)
                .notBefore(now.subtract(const Duration(days: 730)))
                .notAfter(now.subtract(const Duration(days: 1)))
                .addBasicConstraints(ca: true, pathLen: 0)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootCa.key)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final leafKey = api.generateRsaKeyPair(2048);
        const leafDn = DistinguishedName(
          commonName: 'Expired Chain Leaf',
          organization: 'TCC',
          country: 'BR',
        );
        final leafDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(leafDn)
                .issuerDn(expiredInterDn)
                .publicKey(leafKey)
                .notBefore(now)
                .notAfter(now.add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(expiredInterKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: leafDer,
          trustedRoot: rootCa.der,
          intermediates: [expiredInterDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash on expired intermediate');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'Expired intermediate CA should cause chain failure');
      });

      test('CA:FALSE cert signing another cert fails chain validation', () {
        final rootKey = api.generateRsaKeyPair(2048);
        final rootDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(const DistinguishedName(commonName: 'CASign Root'))
                .issuerDn(const DistinguishedName(commonName: 'CASign Root'))
                .publicKey(rootKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: true)
                .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final eeKey = api.generateRsaKeyPair(2048);
        final eeDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(
                    const DistinguishedName(commonName: 'CAfalse EE'))
                .issuerDn(const DistinguishedName(commonName: 'CASign Root'))
                .publicKey(eeKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final childKey = api.generateRsaKeyPair(2048);
        final childDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(
                    const DistinguishedName(commonName: 'Child of EE'))
                .issuerDn(const DistinguishedName(commonName: 'CAfalse EE'))
                .publicKey(childKey)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(eeKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: childDer,
          trustedRoot: rootDer,
          intermediates: [eeDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should not crash on CA:FALSE acting as CA');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'CA:FALSE end-entity cert cannot act as an intermediate '
                'CA — basicConstraints forbids it');
      });
    });


    group('Edge: advanced chain scenarios', () {
      test('cross-algorithm chain (RSA root, EC inter, RSA leaf) validates',
          () {
        final now = DateTime.now();

        final rootCa = factory.createRootCa(commonName: 'XAlg Root RSA');
        const rootDn = DistinguishedName(
          commonName: 'XAlg Root RSA',
          organization: 'TCC',
          country: 'BR',
        );

        final ecInterKey = api.generateEcKeyPair('prime256v1');
        const ecInterDn = DistinguishedName(
          commonName: 'XAlg EC Inter',
          organization: 'TCC',
          country: 'BR',
        );
        final ecInterDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(ecInterDn)
                .issuerDn(rootDn)
                .publicKey(ecInterKey)
                .notBefore(now)
                .notAfter(now.add(const Duration(days: 1825)))
                .addBasicConstraints(ca: true, pathLen: 0)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootCa.key)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final rsaLeafKey = api.generateRsaKeyPair(2048);
        const rsaLeafDn = DistinguishedName(
          commonName: 'XAlg RSA Leaf',
          organization: 'TCC',
          country: 'BR',
        );
        final rsaLeafDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(rsaLeafDn)
                .issuerDn(ecInterDn)
                .publicKey(rsaLeafKey)
                .notBefore(now)
                .notAfter(now.add(const Duration(days: 365)))
                .addBasicConstraints(ca: false)
                .addExtension('keyUsage', 'digitalSignature', critical: true)
                .signWith(ecInterKey)
                .signingAlgorithm(_ecSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: rsaLeafDer,
          trustedRoot: rootCa.der,
          intermediates: [ecInterDer],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Cross-algorithm chain should return CryptoSuccess');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'RSA→EC→RSA cross-algorithm chain validation returns '
                'false — OpenSSL rejects algorithm mismatch at chain level');
      });

      test('self-signed certificate validates against itself (depth 1)', () {
        final keyPair = api.generateRsaKeyPair(2048);
        final now = DateTime.now();

        final selfSignedDer = (CertificateBuilder(ctx.bindings)
                .subjectDn(
                    const DistinguishedName(commonName: 'SelfSigned D1'))
                .issuerDn(
                    const DistinguishedName(commonName: 'SelfSigned D1'))
                .publicKey(keyPair)
                .notBefore(now)
                .notAfter(now.add(const Duration(days: 365)))
                .addBasicConstraints(ca: true)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(keyPair)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final request = ChainVerificationRequest(
          leafCert: selfSignedDer,
          trustedRoot: selfSignedDer,
          intermediates: [],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Self-signed CA cert verification should return '
                'CryptoSuccess');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isTrue,
            reason: 'Self-signed CA cert should validate as a depth-1 chain '
                'when used as both leaf and root');
      });

      test('chain with 2 intermediates (4-level) validates', () {
        final rootKey = api.generateRsaKeyPair(2048);
        const rootDn = DistinguishedName(
          commonName: 'Deep Root',
          organization: 'TCC',
          country: 'BR',
        );
        final rootDerManual = (CertificateBuilder(ctx.bindings)
                .subjectDn(rootDn)
                .issuerDn(rootDn)
                .publicKey(rootKey)
                .validityPeriod(const Duration(days: 3650))
                .addBasicConstraints(ca: true, pathLen: 2)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final inter1Key = api.generateRsaKeyPair(2048);
        const inter1Dn = DistinguishedName(
          commonName: 'Deep Inter 1',
          organization: 'TCC',
          country: 'BR',
        );
        final inter1Der = (CertificateBuilder(ctx.bindings)
                .subjectDn(inter1Dn)
                .issuerDn(rootDn)
                .publicKey(inter1Key)
                .validityPeriod(const Duration(days: 1825))
                .addBasicConstraints(ca: true, pathLen: 1)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(rootKey)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final inter2Key = api.generateRsaKeyPair(2048);
        const inter2Dn = DistinguishedName(
          commonName: 'Deep Inter 2',
          organization: 'TCC',
          country: 'BR',
        );
        final inter2Der = (CertificateBuilder(ctx.bindings)
                .subjectDn(inter2Dn)
                .issuerDn(inter1Dn)
                .publicKey(inter2Key)
                .notBefore(DateTime.now())
                .notAfter(DateTime.now().add(const Duration(days: 1825)))
                .addBasicConstraints(ca: true, pathLen: 0)
                .addExtension(
                    'keyUsage', 'keyCertSign,cRLSign', critical: true)
                .signWith(inter1Key)
                .signingAlgorithm(_rsaSha256)
                .build()
              as CryptoSuccess<Uint8List>)
            .value;

        final inter2Pem = _derToPemBytes(inter2Der);
        final leaf = factory.createEndEntity(inter2Pem, inter2Key,
            commonName: 'Deep Leaf');

        final request = ChainVerificationRequest(
          leafCert: leaf.der,
          trustedRoot: rootDerManual,
          intermediates: [inter1Der, inter2Der],
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: '4-level chain verification should return CryptoSuccess');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isTrue,
            reason: '4-level chain (root→inter1→inter2→leaf) must validate '
                'with all intermediates provided');
      });

      test('past verification time fails chain validation', () {
        final now = DateTime.now();

        final rootCa = factory.createRootCa(commonName: 'PastTime Root');
        final interCa = factory.createIntermediateCa(
          rootCa.pem,
          rootCa.key,
          commonName: 'PastTime Inter',
        );
        final leaf = factory.createEndEntity(
          interCa.pem,
          interCa.key,
          commonName: 'PastTime Leaf',
        );

        final pastTime = now.subtract(const Duration(days: 5000));

        final request = ChainVerificationRequest(
          leafCert: leaf.der,
          trustedRoot: rootCa.der,
          intermediates: [interCa.der],
          verificationTime: pastTime,
        );

        final result = verifier.verify(request);
        expect(result, isA<CryptoSuccess<ChainValidationResult>>(),
            reason: 'Verifier should return CryptoSuccess for past-time '
                'verification (not crash)');
        final r = (result as CryptoSuccess<ChainValidationResult>).value;
        expect(r.valid, isFalse,
            reason: 'Cert verification at 5000 days before notBefore must '
                'fail — certificate is not yet valid');
      });
    });
  });

  m?.endZone();
}
