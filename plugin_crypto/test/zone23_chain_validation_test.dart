@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_chain/chain_verification_request.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_chain/chain_verifier.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_chain/openssl_chain_verifier.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/key_creator_factory.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/crypto/models/signing_algorithm.dart';
import 'package:plugin_crypto/src/crypto/plugin_crypto_context.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone23', 'Certificate Chain Validation');

  late OpenSslBindings bindings;
  late KeyCreatorFactory keyFactory;
  late OpensslChainVerifier verifier;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    keyFactory = KeyCreatorFactory(bindings);
    verifier = OpensslChainVerifier(PluginCryptoContext(bindings));
  });


  const rootDn = DistinguishedName(commonName: 'Root CA', organization: 'TCC');
  const intermediateDn = DistinguishedName(
    commonName: 'Intermediate CA',
    organization: 'TCC',
  );
  const otherIntermediateDn = DistinguishedName(
    commonName: 'Other Intermediate CA',
    organization: 'TCC',
  );
  const leafDn = DistinguishedName(
    commonName: 'Leaf Cert',
    organization: 'TCC',
  );
  const extraIntermediateDn = DistinguishedName(
    commonName: 'Extra Intermediate CA',
    organization: 'TCC',
  );

  const rsaSha256 = SigningAlgorithm(
    hash: HashAlgorithm.sha256,
    keyType: SigningKeyType.rsa,
  );


  /// Generates an RSA-2048 key pair using [KeyCreatorFactory].
  KeyPair _genKey() {
    final creator = keyFactory.create(RsaKeySpec(2048))!;
    final result = creator.create(RsaKeySpec(2048));
    return (result as CryptoSuccess<KeyPair>).value;
  }


  /// Builds a self-signed Root CA certificate using [CertificateBuilder]
  /// with CA:TRUE basic constraints and keyCertSign usage.
  Uint8List _buildRootCa({
    required DistinguishedName subjectDn,
    required KeyPair subjectKey,
    Duration validity = const Duration(days: 3650),
  }) {
    final builder = CertificateBuilder(bindings)
        .subjectDn(subjectDn)
        .issuerDn(subjectDn)
        .publicKey(subjectKey)
        .validityPeriod(validity)
        .addBasicConstraints(ca: true)
        .addExtension('keyUsage', 'critical,keyCertSign,cRLSign')
        .signWith(subjectKey)
        .signingAlgorithm(rsaSha256);

    final result = builder.build();
    return (result as CryptoSuccess<Uint8List>).value;
  }

  Uint8List _buildIntermediateCa({
    required DistinguishedName subjectDn,
    required DistinguishedName issuerDn,
    required KeyPair subjectKey,
    required KeyPair issuerKey,
    int? pathLen,
    Duration validity = const Duration(days: 1825),
  }) {
    final builder = CertificateBuilder(bindings)
        .subjectDn(subjectDn)
        .issuerDn(issuerDn)
        .publicKey(subjectKey)
        .validityPeriod(validity)
        .addBasicConstraints(ca: true, pathLen: pathLen)
        .addExtension('keyUsage', 'critical,keyCertSign')
        .signWith(issuerKey)
        .signingAlgorithm(rsaSha256);

    final result = builder.build();
    return (result as CryptoSuccess<Uint8List>).value;
  }

  /// Builds a leaf (end-entity) certificate signed by [issuerKey].
  Uint8List _buildLeafCert({
    required DistinguishedName subjectDn,
    required DistinguishedName issuerDn,
    required KeyPair subjectKey,
    required KeyPair issuerKey,
    Duration validity = const Duration(days: 365),
    DateTime? notBefore,
    DateTime? notAfter,
  }) {
    final builder = CertificateBuilder(bindings)
        .subjectDn(subjectDn)
        .issuerDn(issuerDn)
        .publicKey(subjectKey)
        .addKeyUsage(digitalSignature: true)
        .signWith(issuerKey)
        .signingAlgorithm(rsaSha256);

    if (notBefore != null && notAfter != null) {
      builder.notBefore(notBefore).notAfter(notAfter);
    } else {
      builder.validityPeriod(validity);
    }

    final result = builder.build();
    return (result as CryptoSuccess<Uint8List>).value;
  }


  group('Chain verification — positive', () {
    test('self-signed cert validates against itself', () {
      final rootKey = _genKey();
      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);

      final request = ChainVerificationRequest(
        leafCert: rootCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isTrue);
      expect(r.errorReason, isNull);
    });

    test('2-level chain validates (root → leaf)', () {
      final rootKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: rootDn,
        subjectKey: leafKey,
        issuerKey: rootKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isTrue);
    });

    test('3-level chain validates (root → intermediate → leaf)', () {
      final rootKey = _genKey();
      final intermediateKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final intermediateCert = _buildIntermediateCa(
        subjectDn: intermediateDn,
        issuerDn: rootDn,
        subjectKey: intermediateKey,
        issuerKey: rootKey,
      );
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: intermediateDn,
        subjectKey: leafKey,
        issuerKey: intermediateKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
        intermediates: [intermediateCert],
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isTrue);
    });

    test('chain with multiple intermediates validates', () {
      final rootKey = _genKey();
      final int1Key = _genKey();
      final int2Key = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final int1Cert = _buildIntermediateCa(
        subjectDn: intermediateDn,
        issuerDn: rootDn,
        subjectKey: int1Key,
        issuerKey: rootKey,
      );
      final int2Cert = _buildIntermediateCa(
        subjectDn: extraIntermediateDn,
        issuerDn: intermediateDn,
        subjectKey: int2Key,
        issuerKey: int1Key,
        pathLen: 0,
      );
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: extraIntermediateDn,
        subjectKey: leafKey,
        issuerKey: int2Key,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
        intermediates: [int1Cert, int2Cert],
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isTrue);
    });
  });


  group('Chain verification — negative', () {
    test('rejects chain with wrong trusted root', () {
      final trustedRootKey = _genKey();
      final actualRootKey = _genKey();
      final leafKey = _genKey();

      const actualRootDn = DistinguishedName(
        commonName: 'Actual Root CA',
        organization: 'TCC',
      );

      final trustedRootCert = _buildRootCa(
        subjectDn: rootDn,
        subjectKey: trustedRootKey,
      );
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: actualRootDn,
        subjectKey: leafKey,
        issuerKey: actualRootKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: trustedRootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
    });

    test('rejects chain with missing intermediate', () {
      final rootKey = _genKey();
      final intermediateKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      _buildIntermediateCa(
        subjectDn: intermediateDn,
        issuerDn: rootDn,
        subjectKey: intermediateKey,
        issuerKey: rootKey,
      );
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: intermediateDn,
        subjectKey: leafKey,
        issuerKey: intermediateKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
    });

    test('rejects chain with expired cert', () {
      final rootKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final now = DateTime.now();
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: rootDn,
        subjectKey: leafKey,
        issuerKey: rootKey,
        notBefore: now.subtract(const Duration(days: 2)),
        notAfter: now.subtract(const Duration(days: 1)),
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
    });

    test('rejects chain with wrong intermediate', () {
      final rootKey = _genKey();
      final correctIntKey = _genKey();
      final wrongIntKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      _buildIntermediateCa(
        subjectDn: intermediateDn,
        issuerDn: rootDn,
        subjectKey: correctIntKey,
        issuerKey: rootKey,
      );
      final wrongIntCert = _buildIntermediateCa(
        subjectDn: otherIntermediateDn,
        issuerDn: rootDn,
        subjectKey: wrongIntKey,
        issuerKey: rootKey,
      );
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: intermediateDn,
        subjectKey: leafKey,
        issuerKey: correctIntKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
        intermediates: [wrongIntCert],
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
    });

    test('rejects self-signed leaf not in trust store', () {
      final leafKey = _genKey();
      final untrustedKey = _genKey();

      final unrelatedRoot = _buildRootCa(
        subjectDn: rootDn,
        subjectKey: untrustedKey,
      );
      final leafCert = _buildRootCa(subjectDn: leafDn, subjectKey: leafKey);

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: unrelatedRoot,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
    });
  });


  group('ChainVerificationRequest validation', () {
    final dummyCert = Uint8List.fromList([0x30, 0x03, 0x02, 0x01, 0x01]);

    test('rejects empty leafCert', () {
      expect(
        () => ChainVerificationRequest(
          leafCert: Uint8List(0),
          trustedRoot: dummyCert,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects empty intermediate', () {
      expect(
        () => ChainVerificationRequest(
          leafCert: dummyCert,
          trustedRoot: dummyCert,
          intermediates: [Uint8List(0)],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects empty trustedRoot', () {
      expect(
        () => ChainVerificationRequest(
          leafCert: dummyCert,
          trustedRoot: Uint8List(0),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects future verificationTime', () {
      expect(
        () => ChainVerificationRequest(
          leafCert: dummyCert,
          verificationTime: DateTime.now().add(const Duration(hours: 1)),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });


  group('ChainValidationResult shape', () {
    test('valid chain returns valid=true with expected fields', () {
      final rootKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: rootDn,
        subjectKey: leafKey,
        issuerKey: rootKey,
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isTrue);
      expect(r.errorReason, isNull);
      expect(r.chainDepth, isNull);
      expect(r.validatedAt, isA<DateTime>());
    });

    test('invalid chain returns valid=false with errorReason', () {
      final rootKey = _genKey();
      final leafKey = _genKey();

      final rootCert = _buildRootCa(subjectDn: rootDn, subjectKey: rootKey);
      final now = DateTime.now();
      final leafCert = _buildLeafCert(
        subjectDn: leafDn,
        issuerDn: rootDn,
        subjectKey: leafKey,
        issuerKey: rootKey,
        notBefore: now.subtract(const Duration(days: 2)),
        notAfter: now.subtract(const Duration(days: 1)),
      );

      final request = ChainVerificationRequest(
        leafCert: leafCert,
        trustedRoot: rootCert,
      );
      final result = verifier.verify(request);

      expect(result, isA<CryptoSuccess<ChainValidationResult>>());
      final r = (result as CryptoSuccess<ChainValidationResult>).value;
      expect(r.valid, isFalse);
      expect(r.errorReason, isNotNull);
      expect(r.errorReason, isNotEmpty);
      expect(r.validatedAt, isA<DateTime>());
    });
  });

  m?.endZone();
}
