library;

import 'package:plugin_crypto/plugin_crypto.dart';


const testSubjectDn = DistinguishedName(
  commonName: 'Test CN',
  organization: 'TCC',
);

const testDnWithCountry = DistinguishedName(commonName: 'Test', country: 'US');

const testDnFull = DistinguishedName(
  commonName: 'PluginCryptoTest',
  organization: 'TCC',
  organizationalUnit: 'QA',
  locality: 'TestCity',
  state: 'TestState',
  country: 'BR',
);


const defaultSigningAlgorithm = SigningAlgorithm(
  hash: HashAlgorithm.sha256,
  keyType: SigningKeyType.rsa,
);


/// Creates a valid [CertificateRequest] using a generated key pair.
CertificateRequest createValidCertificateRequest() {
  final api = PluginCryptoAPI.instance;
  final keyPair = api.generateRsaKeyPair(2048);
  final now = DateTime.now();

  return CertificateRequest(
    subject: testSubjectDn,
    issuer: testSubjectDn,
    subjectPublicKey: keyPair,
    issuerPrivateKey: keyPair,
    notBefore: now,
    notAfter: now.add(const Duration(days: 365)),
    signingAlgorithm: defaultSigningAlgorithm,
  );
}

/// Creates a valid [CertificateRequest] with an EC key pair.
CertificateRequest createEcCertificateRequest() {
  final api = PluginCryptoAPI.instance;
  final keyPair = api.generateEcKeyPair('prime256v1');
  final now = DateTime.now();

  return CertificateRequest(
    subject: testSubjectDn,
    issuer: testSubjectDn,
    subjectPublicKey: keyPair,
    issuerPrivateKey: keyPair,
    notBefore: now,
    notAfter: now.add(const Duration(days: 365)),
    signingAlgorithm: const SigningAlgorithm(
      hash: HashAlgorithm.sha256,
      keyType: SigningKeyType.ec,
    ),
  );
}
