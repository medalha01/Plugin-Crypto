library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/signing_algorithm.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/utils/bio_utils.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';


class PkiHierarchy {
  final Uint8List rootDer;
  final Uint8List intermediateDer;
  final Uint8List leafDer;

  final Uint8List rootPem;
  final Uint8List intermediatePem;
  final Uint8List leafPem;

  /// Alias for [rootPem] (convenience for test readability).
  Uint8List get rootCaPem => rootPem;

  /// Alias for [intermediatePem] (convenience for test readability).
  Uint8List get intermediateCaPem => intermediatePem;

  final KeyPair rootKey;
  final KeyPair intermediateKey;
  final KeyPair leafKey;

  final String rootPrivateKeyPem;
  final String intermediatePrivateKeyPem;
  final String leafPrivateKeyPem;

  const PkiHierarchy({
    required this.rootDer,
    required this.rootPem,
    required this.intermediateDer,
    required this.intermediatePem,
    required this.leafDer,
    required this.leafPem,
    required this.rootKey,
    required this.intermediateKey,
    required this.leafKey,
    required this.rootPrivateKeyPem,
    required this.intermediatePrivateKeyPem,
    required this.leafPrivateKeyPem,
  });
}


class PkiFixtureFactory {
  final OpenSslBindings _b;
  final PluginCryptoAPI _api = PluginCryptoAPI.instance;

  /// Creates a factory with the given FFI bindings.
  PkiFixtureFactory(this._b);


  ({Uint8List der, Uint8List pem, KeyPair key}) createRootCa({
    String commonName = 'Test Root CA',
    String organization = 'TCC',
    String country = 'BR',
  }) {
    final keyPair = _api.generateRsaKeyPair(2048);
    final dn = DistinguishedName(
      commonName: commonName,
      organization: organization,
      country: country,
    );
    final now = DateTime.now();

    final derResult = CertificateBuilder(_b)
        .subjectDn(dn)
        .issuerDn(dn)
        .publicKey(keyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 3650)))
        .addBasicConstraints(ca: true)
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .signWith(keyPair)
        .signingAlgorithm(_rsaSha256)
        .build();

    final der = (derResult as CryptoSuccess<Uint8List>).value;
    final pemStr = _derToPem(_b, der);
    final pem = Uint8List.fromList(utf8.encode(pemStr));

    return (der: der, pem: pem, key: keyPair);
  }

  ({Uint8List der, Uint8List pem, KeyPair key}) createIntermediateCa(
    Uint8List rootCert,
    KeyPair rootKey, {
    String commonName = 'Test Intermediate CA',
    String organization = 'TCC',
    String country = 'BR',
  }) {
    final keyPair = _api.generateRsaKeyPair(2048);
    final parentDn = _extractSubjectDn(_b, rootCert);
    final dn = DistinguishedName(
      commonName: commonName,
      organization: organization,
      country: country,
    );
    final now = DateTime.now();

    final derResult = CertificateBuilder(_b)
        .subjectDn(dn)
        .issuerDn(parentDn)
        .publicKey(keyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 1825)))
        .addBasicConstraints(ca: true, pathLen: 0)
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .signWith(rootKey)
        .signingAlgorithm(_rsaSha256)
        .build();

    final der = (derResult as CryptoSuccess<Uint8List>).value;
    final pemStr = _derToPem(_b, der);
    final pem = Uint8List.fromList(utf8.encode(pemStr));

    return (der: der, pem: pem, key: keyPair);
  }

  ({Uint8List der, Uint8List pem, KeyPair key}) createEndEntity(
    Uint8List issuerCert,
    KeyPair issuerKey, {
    String commonName = 'Test Leaf EE',
    String organization = 'TCC',
    String country = 'BR',
  }) {
    final keyPair = _api.generateRsaKeyPair(2048);
    final parentDn = _extractSubjectDn(_b, issuerCert);
    final dn = DistinguishedName(
      commonName: commonName,
      organization: organization,
      country: country,
    );
    final now = DateTime.now();

    final derResult = CertificateBuilder(_b)
        .subjectDn(dn)
        .issuerDn(parentDn)
        .publicKey(keyPair)
        .notBefore(now)
        .notAfter(now.add(const Duration(days: 365)))
        .addBasicConstraints(ca: false)
        .addExtension('keyUsage', 'digitalSignature', critical: true)
        .signWith(issuerKey)
        .signingAlgorithm(_rsaSha256)
        .build();

    final der = (derResult as CryptoSuccess<Uint8List>).value;
    final pemStr = _derToPem(_b, der);
    final pem = Uint8List.fromList(utf8.encode(pemStr));

    return (der: der, pem: pem, key: keyPair);
  }


  PkiHierarchy createPkiHierarchy() {
    final rootCa = createRootCa();
    final intermediateCa = createIntermediateCa(rootCa.pem, rootCa.key);
    final leaf = createEndEntity(intermediateCa.pem, intermediateCa.key);

    return PkiHierarchy(
      rootDer: rootCa.der,
      rootPem: rootCa.pem,
      intermediateDer: intermediateCa.der,
      intermediatePem: intermediateCa.pem,
      leafDer: leaf.der,
      leafPem: leaf.pem,
      rootKey: rootCa.key,
      intermediateKey: intermediateCa.key,
      leafKey: leaf.key,
      rootPrivateKeyPem: rootCa.key.privateKeyPem,
      intermediatePrivateKeyPem: intermediateCa.key.privateKeyPem,
      leafPrivateKeyPem: leaf.key.privateKeyPem,
    );
  }
}


PkiHierarchy createPkiHierarchy() {
  final b = _createBindings();
  return PkiFixtureFactory(b).createPkiHierarchy();
}

/// Creates a hierarchy where the intermediate CA is expired.
PkiHierarchy createExpiredChain() {
  final b = _createBindings();
  final factory = PkiFixtureFactory(b);
  final api = PluginCryptoAPI.instance;
  final now = DateTime.now();

  final rootCa = factory.createRootCa();

  final intermediateKey = api.generateRsaKeyPair(2048);
  const intermediateDn = DistinguishedName(
    commonName: 'Test Intermediate CA',
    organization: 'TCC',
    country: 'BR',
  );
  final parentDn = _extractSubjectDn(b, rootCa.pem);
  final interResult = CertificateBuilder(b)
      .subjectDn(intermediateDn)
      .issuerDn(parentDn)
      .publicKey(intermediateKey)
      .notBefore(now.subtract(const Duration(days: 730)))
      .notAfter(now.subtract(const Duration(days: 365)))
      .addBasicConstraints(ca: true, pathLen: 0)
      .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
      .signWith(rootCa.key)
      .signingAlgorithm(_rsaSha256)
      .build();
  final interDer = (interResult as CryptoSuccess<Uint8List>).value;
  final interPemStr = _derToPem(b, interDer);
  final interPem = Uint8List.fromList(utf8.encode(interPemStr));

  final leafKey = api.generateRsaKeyPair(2048);
  const leafDn = DistinguishedName(
    commonName: 'Test Leaf EE',
    organization: 'TCC',
    country: 'BR',
  );
  final interIssuerDn = _extractSubjectDn(b, interPem);
  final leafResult = CertificateBuilder(b)
      .subjectDn(leafDn)
      .issuerDn(interIssuerDn)
      .publicKey(leafKey)
      .notBefore(now)
      .notAfter(now.add(const Duration(days: 365)))
      .addBasicConstraints()
      .addExtension('keyUsage', 'digitalSignature', critical: true)
      .signWith(intermediateKey)
      .signingAlgorithm(_rsaSha256)
      .build();
  final leafDer = (leafResult as CryptoSuccess<Uint8List>).value;
  final leafPemStr = _derToPem(b, leafDer);
  final leafPem = Uint8List.fromList(utf8.encode(leafPemStr));

  return PkiHierarchy(
    rootDer: rootCa.der,
    rootPem: rootCa.pem,
    intermediateDer: interDer,
    intermediatePem: interPem,
    leafDer: leafDer,
    leafPem: leafPem,
    rootKey: rootCa.key,
    intermediateKey: intermediateKey,
    leafKey: leafKey,
    rootPrivateKeyPem: rootCa.key.privateKeyPem,
    intermediatePrivateKeyPem: intermediateKey.privateKeyPem,
    leafPrivateKeyPem: leafKey.privateKeyPem,
  );
}

/// Creates a hierarchy with mixed key algorithms (RSA root, EC intermediate,
/// RSA leaf).
PkiHierarchy createCrossAlgorithmHierarchy() {
  final b = _createBindings();
  final factory = PkiFixtureFactory(b);
  final api = PluginCryptoAPI.instance;
  final now = DateTime.now();

  final rootCa = factory.createRootCa();

  final intermediateKey = api.generateEcKeyPair('prime256v1');
  const intermediateDn = DistinguishedName(
    commonName: 'Test Intermediate CA',
    organization: 'TCC',
    country: 'BR',
  );
  final parentDn = _extractSubjectDn(b, rootCa.pem);
  final interResult = CertificateBuilder(b)
      .subjectDn(intermediateDn)
      .issuerDn(parentDn)
      .publicKey(intermediateKey)
      .notBefore(now)
      .notAfter(now.add(const Duration(days: 1825)))
      .addBasicConstraints(ca: true, pathLen: 0)
      .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
      .signWith(rootCa.key)
      .signingAlgorithm(_rsaSha256)
      .build();
  final interDer = (interResult as CryptoSuccess<Uint8List>).value;
  final interPemStr = _derToPem(b, interDer);
  final interPem = Uint8List.fromList(utf8.encode(interPemStr));

  final leafKey = api.generateRsaKeyPair(2048);
  const leafDn = DistinguishedName(
    commonName: 'Test Leaf EE',
    organization: 'TCC',
    country: 'BR',
  );
  final interIssuerDn = _extractSubjectDn(b, interPem);
  final leafResult = CertificateBuilder(b)
      .subjectDn(leafDn)
      .issuerDn(interIssuerDn)
      .publicKey(leafKey)
      .notBefore(now)
      .notAfter(now.add(const Duration(days: 365)))
      .addBasicConstraints()
      .addExtension('keyUsage', 'digitalSignature', critical: true)
      .signWith(intermediateKey)
      .signingAlgorithm(_ecSha256)
      .build();
  final leafDer = (leafResult as CryptoSuccess<Uint8List>).value;
  final leafPemStr = _derToPem(b, leafDer);
  final leafPem = Uint8List.fromList(utf8.encode(leafPemStr));

  return PkiHierarchy(
    rootDer: rootCa.der,
    rootPem: rootCa.pem,
    intermediateDer: interDer,
    intermediatePem: interPem,
    leafDer: leafDer,
    leafPem: leafPem,
    rootKey: rootCa.key,
    intermediateKey: intermediateKey,
    leafKey: leafKey,
    rootPrivateKeyPem: rootCa.key.privateKeyPem,
    intermediatePrivateKeyPem: intermediateKey.privateKeyPem,
    leafPrivateKeyPem: leafKey.privateKeyPem,
  );
}


const _rsaSha256 = SigningAlgorithm(
  hash: HashAlgorithm.sha256,
  keyType: SigningKeyType.rsa,
);

const _ecSha256 = SigningAlgorithm(
  hash: HashAlgorithm.sha256,
  keyType: SigningKeyType.ec,
);

/// Converts DER-encoded certificate bytes to a PEM string.
String _derToPem(final OpenSslBindings b, final Uint8List derBytes) {
  final pemBio = b.bioNew(b.bioSMem());
  if (pemBio == nullptr) throw StateError('BIO_new for PEM output');

  try {
    final derBio = bioFromData(b, derBytes);
    if (derBio == nullptr) throw StateError('BIO_new for DER input');
    try {
      final x509 = b.d2iX509Bio(derBio, nullptr);
      if (x509 == nullptr) throw StateError('d2i_X509_bio failed');
      try {
        final ok = b.pemWriteBioX509(pemBio, x509);
        if (ok != 1) throw StateError('PEM_write_bio_X509 failed');
        return bioToString(b, pemBio);
      } finally {
        b.x509Free(x509);
      }
    } finally {
      b.bioFree(derBio);
    }
  } finally {
    b.bioFree(pemBio);
  }
}

OpenSslBindings _createBindings() =>
    OpenSslBindings.create(loadCrypto(), loadSsl());


/// Extracts the subject Distinguished Name from a PEM-encoded certificate.
DistinguishedName _extractSubjectDn(OpenSslBindings b, Uint8List certPem) {
  final bio = bioFromString(b, utf8.decode(certPem));
  if (bio == nullptr) throw StateError('BIO_new for PEM read');

  final x509 = b.pemReadBioX509(bio, nullptr, nullptr, nullptr);
  if (x509 == nullptr) {
    b.bioFree(bio);
    throw StateError('PEM_read_bio_X509 failed');
  }

  try {
    final name = b.x509GetSubjectName(x509);
    if (name == nullptr) throw StateError('X509_get_subject_name failed');

    final buf = calloc<Uint8>(256);
    try {
      b.x509NameOneline(name, buf.cast<Utf8>(), 256);
      return _parseNameLine(buf.cast<Utf8>().toDartString());
    } finally {
      calloc.free(buf);
    }
  } finally {
    b.x509Free(x509);
    b.bioFree(bio);
  }
}

/// Parses an OpenSSL one-line name such as `/CN=Test/C=BR/O=TCC` into a
/// [DistinguishedName].
DistinguishedName _parseNameLine(String line) {
  final parts = <String, String>{};
  for (final segment in line.split('/')) {
    if (segment.isEmpty) continue;
    final eq = segment.indexOf('=');
    if (eq == -1) continue;
    parts[segment.substring(0, eq)] = segment.substring(eq + 1);
  }
  return DistinguishedName(
    commonName: parts['CN'] ?? 'Unknown',
    organization: parts['O'],
    organizationalUnit: parts['OU'],
    locality: parts['L'],
    state: parts['ST'],
    country: parts['C'],
  );
}
