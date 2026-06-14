library;

import 'dart:typed_data';

import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/crypto_context.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_chain/chain_verification_request.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';

/// Holds the pre-built PKI hierarchy: root, intermediate, and leaf.
class PkiHierarchy {
  final KeyPair rootKey;
  final KeyPair intermediateKey;
  final KeyPair leafKey;
  final Uint8List rootDer;
  final Uint8List intermediateDer;
  final Uint8List leafDer;
  final Uint8List rootPem;
  final Uint8List intermediatePem;
  final Uint8List leafPem;

  const PkiHierarchy({
    required this.rootKey,
    required this.intermediateKey,
    required this.leafKey,
    required this.rootDer,
    required this.intermediateDer,
    required this.leafDer,
    required this.rootPem,
    required this.intermediatePem,
    required this.leafPem,
  });
}

/// A single certificate entry in a PKI — holds the cert (DER + PEM) and its key.
class CertificateEntry {
  final Uint8List pem;
  final Uint8List der;
  final KeyPair key;

  const CertificateEntry({
    required this.pem,
    required this.der,
    required this.key,
  });
}

class SharedPkiFactory {
  final CryptoContext _ctx;

  SharedPkiFactory(this._ctx);

  /// Creates a 3-level hierarchy:
  ///   Root CA → Intermediate CA → End-Entity
  PkiHierarchy createPkiHierarchy() {
    final rootKey = _ctx.operations.generateRsaKeyPair(2048);
    final intermediateKey = _ctx.operations.generateRsaKeyPair(2048);
    final leafKey = _ctx.operations.generateRsaKeyPair(2048);

    const rootDn = DistinguishedName(
      commonName: 'Test Root CA',
      organization: 'TCC PKI',
      country: 'BR',
    );
    final rootDerResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(rootDn)
        .issuerDn(rootDn)
        .publicKey(rootKey)
        .validityPeriod(const Duration(days: 3650))
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .addBasicConstraints(ca: true, pathLen: 1)
        .signWith(rootKey)
        .build();

    final rootCert = _requireSuccess(rootDerResult, 'Root CA build');
    final rootPem = _derToPemBytes(rootCert);

    const intermediateDn = DistinguishedName(
      commonName: 'Test Intermediate CA',
      organization: 'TCC PKI',
      country: 'BR',
    );
    final intermediateDerResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(intermediateDn)
        .issuerDn(rootDn)
        .publicKey(intermediateKey)
        .validityPeriod(const Duration(days: 1825))
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .addBasicConstraints(ca: true, pathLen: 0)
        .signWith(rootKey)
        .build();

    final intermediateCert = _requireSuccess(
      intermediateDerResult,
      'Intermediate CA build',
    );
    final intermediatePem = _derToPemBytes(intermediateCert);

    const leafDn = DistinguishedName(
      commonName: 'test.example.com',
      organization: 'TCC PKI',
      country: 'BR',
    );
    final leafDerResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(leafDn)
        .issuerDn(intermediateDn)
        .publicKey(leafKey)
        .validityPeriod(const Duration(days: 365))
        .addExtension(
          'keyUsage',
          'digitalSignature,nonRepudiation,keyEncipherment',
          critical: true,
        )
        .addBasicConstraints(ca: false)
        .signWith(intermediateKey)
        .build();

    final leafCert = _requireSuccess(leafDerResult, 'Leaf cert build');
    final leafPem = _derToPemBytes(leafCert);

    return PkiHierarchy(
      rootKey: rootKey,
      intermediateKey: intermediateKey,
      leafKey: leafKey,
      rootDer: rootCert,
      intermediateDer: intermediateCert,
      leafDer: leafCert,
      rootPem: rootPem,
      intermediatePem: intermediatePem,
      leafPem: leafPem,
    );
  }

  /// Convenience: creates a valid 3-level chain request.
  ChainVerificationRequest createValidChainRequest(
    PkiHierarchy pki, {
    bool usePem = false,
  }) {
    return ChainVerificationRequest(
      leafCert: usePem ? pki.leafPem : pki.leafDer,
      trustedRoot: usePem ? pki.rootPem : pki.rootDer,
      intermediates: [usePem ? pki.intermediatePem : pki.intermediateDer],
    );
  }

  /// Creates a self-signed root CA certificate.
  CertificateEntry createRootCa({String commonName = 'Test Root CA'}) {
    final key = _ctx.operations.generateRsaKeyPair(2048);
    const dn = DistinguishedName(
      commonName: 'Test Root CA',
      organization: 'TCC PKI',
      country: 'BR',
    );
    final actualDn = commonName == 'Test Root CA'
        ? dn
        : DistinguishedName(
            commonName: commonName,
            organization: 'TCC PKI',
            country: 'BR',
          );
    final derResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(actualDn)
        .issuerDn(actualDn)
        .publicKey(key)
        .validityPeriod(const Duration(days: 3650))
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .addBasicConstraints(ca: true, pathLen: 1)
        .signWith(key)
        .build();
    final der = _requireSuccess(derResult, 'Root CA build');
    final pem = _derToPemBytes(der);
    return CertificateEntry(pem: pem, der: der, key: key);
  }

  /// Creates an intermediate CA signed by [issuerPem]/[issuerKey].
  CertificateEntry createIntermediateCa(
    Uint8List issuerPem,
    KeyPair issuerKey, {
    String commonName = 'Test Intermediate CA',
  }) {
    final key = _ctx.operations.generateRsaKeyPair(2048);
    const issuerDn = DistinguishedName(
      commonName: 'Test Root CA',
      organization: 'TCC PKI',
      country: 'BR',
    );
    final subjectDn = commonName == 'Test Intermediate CA'
        ? const DistinguishedName(
            commonName: 'Test Intermediate CA',
            organization: 'TCC PKI',
            country: 'BR',
          )
        : DistinguishedName(
            commonName: commonName,
            organization: 'TCC PKI',
            country: 'BR',
          );
    final derResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(subjectDn)
        .issuerDn(issuerDn)
        .publicKey(key)
        .validityPeriod(const Duration(days: 1825))
        .addExtension('keyUsage', 'keyCertSign,cRLSign', critical: true)
        .addBasicConstraints(ca: true, pathLen: 0)
        .signWith(issuerKey)
        .build();
    final der = _requireSuccess(derResult, 'Intermediate CA build');
    final pem = _derToPemBytes(der);
    return CertificateEntry(pem: pem, der: der, key: key);
  }

  /// Creates an end-entity leaf certificate signed by [issuerPem]/[issuerKey].
  CertificateEntry createEndEntity(
    Uint8List issuerPem,
    KeyPair issuerKey, {
    String commonName = 'test.example.com',
  }) {
    final key = _ctx.operations.generateRsaKeyPair(2048);
    final issuerDn = _extractSubjectDn(issuerPem);
    final leafDn = DistinguishedName(
      commonName: commonName,
      organization: 'TCC PKI',
      country: 'BR',
    );
    final derResult = CertificateBuilder(_ctx.bindings)
        .subjectDn(leafDn)
        .issuerDn(issuerDn)
        .publicKey(key)
        .validityPeriod(const Duration(days: 365))
        .addExtension(
          'keyUsage',
          'digitalSignature,nonRepudiation,keyEncipherment',
          critical: true,
        )
        .addBasicConstraints(ca: false)
        .signWith(issuerKey)
        .build();
    final der = _requireSuccess(derResult, 'Leaf cert build');
    final pem = _derToPemBytes(der);
    return CertificateEntry(pem: pem, der: der, key: key);
  }

  /// Extracts the subject DN from a PEM cert as a DistinguishedName.
  /// Used for issuer DN when building child certs.
  DistinguishedName _extractSubjectDn(Uint8List pemCert) {
    final api = PluginCryptoAPI.instance;
    final parsed = api.parseX509Certificate(pemCert);
    final subj = parsed.subject; // e.g. "/CN=Deep Inter 2/O=TCC PKI/C=BR"

    String commonName = 'Unknown';
    String org = '';
    String country = '';

    final parts = subj.split('/');
    for (final part in parts) {
      if (part.isEmpty) continue;
      final eqIdx = part.indexOf('=');
      if (eqIdx < 0) continue;
      final key = part.substring(0, eqIdx);
      final value = part.substring(eqIdx + 1);
      switch (key) {
        case 'CN':
          commonName = value;
        case 'O':
          org = value;
        case 'C':
          country = value;
      }
    }

    return DistinguishedName(
      commonName: commonName,
      organization: org.isEmpty ? null : org,
      country: country.isEmpty ? null : country,
    );
  }


  T _requireSuccess<T>(CryptoResult<T> result, String label) {
    if (result is CryptoSuccess<T>) return result.value;
    final err = (result as CryptoFailure<T>).error;
    throw StateError('$label failed: ${err.message}');
  }

  Uint8List _derToPemBytes(Uint8List der) {
    final b64 = _base64Encode(der);
    final pem =
        '-----BEGIN CERTIFICATE-----\n'
        '${_wrap64(b64)}\n'
        '-----END CERTIFICATE-----\n';
    return Uint8List.fromList(pem.codeUnits);
  }

  String _base64Encode(Uint8List data) {
    const _alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    final out = StringBuffer();
    for (var i = 0; i < data.length; i += 3) {
      final remaining = data.length - i;
      final b0 = data[i];
      final b1 = remaining > 1 ? data[i + 1] : 0;
      final b2 = remaining > 2 ? data[i + 2] : 0;

      out.write(_alphabet[(b0 >> 2) & 0x3F]);
      out.write(_alphabet[((b0 << 4) | (b1 >> 4)) & 0x3F]);

      if (remaining > 1) {
        out.write(_alphabet[((b1 << 2) | (b2 >> 6)) & 0x3F]);
      } else {
        out.write('=');
      }

      if (remaining > 2) {
        out.write(_alphabet[b2 & 0x3F]);
      } else {
        out.write('=');
      }
    }
    return out.toString();
  }

  String _wrap64(String base64, {int width = 64}) {
    final buf = StringBuffer();
    for (var i = 0; i < base64.length; i += width) {
      final end = (i + width > base64.length) ? base64.length : i + width;
      if (buf.isNotEmpty) buf.write('\n');
      buf.write(base64.substring(i, end));
    }
    return buf.toString();
  }
}
