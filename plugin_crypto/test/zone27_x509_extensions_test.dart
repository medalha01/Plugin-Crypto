@TestOn('linux')
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import 'package:plugin_crypto/src/crypto/crypto_api.dart';
import 'package:plugin_crypto/src/crypto/models/certificate_data.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/flows/certificate_creation/certificate_builder.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/crypto/utils/x509_ext_parser.dart';
import 'package:plugin_crypto/src/crypto/utils/bio_utils.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

/// Reusable test Distinguished Name.
const testDn = DistinguishedName(commonName: 'Test');

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone27', 'X.509 Extensions');

  late OpenSslBindings bindings;
  late PluginCryptoAPI api;
  late KeyPair rsaKeyPair;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    api = PluginCryptoAPI.instance;
  });

  setUp(() {
    rsaKeyPair = api.generateRsaKeyPair(2048);
  });


  group('BasicConstraints', () {
    test('parses BasicConstraints extension (CA:true)', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addBasicConstraints(ca: true);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.basicConstraints?.isCa, isTrue);
    });

    test('parses BasicConstraints extension (CA:false)', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addBasicConstraints(ca: false);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.basicConstraints?.isCa, isFalse);
      expect(parsed.extensions?.basicConstraints?.pathLen, isNull);
    });

    test('parses BasicConstraints with pathLen', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addBasicConstraints(ca: true, pathLen: 0);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.basicConstraints?.isCa, isTrue);
      expect(parsed.extensions?.basicConstraints?.pathLen, equals(0));
    });
  });


  group('KeyUsage', () {
    test('parses KeyUsage extension', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addKeyUsage(digitalSignature: true, keyEncipherment: true);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.keyUsage, isNotNull);
      expect(parsed.extensions!.keyUsage, contains('digitalSignature'));
      expect(parsed.extensions!.keyUsage, contains('keyEncipherment'));
    });

    test('parses KeyUsage keyCertSign+crlSign for CA', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addExtension('keyUsage', 'critical,keyCertSign,cRLSign');
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.keyUsage, isNotNull);
      expect(parsed.extensions!.keyUsage, contains('keyCertSign'));
      expect(parsed.extensions!.keyUsage, contains('cRLSign'));
    });
  });


  group('CRL Distribution Points', () {
    test('parses CRL Distribution Points extension', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addExtension(
            'crlDistributionPoints',
            'URI:http://crl.example.com/ca.crl',
          );
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.crlDistributionPoints, isNotNull);
      expect(
        parsed.extensions!.crlDistributionPoints!.any(
          (u) => u.contains('crl.example.com'),
        ),
        isTrue,
      );
    });

    test('parses CRL DP with multiple URIs', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addExtension(
            'crlDistributionPoints',
            'URI:http://crl1.example.com/ca.crl,URI:http://crl2.example.com/ca.crl',
          );
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.crlDistributionPoints, isNotNull);
      final uris = parsed.extensions!.crlDistributionPoints!;
      expect(uris.any((u) => u.contains('crl1.example.com')), isTrue);
      expect(uris.any((u) => u.contains('crl2.example.com')), isTrue);
    });
  });


  group('AuthorityInfoAccess (OCSP)', () {
    test('parses OCSP responder from AIA extension', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addExtension(
            'authorityInfoAccess',
            'OCSP;URI:http://ocsp.example.com',
          );
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.ocspResponders, isNotNull);
      expect(parsed.extensions!.ocspResponders, isNotEmpty);
      expect(
        parsed.extensions!.ocspResponders!.any(
          (u) => u.contains('ocsp.example.com'),
        ),
        isTrue,
      );
    });

    test('AIA extension without OCSP returns null ocspResponders', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.ocspResponders, isNull);
    });
  });


  group('SubjectAltName', () {
    test('parses SubjectAltName DNS entries', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addSubjectAltName(dnsNames: ['example.com', 'test.example.com']);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.subjectAltNames, isNotNull);
      expect(
        parsed.extensions!.subjectAltNames!.any(
          (s) => s.contains('example.com'),
        ),
        isTrue,
      );
      expect(
        parsed.extensions!.subjectAltNames!.any(
          (s) => s.contains('test.example.com'),
        ),
        isTrue,
      );
    });

    test('parses SubjectAltName IP entries', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addSubjectAltName(ipAddresses: ['127.0.0.1', '::1']);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.subjectAltNames, isNotNull);
      expect(
        parsed.extensions!.subjectAltNames!.any((s) => s.contains('127.0.0.1')),
        isTrue,
      );
    });
  });


  group('KeyUsage all flags', () {
    test('parses all KeyUsage flags', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair)
          .addExtension(
            'keyUsage',
            'critical,digitalSignature,nonRepudiation,keyEncipherment,'
                'dataEncipherment,keyAgreement,keyCertSign,cRLSign,'
                'encipherOnly,decipherOnly',
          );
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.keyUsage, isNotNull);
      final ku = parsed.extensions!.keyUsage!;
      expect(ku, contains('digitalSignature'));
      expect(ku, contains('nonRepudiation'));
      expect(ku, contains('keyEncipherment'));
      expect(ku, contains('dataEncipherment'));
      expect(ku, contains('keyAgreement'));
      expect(ku, contains('keyCertSign'));
      expect(ku, contains('cRLSign'));
      expect(ku, contains('encipherOnly'));
      expect(ku, contains('decipherOnly'));
    });
  });


  group('Model objects', () {
    test('X509ParsedExtensions with no extensions has null fields', () {
      const extensions = X509ParsedExtensions();
      expect(extensions.keyUsage, isNull);
      expect(extensions.basicConstraints, isNull);
      expect(extensions.subjectAltNames, isNull);
      expect(extensions.crlDistributionPoints, isNull);
      expect(extensions.ocspResponders, isNull);
    });

    test('X509Extension model works correctly', () {
      const ext = X509Extension(
        oid: '2.5.29.19',
        value: 'critical,CA:TRUE',
        critical: true,
      );
      expect(ext.oid, equals('2.5.29.19'));
      expect(ext.value, equals('critical,CA:TRUE'));
      expect(ext.critical, isTrue);
    });

    test('BasicConstraints model works correctly', () {
      const bcCa = BasicConstraints(isCa: true, pathLen: 0);
      expect(bcCa.isCa, isTrue);
      expect(bcCa.pathLen, equals(0));

      const bcLeaf = BasicConstraints(isCa: false);
      expect(bcLeaf.isCa, isFalse);
      expect(bcLeaf.pathLen, isNull);
    });

    test('cert with no extensions has all extension fields null', () {
      final builder = CertificateBuilder(bindings)
          .subjectDn(testDn)
          .issuerDn(testDn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);
      final buildResult = builder.buildPem();
      final pemStr = (buildResult as CryptoSuccess<String>).value;
      final pem = Uint8List.fromList(utf8.encode(pemStr));
      final parsed = api.parseX509Certificate(pem);
      expect(parsed.extensions?.keyUsage, isNull);
      expect(parsed.extensions?.basicConstraints, isNull);
      expect(parsed.extensions?.subjectAltNames, isNull);
      expect(parsed.extensions?.crlDistributionPoints, isNull);
      expect(parsed.extensions?.ocspResponders, isNull);
    });
  });


  group('X509ExtensionParser', () {
    test(
      'parseExtensions on self-signed cert without extensions returns empty',
      () {
        final builder = CertificateBuilder(bindings)
            .subjectDn(testDn)
            .issuerDn(testDn)
            .publicKey(rsaKeyPair)
            .validityPeriod(const Duration(days: 365))
            .signWith(rsaKeyPair);
        final buildResult = builder.build();
        final der = (buildResult as CryptoSuccess<Uint8List>).value;

        final bio = bioFromData(bindings, der);
        final x509 = bindings.d2iX509Bio(bio, nullptr);
        bindings.bioFree(bio);
        try {
          final parser = X509ExtensionParser(bindings);
          final ext = parser.parseExtensions(x509.cast());
          expect(ext.keyUsage, isNull);
          expect(ext.basicConstraints, isNull);
          expect(ext.subjectAltNames, isNull);
        } finally {
          bindings.x509Free(x509);
        }
      },
    );

    test(
      'X509ExtensionParser.parseExtensions returns correct BasicConstraints',
      () {
        final builder = CertificateBuilder(bindings)
            .subjectDn(testDn)
            .issuerDn(testDn)
            .publicKey(rsaKeyPair)
            .validityPeriod(const Duration(days: 365))
            .signWith(rsaKeyPair)
            .addBasicConstraints(ca: true);
        final buildResult = builder.build();
        final der = (buildResult as CryptoSuccess<Uint8List>).value;

        final bio = bioFromData(bindings, der);
        final x509 = bindings.d2iX509Bio(bio, nullptr);
        bindings.bioFree(bio);
        try {
          final parser = X509ExtensionParser(bindings);
          final ext = parser.parseExtensions(x509.cast());
          expect(ext.basicConstraints, isNotNull);
          expect(ext.basicConstraints!.isCa, isTrue);
        } finally {
          bindings.x509Free(x509);
        }
      },
    );
  });

  m?.endZone();
}
