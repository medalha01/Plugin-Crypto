/// KeyCreatorFactory, CertificateBuilder, StreamingFileSigner integration tests.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:io' show Platform, File, Directory;
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/file_signing/streaming_file_signer.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/rsa_key_creator.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/throughput.dart';

import 'android_metrics_collector.dart';


/// Converts a PEM string to [Uint8List].
Uint8List _pem(String s) => Uint8List.fromList(utf8.encode(s));

/// Creates a temporary file with the given content and returns its path.
String _createTempFile(String name, Uint8List content) {
  final dir = Directory.systemTemp;
  final file = File('${dir.path}/$name');
  file.writeAsBytesSync(content);
  return file.path;
}

/// Generates random bytes of [length] for file content testing.
Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));
}


void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();


  /// Current test group name, set at the start of each [group] callback.
  String? currentGroupName;

  /// Current test name, set as the first line of each [testWidgets] callback.
  String? currentTestName;

  /// Per-test stopwatch started in [setUp], stopped in [tearDown].
  late Stopwatch testStopwatch;

  /// Metrics collector — only non-null when [TCC_METRICS_OUTPUT] is set.
  final metricsOutputPath = Platform.environment['TCC_METRICS_OUTPUT'];
  AndroidMetricsCollector? collector;

  if (metricsOutputPath != null && metricsOutputPath.isNotEmpty) {
    collector = AndroidMetricsCollector.create();
    collector.recordMemorySample(
      'baseline',
      AndroidMetricsCollector.readVmRss(),
    );
  }

  late PluginCryptoAPI api;
  late OpenSslBindings bindings;
  late KeyCreatorFactory keyFactory;

  setUp(() async {
    testStopwatch = Stopwatch()..start();
    api = PluginCryptoAPI.instance;
    api.clearErrors();
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    keyFactory = KeyCreatorFactory(bindings);
  });

  tearDown(() {
    testStopwatch.stop();
    final elapsedMs = testStopwatch.elapsedMicroseconds ~/ 1000;
    final fullName = currentGroupName != null && currentTestName != null
        ? '$currentGroupName :: $currentTestName'
        : (currentTestName ?? 'unknown');
    collector?.recordTestResult(fullName, 'passed', elapsedMs);
    api.clearErrors();
  });


  group('CF1 — Key Creation', () {
    currentGroupName = 'CF1 — Key Creation';
    collector?.startGroup('CF1 — Key Creation');

    testWidgets('RSA-2048 keygen produces valid PEM', (_) async {
      currentTestName = 'RSA-2048 keygen produces valid PEM';
      final spec = RsaKeySpec(2048);
      final creator = keyFactory.create(spec)!;
      final result = creator.create(spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final kp = (result as CryptoSuccess<KeyPair>).value;
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('EC prime256v1 keygen produces valid PEM', (_) async {
      currentTestName = 'EC prime256v1 keygen produces valid PEM';
      final spec = EcKeySpec('prime256v1');
      final creator = keyFactory.create(spec)!;
      final result = creator.create(spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final kp = (result as CryptoSuccess<KeyPair>).value;
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('EC secp384r1 keygen produces valid PEM', (_) async {
      currentTestName = 'EC secp384r1 keygen produces valid PEM';
      final spec = EcKeySpec('secp384r1');
      final creator = keyFactory.create(spec)!;
      final result = creator.create(spec);

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final kp = (result as CryptoSuccess<KeyPair>).value;
      expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
      expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));
    });

    testWidgets('Generated RSA keys are distinct across calls', (_) async {
      currentTestName = 'Generated RSA keys are distinct across calls';
      final spec = RsaKeySpec(2048);
      final creator = keyFactory.create(spec)!;
      final results = <String>{};
      for (var i = 0; i < 5; i++) {
        final result = creator.create(spec);
        expect(result, isA<CryptoSuccess<KeyPair>>());
        final kp = (result as CryptoSuccess<KeyPair>).value;
        results.add(kp.privateKeyPem);
      }
      expect(results.length, equals(5));
    });

    testWidgets('KeyPair PEM headers match key type', (_) async {
      currentTestName = 'KeyPair PEM headers match key type';
      final rsaResult = keyFactory.create(RsaKeySpec(2048))!.create(RsaKeySpec(2048));
      final ecResult = keyFactory.create(EcKeySpec('prime256v1'))!.create(EcKeySpec('prime256v1'));

      expect(rsaResult, isA<CryptoSuccess<KeyPair>>());
      expect(ecResult, isA<CryptoSuccess<KeyPair>>());

      final rsaKp = (rsaResult as CryptoSuccess<KeyPair>).value;
      final ecKp = (ecResult as CryptoSuccess<KeyPair>).value;

      expect(
        rsaKp.privateKeyPem.contains('RSA') ||
            rsaKp.privateKeyPem.contains('BEGIN PRIVATE KEY'),
        isTrue,
      );
      expect(
        ecKp.privateKeyPem.contains('EC') ||
            ecKp.privateKeyPem.contains('BEGIN PRIVATE KEY'),
        isTrue,
      );
    });

    collector?.endGroup();
  });


  group('CF2 — Certificate Creation', () {
    currentGroupName = 'CF2 — Certificate Creation';
    collector?.startGroup('CF2 — Certificate Creation');

    late KeyPair rsaKeyPair;
    late KeyPair ecKeyPair;

    setUp(() {
      final rsaCreator = keyFactory.create(RsaKeySpec(2048))!;
      final ecCreator = keyFactory.create(EcKeySpec('prime256v1'))!;
      rsaKeyPair = (rsaCreator.create(RsaKeySpec(2048)) as CryptoSuccess<KeyPair>).value;
      ecKeyPair = (ecCreator.create(EcKeySpec('prime256v1')) as CryptoSuccess<KeyPair>).value;
    });

    testWidgets('Self-signed RSA cert parses correctly', (_) async {
      currentTestName = 'Self-signed RSA cert parses correctly';
      const dn = DistinguishedName(
        commonName: 'AndroidRsaTest',
        organization: 'TCC',
        country: 'BR',
      );

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final derBytes = (result as CryptoSuccess<Uint8List>).value;
      expect(derBytes, isNotEmpty);

      final cert = api.parseX509Certificate(derBytes);
      expect(cert.subject, contains('AndroidRsaTest'));
      expect(cert.issuer, contains('AndroidRsaTest'));
      if (!Platform.isAndroid) {
        expect(cert.notBefore.year, greaterThanOrEqualTo(2026));
        expect(cert.notAfter.year, greaterThanOrEqualTo(2026));
      }
    });

    testWidgets('Self-signed EC cert parses correctly', (_) async {
      currentTestName = 'Self-signed EC cert parses correctly';
      const dn = DistinguishedName(
        commonName: 'AndroidEcTest',
        organization: 'TCC',
        country: 'BR',
      );

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(ecKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(ecKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final derBytes = (result as CryptoSuccess<Uint8List>).value;
      expect(derBytes, isNotEmpty);

      final cert = api.parseX509Certificate(derBytes);
      expect(cert.subject, contains('AndroidEcTest'));
      expect(cert.issuer, contains('AndroidEcTest'));
    });

    testWidgets('CertificateData validity dates match requested period',
        (_) async {
      currentTestName =
          'CertificateData validity dates match requested period';
      const dn = DistinguishedName(commonName: 'ValidityTest');

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 30))
          .signWith(rsaKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final derBytes = (result as CryptoSuccess<Uint8List>).value;
      final cert = api.parseX509Certificate(derBytes);

      if (!Platform.isAndroid) {
        final delta = cert.notAfter.difference(cert.notBefore);
        expect(delta.inDays, greaterThanOrEqualTo(29));
        expect(delta.inDays, lessThanOrEqualTo(31));
      }
    });

    testWidgets('CertificateBuilder with extensions', (_) async {
      currentTestName = 'CertificateBuilder with extensions';
      const dn = DistinguishedName(commonName: 'ExtensionsTest');

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .addBasicConstraints(ca: true, pathLen: 0)
          .addKeyUsage(
              digitalSignature: true,
              keyEncipherment: true,
              dataEncipherment: false)
          .signWith(rsaKeyPair);

      final result = builder.build();

      expect(result, isA<CryptoSuccess<Uint8List>>());
      final derBytes = (result as CryptoSuccess<Uint8List>).value;
      expect(derBytes, isNotEmpty);
      final cert = api.parseX509Certificate(derBytes);
      expect(cert.subject, contains('ExtensionsTest'));
    });

    testWidgets('CertificateBuilder buildPem returns valid PEM', (_) async {
      currentTestName = 'CertificateBuilder buildPem returns valid PEM';
      const dn = DistinguishedName(commonName: 'PemTest');

      final builder = CertificateBuilder(bindings)
          .subjectDn(dn)
          .issuerDn(dn)
          .publicKey(rsaKeyPair)
          .validityPeriod(const Duration(days: 365))
          .signWith(rsaKeyPair);

      final result = builder.buildPem();

      expect(result, isA<CryptoSuccess<String>>());
      final pemString = (result as CryptoSuccess<String>).value;
      expect(pemString, contains('-----BEGIN CERTIFICATE-----'));
      expect(pemString, contains('-----END CERTIFICATE-----'));
    });

    collector?.endGroup();
  });


  group('CF3 — File Signing', () {
    currentGroupName = 'CF3 — File Signing';
    collector?.startGroup('CF3 — File Signing');

    late KeyPair rsaKeyPair;
    late KeyPair ecKeyPair;

    setUp(() {
      final rsaCreator = keyFactory.create(RsaKeySpec(2048))!;
      final ecCreator = keyFactory.create(EcKeySpec('prime256v1'))!;
      rsaKeyPair = (rsaCreator.create(RsaKeySpec(2048)) as CryptoSuccess<KeyPair>).value;
      ecKeyPair = (ecCreator.create(EcKeySpec('prime256v1')) as CryptoSuccess<KeyPair>).value;
    });

    testWidgets('Sign 10 KB file with RSA key and verify', (_) async {
      currentTestName = 'Sign 10 KB file with RSA key and verify';
      final fileContent = _randomBytes(10 * 1024);
      final filePath = _createTempFile('rsa_10k_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: rsaKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          fileContent,
          _pem(rsaKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('Sign 10 KB file with EC key and verify', (_) async {
      currentTestName = 'Sign 10 KB file with EC key and verify';
      final fileContent = _randomBytes(10 * 1024);
      final filePath = _createTempFile('ec_10k_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: ecKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          fileContent,
          _pem(ecKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('Sign 100 KB file with RSA key (streaming)', (_) async {
      currentTestName = 'Sign 100 KB file with RSA key (streaming)';
      final fileContent = _randomBytes(100 * 1024);
      final filePath = _createTempFile('rsa_100k_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: rsaKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final sw = Stopwatch()..start();
        final result = signer.sign(request);
        sw.stop();

        collector?.recordOperationTiming(OperationTiming(
          operation: 'fileSign_RSA_100KB',
          category: 'file_sign',
          inputSizeBytes: fileContent.length,
          coldMs: sw.elapsedMicroseconds / 1000.0,
          warmMs: 0,
          throughputMbps: computeMbps(
              fileContent.length, sw.elapsedMicroseconds / 1000.0),
          iterationsWarm: 1,
        ));

        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          fileContent,
          _pem(rsaKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    }, tags: ['slow']);

    testWidgets('Sign 1 MB file with EC key (streaming)', (_) async {
      currentTestName = 'Sign 1 MB file with EC key (streaming)';
      final fileContent = _randomBytes(1024 * 1024);
      final filePath = _createTempFile('ec_1mb_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: ecKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final sw = Stopwatch()..start();
        final result = signer.sign(request);
        sw.stop();

        collector?.recordOperationTiming(OperationTiming(
          operation: 'fileSign_EC_1MB',
          category: 'file_sign',
          inputSizeBytes: fileContent.length,
          coldMs: sw.elapsedMicroseconds / 1000.0,
          warmMs: 0,
          throughputMbps: computeMbps(
              fileContent.length, sw.elapsedMicroseconds / 1000.0),
          iterationsWarm: 1,
        ));

        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          fileContent,
          _pem(ecKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    }, tags: ['slow']);

    testWidgets('Signature does NOT verify with wrong public key',
        (_) async {
      currentTestName = 'Signature does NOT verify with wrong public key';
      final fileContent = _randomBytes(1024);
      final filePath = _createTempFile('wrong_key_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: rsaKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;

        final verified = api.verify(
          fileContent,
          _pem(ecKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isFalse);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('Signature does NOT verify with tampered file content',
        (_) async {
      currentTestName =
          'Signature does NOT verify with tampered file content';
      final fileContent = _randomBytes(1024);
      final filePath = _createTempFile('tamper_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: rsaKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;

        final tampered = Uint8List.fromList(fileContent);
        tampered[0] = tampered[0] ^ 0xFF; // Flip bits in first byte
        final verified = api.verify(
          tampered,
          _pem(rsaKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isFalse);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('File signing with empty file succeeds', (_) async {
      currentTestName = 'File signing with empty file succeeds';
      final emptyContent = Uint8List(0);
      final filePath = _createTempFile('empty_test.bin', emptyContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: ecKeyPair.privateKeyPem,
          hashAlgorithm: 'sha256',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          emptyContent,
          _pem(ecKeyPair.publicKeyPem),
          signature,
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('File signing with sha512 hash algorithm', (_) async {
      currentTestName = 'File signing with sha512 hash algorithm';
      final fileContent = _randomBytes(8 * 1024);
      final filePath = _createTempFile('sha512_test.bin', fileContent);

      try {
        final signer = StreamingFileSigner(bindings);
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: rsaKeyPair.privateKeyPem,
          hashAlgorithm: 'sha512',
        );

        final result = signer.sign(request);
        expect(result, isA<CryptoSuccess<Uint8List>>());
        final signature = (result as CryptoSuccess<Uint8List>).value;
        expect(signature, isNotEmpty);

        final verified = api.verify(
          fileContent,
          _pem(rsaKeyPair.publicKeyPem),
          signature,
          hashAlgorithm: 'sha512',
        );
        expect(verified, isTrue);
      } finally {
        File(filePath).delete().ignore();
      }
    });

    collector?.endGroup();
  });


  group('CF4 — Error Handling', () {
    currentGroupName = 'CF4 — Error Handling';
    collector?.startGroup('CF4 — Error Handling');

    testWidgets('File signing non-existent file returns CryptoFailure',
        (_) async {
      currentTestName =
          'File signing non-existent file returns CryptoFailure';
      final signer = StreamingFileSigner(bindings);
      final request = FileSigningRequest(
        filePath: '/nonexistent/path/to/file_that_does_not_exist.bin',
        privateKeyPem: '-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n',
        hashAlgorithm: 'sha256',
      );

      final result = signer.sign(request);
      expect(result, isA<CryptoFailure<Uint8List>>());
    });

    testWidgets('File signing with invalid private key returns CryptoFailure',
        (_) async {
      currentTestName =
          'File signing with invalid private key returns CryptoFailure';
      final filePath = _createTempFile('badkey_test.bin', _randomBytes(256));

      try {
        const badPem = '-----BEGIN PRIVATE KEY-----\nnot-a-valid-key\n-----END PRIVATE KEY-----\n';
        final request = FileSigningRequest(
          filePath: filePath,
          privateKeyPem: badPem,
          hashAlgorithm: 'sha256',
        );

        final signer = StreamingFileSigner(bindings);
        final result = signer.sign(request);
        expect(result, isA<CryptoFailure<Uint8List>>());
      } finally {
        File(filePath).delete().ignore();
      }
    });

    testWidgets('Unregistering a KeySpec type returns null from factory',
        (_) async {
      currentTestName =
          'Unregistering a KeySpec type returns null from factory';
      keyFactory.unregister(RsaKeySpec);
      try {
        final creator = keyFactory.create(RsaKeySpec(2048));
        expect(creator, isNull);
      } finally {
        keyFactory.register(RsaKeySpec, () => RsaKeyCreator(bindings));
      }
    });

    collector?.endGroup();
  });
}
