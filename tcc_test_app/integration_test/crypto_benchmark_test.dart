import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_kem_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_dsa_key_creator.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';

const _warmupIter = 5;
const _measIter = 25;

double _measure(String label, void Function() fn, {int warmup = _warmupIter, int iterations = _measIter}) {
  for (var i = 0; i < warmup; i++) {
    fn();
  }
  final sw = Stopwatch();
  final times = <double>[];
  for (var i = 0; i < iterations; i++) {
    sw.reset();
    sw.start();
    fn();
    sw.stop();
    times.add(sw.elapsedMicroseconds / 1000.0);
  }
  times.sort();
  final sum = times.reduce((a, b) => a + b);
  return sum / times.length;
}

Uint8List _randomBytes(int length, {int seed = 42}) {
  final rng = Random(seed);
  return Uint8List.fromList(List.generate(length, (_) => rng.nextInt(256)));
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final results = <String, dynamic>{
    'schema_version': '1.0.0',
    'generated_at': DateTime.now().toUtc().toIso8601String(),
    'platform': 'android_arm64_v8a',
    'operations': <Map<String, dynamic>>[],
  };

  late PluginCryptoAPI api;
  late OpenSslBindings bindings;
  late MlKemKeyCreator mlKemCreator;
  late MlDsaKeyCreator mlDsaCreator;

  setUpAll(() {
    api = PluginCryptoAPI.instance;
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    mlKemCreator = MlKemKeyCreator(bindings);
    mlDsaCreator = MlDsaKeyCreator(bindings);
  });

  test('SHA-256 (1 KB)', () {
    final data = _randomBytes(1024);
    final warmMs = _measure('sha256_1kb', () => api.sha256(data));
    (results['operations'] as List).add({
      'operation': 'sha256',
      'input_size_bytes': 1024,
      'warm_ms': warmMs,
    });
  });

  test('AES-256-GCM encrypt (1 KB)', () {
    final key = _randomBytes(32);
    final iv = _randomBytes(12);
    final plaintext = _randomBytes(1024);
    final warmMs = _measure('aes256GcmEncrypt_1kb', () => api.aes256GcmEncrypt(key, iv, plaintext));
    (results['operations'] as List).add({
      'operation': 'aes256GcmEncrypt',
      'input_size_bytes': 1024,
      'warm_ms': warmMs,
    });
  });

  test('RSA-2048 keygen', () {
    final warmMs = _measure('generateRsaKeyPair_2048', () => api.generateRsaKeyPair(2048));
    (results['operations'] as List).add({
      'operation': 'generateRsaKeyPair_2048',
      'input_size_bytes': 0,
      'warm_ms': warmMs,
    });
  });

  test('RSA-2048 sign (SHA-256, 32 B)', () {
    final keyPair = api.generateRsaKeyPair(2048);
    final message = _randomBytes(32);
    final privKey = Uint8List.fromList(utf8.encode(keyPair.privateKeyPem));
    final warmMs = _measure('rsaSign_sha256_32B', () => api.sign(message, privKey, hashAlgorithm: 'sha256'));
    (results['operations'] as List).add({
      'operation': 'rsaSign_sha256',
      'input_size_bytes': 32,
      'warm_ms': warmMs,
    });
  });

  test('RSA-2048 verify (SHA-256, 32 B)', () {
    final keyPair = api.generateRsaKeyPair(2048);
    final message = _randomBytes(32);
    final privKey = Uint8List.fromList(utf8.encode(keyPair.privateKeyPem));
    final pubKey = Uint8List.fromList(utf8.encode(keyPair.publicKeyPem));
    final signature = api.sign(message, privKey, hashAlgorithm: 'sha256');
    final warmMs = _measure('rsaVerify_sha256_32B', () {
      api.verify(message, pubKey, signature, hashAlgorithm: 'sha256');
    });
    (results['operations'] as List).add({
      'operation': 'rsaVerify_sha256',
      'input_size_bytes': 32,
      'warm_ms': warmMs,
    });
  });

  test('ECDSA P-256 sign (32 B)', () {
    final keyPair = api.generateEcKeyPair('prime256v1');
    final message = _randomBytes(32);
    final privKey = Uint8List.fromList(utf8.encode(keyPair.privateKeyPem));
    final warmMs = _measure('ecSign_prime256v1_32B', () => api.sign(message, privKey, hashAlgorithm: 'sha256'));
    (results['operations'] as List).add({
      'operation': 'ecSign_prime256v1',
      'input_size_bytes': 32,
      'warm_ms': warmMs,
    });
  });

  test('ML-KEM-768 keygen', () {
    final spec = const MlKemKeySpec(MlKemParameterSet.mlKem768);
    final warmMs = _measure('generateMlKemKeyPair_mlKem768', () => mlKemCreator.create(spec));
    final op = <String, dynamic>{
      'operation': 'generateMlKemKeyPair_mlKem768',
      'input_size_bytes': 0,
      'warm_ms': warmMs,
    };
    (results['operations'] as List).add(op);
  });

  test('ML-DSA-44 sign (32 B)', () {
    final spec = const MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
    final cr = mlDsaCreator.create(spec);
    final keyPair = (cr as CryptoSuccess).value as dynamic;
    final message = _randomBytes(32);
    final privKey = Uint8List.fromList(utf8.encode(keyPair.privateKeyPem as String));
    final warmMs = _measure('mlDsaSign_mlDsa44_32B', () => api.sign(message, privKey, hashAlgorithm: 'sha256'));
    (results['operations'] as List).add({
      'operation': 'mlDsaSign_mlDsa44',
      'input_size_bytes': 32,
      'warm_ms': warmMs,
    });
  });

  tearDownAll(() {
    final encoded = const JsonEncoder.withIndent('  ').convert(results);
    final path = '${Directory.systemTemp.path}/tcc_android_benchmark.json';
    File(path).writeAsStringSync(encoded);
    print('TCC_BENCHMARK_OUTPUT:$path');
  });
}
