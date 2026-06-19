@Tags(['metrics'])
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/utils/secret_memory.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';
import 'package:plugin_crypto/src/metrics/metrics_models.dart';
import 'package:plugin_crypto/src/metrics/zeroization.dart';

import 'fixtures/helpers.dart' as helpers;

MetricsCollector get _collector =>
    MetricsCollector.instance ?? MetricsCollector.create();

typedef _AllZeroNative = Int32 Function(Pointer<Uint8>, Size);
typedef _AllZeroDart = int Function(Pointer<Uint8>, int);

final class _CleanseObserver implements SecretMemoryObserver {
  final _AllZeroDart allZeroNative;
  var calls = 0;
  var allZero = true;

  _CleanseObserver(this.allZeroNative);

  @override
  void afterCleanse(Pointer<Uint8> pointer, int length) {
    calls++;
    if (allZeroNative(pointer, length) != 1) {
      allZero = false;
    }
  }
}

void main() {
  final api = helpers.api();
  late final OpenSslBindings bindings;
  late final _CleanseObserver observer;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    final shimPath = Platform.environment['PLUGIN_CRYPTO_TEST_SHIM'] ??
        '${Directory.current.path}/build/test_native/'
            'libplugin_crypto_test_shim.so';
    final shim = DynamicLibrary.open(shimPath);
    observer = _CleanseObserver(
      shim.lookupFunction<_AllZeroNative, _AllZeroDart>(
        'plugin_crypto_test_all_zero',
      ),
    );
    secretMemoryObserver = observer;
  });

  tearDownAll(() {
    secretMemoryObserver = null;
    final verified = observer.calls > 0 && observer.allZero;
    _collector.setZeroizationMetrics(
      ZeroizationMetrics(
        verificationStatus: verified ? 'verified' : 'failed',
        scope: 'plugin-owned native temporary buffers before free',
        keyMaterialWipedAfterFree: false,
        intermediateBuffersCleared: verified,
        opensslCleanseVerified:
            ZeroizationVerifier.isOpensslCleanseBound(bindings),
        cryptoFreeVerified: ZeroizationVerifier.isCryptoFreeBound(bindings),
        fipsProviderActive:
            ZeroizationVerifier.isFipsProviderActive(bindings),
        evidence: '${observer.calls} cleanup callbacks; allZero=${observer.allZero}',
        methodology:
            'Observed plugin-owned native buffers immediately after '
            'OPENSSL_cleanse and before calloc.free. Caller-owned Dart memory '
            'and OpenSSL-internal allocations are outside this scope.',
      ),
    );
  });

  test('secret buffers are zero immediately before free', () {
    final before = observer.calls;
    final key = Uint8List.fromList(List<int>.filled(16, 0xA5));
    final iv = Uint8List.fromList(List<int>.filled(12, 0x5A));
    final plaintext = Uint8List.fromList(List<int>.filled(32, 0x3C));

    final encrypted = api.aes128GcmEncrypt(key, iv, plaintext);
    expect(encrypted.ciphertext, isNotEmpty);
    expect(observer.calls, greaterThanOrEqualTo(before + 3));
    expect(observer.allZero, isTrue);
  });

  test('required OpenSSL cleanup symbols are bound', () {
    expect(ZeroizationVerifier.isOpensslCleanseBound(bindings), isTrue);
    expect(ZeroizationVerifier.isCryptoFreeBound(bindings), isTrue);
  });

  test('cleanup runs when the native action throws', () {
    final before = observer.calls;
    expect(
      () => withSecretBytes<void>(
        bindings,
        Uint8List.fromList(List<int>.filled(24, 0xCC)),
        (_) => throw StateError('deliberate failure'),
      ),
      throwsStateError,
    );
    expect(observer.calls, before + 1);
    expect(observer.allZero, isTrue);
  });

  test('native shim negative control detects non-zero memory', () {
    final pointer = calloc<Uint8>(8);
    try {
      pointer.asTypedList(8).fillRange(0, 8, 0x7F);
      expect(observer.allZeroNative(pointer, 8), 0);
    } finally {
      calloc.free(pointer);
    }
  });
}
