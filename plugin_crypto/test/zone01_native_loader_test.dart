import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone01', 'Native Loader');

  TestWidgetsFlutterBinding.ensureInitialized();
  group('Native Loader', () {
    test('candidate order prefers override and executable directory', () {
      final candidates = nativeLibraryCandidates(
        'crypto',
        operatingSystem: 'linux',
        executablePath: '/opt/app/plugin_crypto',
        currentDirectory: '/workspace/plugin_crypto',
        environment: const {'PLUGIN_CRYPTO_NATIVE_DIR': '/pinned'},
      );
      expect(candidates.first, contains('/pinned'));
      expect(candidates[1], contains('/opt/app'));
      expect(candidates.last, 'libcrypto.so.4');
    });

    test('unsupported platforms have no library candidates', () {
      expect(
        nativeLibraryCandidates(
          'crypto',
          operatingSystem: 'plan9',
          executablePath: '/app',
          currentDirectory: '/workspace',
        ),
        isEmpty,
      );
    });

    test('loadCrypto returns valid DynamicLibrary', () {
      expect(() => loadCrypto(), returnsNormally);
    });

    test('loadSsl returns valid DynamicLibrary', () {
      expect(() => loadSsl(), returnsNormally);
    });

    test('OpenSslBindings.create does not throw', () {
      final crypto = loadCrypto();
      final ssl = loadSsl();
      expect(() => OpenSslBindings.create(crypto, ssl), returnsNormally);
    });
  });

  group('PluginCryptoAPI Initialization', () {
    test('instance returns valid', () {
      final api = PluginCryptoAPI.instance;
      expect(api, isNotNull);
    });

    test('getOpenSSLVersion returns non-empty string containing OpenSSL', () {
      final api = PluginCryptoAPI.instance;
      final version = api.getOpenSSLVersion();
      expect(version, isNotEmpty);
      expect(version, startsWith('OpenSSL 4.'));
    });

    test('same version on second call', () {
      final api = PluginCryptoAPI.instance;
      final first = api.getOpenSSLVersion();
      final second = api.getOpenSSLVersion();
      expect(second, equals(first));
    });
  });

  group('PluginCrypto convenience', () {
    test('PluginCrypto.instance.api returns crypto API', () {
      final plugin = PluginCrypto.instance;
      final api = plugin.api;
      expect(api, isNotNull);
      expect(api, isA<PluginCryptoAPI>());
    });

    test('getPlatformVersion returns non-null', () async {
      final plugin = PluginCrypto.instance;
      try {
        final version = await plugin.getPlatformVersion();
        expect(version, isNotNull);
      } on MissingPluginException {
      }
    });
  });

  m?.endZone();
}
