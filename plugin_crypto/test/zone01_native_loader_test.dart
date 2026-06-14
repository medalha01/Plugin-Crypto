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
      expect(version, contains('OpenSSL'));
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
