library;

import '../ffi/openssl_bindings.dart';
import 'crypto_context.dart';
import 'crypto_api.dart';
import 'plugin_crypto_operations.dart';

/// [CryptoContext] implementation backed by [PluginCryptoAPI].
class PluginCryptoContext implements CryptoContext {
  @override
  final OpenSslBindings bindings;

  final PluginCryptoOperations _operations;

  PluginCryptoContext(this.bindings)
    : _operations = PluginCryptoOperations(bindings);

  @override
  CryptographicOperations get operations => _operations;
}
