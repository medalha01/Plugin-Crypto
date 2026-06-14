import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'plugin_crypto_method_channel.dart';

abstract class PluginCryptoPlatform extends PlatformInterface {
  /// Constructs a PluginCryptoPlatform.
  PluginCryptoPlatform() : super(token: _token);

  static final Object _token = Object();

  static PluginCryptoPlatform _instance = MethodChannelPluginCrypto();

  static PluginCryptoPlatform get instance => _instance;

  static set instance(PluginCryptoPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
