import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'plugin_crypto_platform_interface.dart';

/// An implementation of [PluginCryptoPlatform] that uses method channels.
class MethodChannelPluginCrypto extends PluginCryptoPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('plugin_crypto');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>(
      'getPlatformVersion',
    );
    return version;
  }
}
