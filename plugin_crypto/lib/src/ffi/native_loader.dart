library;

import 'dart:ffi';
import 'dart:io';

String? _resolveNativeDir() {
  final envDir = Platform.environment['PLUGIN_CRYPTO_NATIVE_DIR'];
  if (envDir != null && Directory(envDir).existsSync()) return envDir;

  final cwdNative = '${Directory.current.path}/native/linux/x86_64';
  if (Directory(cwdNative).existsSync()) return cwdNative;

  return null;
}

/// Loads the OpenSSL crypto library for the current platform.
DynamicLibrary loadCrypto() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libcrypto.so');
  } else if (Platform.isIOS) {
    return DynamicLibrary.process();
  } else if (Platform.isLinux) {
    final nativeDir = _resolveNativeDir();
    if (nativeDir != null) {
      try {
        return DynamicLibrary.open('$nativeDir/libcrypto.so.4');
      } catch (_) {
        try {
          return DynamicLibrary.open('$nativeDir/libcrypto.so');
        } catch (_) {
        }
      }
    }
    try {
      return DynamicLibrary.open('libcrypto.so.4');
    } catch (_) {
      try {
        return DynamicLibrary.open('libcrypto.so');
      } catch (_) {
        return DynamicLibrary.open('libcrypto.so.3');
      }
    }
  }
  throw UnsupportedError(
    'Platform ${Platform.operatingSystem} is not supported by PluginCrypto.',
  );
}

/// Loads the OpenSSL SSL library for the current platform.
DynamicLibrary loadSsl() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libssl.so');
  } else if (Platform.isIOS) {
    return DynamicLibrary.process();
  } else if (Platform.isLinux) {
    final nativeDir = _resolveNativeDir();
    if (nativeDir != null) {
      try {
        return DynamicLibrary.open('$nativeDir/libssl.so.4');
      } catch (_) {
      }
    }
    try {
      return DynamicLibrary.open('libssl.so.4');
    } catch (_) {
      try {
        return DynamicLibrary.open('libssl.so');
      } catch (_) {
        return DynamicLibrary.open('libssl.so.3');
      }
    }
  }
  throw UnsupportedError(
    'Platform ${Platform.operatingSystem} is not supported by PluginCrypto.',
  );
}
