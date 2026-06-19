library;

import 'dart:ffi';

import '../ffi/openssl_bindings.dart';

class ZeroizationVerifier {
  static bool isOpensslCleanseBound(OpenSslBindings bindings) {
    try {
      bindings.opensslCleanse;
      return true;
    } catch (_) {
      return false;
    }
  }

  static bool isCryptoFreeBound(OpenSslBindings bindings) {
    try {
      bindings.cryptoFree;
      return true;
    } catch (_) {
      return false;
    }
  }

  static bool isFipsProviderActive(OpenSslBindings bindings) {
    try {
      final result = bindings.evpDefaultPropertiesIsFips(nullptr);
      return result == 1;
    } catch (_) {
      return false;
    }
  }

}
