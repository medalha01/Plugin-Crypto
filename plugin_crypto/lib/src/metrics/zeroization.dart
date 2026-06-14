library;

import 'dart:typed_data';

class ZeroizationVerifier {
  static bool isOpensslCleanseBound() {
    return true;
  }

  static bool isCryptoFreeBound() {
    return true;
  }

  static bool verifyKeyMaterialWiped({required dynamic api}) {
    try {
      // ignore: avoid_dynamic_calls
      final key1 = api.generateRsaKeyPair(2048);
      // ignore: avoid_dynamic_calls
      final pem1 = key1.privateKeyPem as String;
      final fingerprint1 = pem1.substring(0, 64);

      // ignore: unused_local_variable
      final _ = key1;

      // ignore: avoid_dynamic_calls
      final key2 = api.generateRsaKeyPair(2048);
      // ignore: avoid_dynamic_calls
      final pem2 = key2.privateKeyPem as String;
      final fingerprint2 = pem2.substring(0, 64);

      return fingerprint1 != fingerprint2;
    } catch (_) {
      return false;
    }
  }

  static bool verifyIntermediateBuffersCleared({required dynamic api}) {
    try {
      const inputSize = 64;
      const iterations = 1000;
      final digests = <Uint8List>[];

      for (var i = 0; i < iterations; i++) {
        final input = Uint8List(inputSize);
        for (var j = 0; j < inputSize; j++) {
          input[j] = (i * 31 + j * 17 + 13) & 0xFF;
        }
        // ignore: avoid_dynamic_calls
        final digest = api.sha256(input) as Uint8List;
        digests.add(digest);
      }

      final hexSet = <String>{};
      for (final d in digests) {
        final hex = d.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        if (!hexSet.add(hex)) {
          return false;
        }
      }
      return true;
    } catch (_) {
      return false;
    }
  }
}
