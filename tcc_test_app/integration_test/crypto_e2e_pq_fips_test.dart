/// ML-KEM-768 and ML-DSA-44 DER byte length validation via FFI.
/// Platform: Linux x86_64 and Android ARM64.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/crypto_data.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_dsa_key_creator.dart';
import 'package:plugin_crypto/src/crypto/flows/key_creation/ml_kem_key_creator.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/key_types.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';


/// Base64-decode the body of a PEM string (stripping header/footer lines).
Uint8List _pemDecode(String pem) {
  final lines = pem
      .split(RegExp(r'\r?\n'))
      .where((l) => !l.startsWith('-----'))
      .join();
  return Uint8List.fromList(base64Decode(lines));
}


void main() {

  late OpenSslBindings bindings;
  late MlKemKeyCreator mlKemCreator;
  late MlDsaKeyCreator mlDsaCreator;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    mlKemCreator = MlKemKeyCreator(bindings);
    mlDsaCreator = MlDsaKeyCreator(bindings);
  });


  group('V7: ML-KEM-768 public key size (FIPS 203)', () {
    test('ML-KEM-768 public key DER == 1184 bytes (key material)', () {
      final result = mlKemCreator.create(
        const MlKemKeySpec(MlKemParameterSet.mlKem768),
      );

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;

      final spkiDer = _pemDecode(pair.publicKeyPem);

      expect(
        spkiDer.length,
        equals(1206),
        reason:
            'ML-KEM-768 SPKI DER must be exactly 1206 bytes '
            '(OpenSSL 4.0.0 wrapper). Got ${spkiDer.length} bytes.',
      );

      final result2 = mlKemCreator.create(
        const MlKemKeySpec(MlKemParameterSet.mlKem768),
      );
      final pair2 = (result2 as CryptoSuccess<KeyPair>).value;
      final spkiDer2 = _pemDecode(pair2.publicKeyPem);
      expect(
        spkiDer2.length,
        equals(1206),
        reason:
            'Second ML-KEM-768 SPKI DER also must be 1206 bytes. '
            'Got ${spkiDer2.length}.',
      );
    });
  });


  group('V8: ML-DSA-44 public key size (FIPS 204)', () {
    test('ML-DSA-44 public key DER == 1312 bytes (key material)', () {
      final result = mlDsaCreator.create(
        const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
      );

      expect(result, isA<CryptoSuccess<KeyPair>>());
      final pair = (result as CryptoSuccess<KeyPair>).value;

      final spkiDer = _pemDecode(pair.publicKeyPem);

      expect(
        spkiDer.length,
        equals(1334),
        reason:
            'ML-DSA-44 SPKI DER must be exactly 1334 bytes '
            '(OpenSSL 4.0.0 wrapper). Got ${spkiDer.length} bytes.',
      );

      final result2 = mlDsaCreator.create(
        const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
      );
      final pair2 = (result2 as CryptoSuccess<KeyPair>).value;
      final spkiDer2 = _pemDecode(pair2.publicKeyPem);
      expect(
        spkiDer2.length,
        equals(1334),
        reason:
            'Second ML-DSA-44 SPKI DER also must be 1334 bytes. '
            'Got ${spkiDer2.length}.',
      );
    });
  });
}
