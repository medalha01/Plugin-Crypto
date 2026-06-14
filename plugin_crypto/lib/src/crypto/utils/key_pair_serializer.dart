/// Canonical EVP_PKEY → KeyPair (PEM) serializer.
/// Eliminates 228 lines of duplicated _extractKeyPair across 4 key creators.
library;

import 'dart:ffi';

import '../../ffi/openssl_bindings.dart';
import '../crypto_data.dart';
import '../models/crypto_result.dart';
import '../models/crypto_error.dart';
import 'bio_utils.dart';
import 'openssl_error.dart';

class KeyPairSerializer {
  final OpenSslBindings _b;

  const KeyPairSerializer(this._b);

  CryptoResult<KeyPair> extract(EVP_PKEY pkey, String keyType) {
    final pubBio = _b.bioNew(_b.bioSMem());
    if (pubBio == nullptr) {
      _b.evpPkeyFree(pkey);
      return _error(keyType, 'Failed to create public key BIO');
    }

    final pubResult = _b.pemWriteBioPubkey(pubBio, pkey);
    if (pubResult != 1) {
      _b.bioFree(pubBio);
      _b.evpPkeyFree(pkey);
      return _error(keyType, 'Failed to write public key');
    }

    final publicKeyPem = bioToString(_b, pubBio);
    _b.bioFree(pubBio);

    final privBio = _b.bioNew(_b.bioSMem());
    if (privBio == nullptr) {
      _b.evpPkeyFree(pkey);
      return _error(keyType, 'Failed to create private key BIO');
    }

    final privResult = _b.pemWriteBioPrivateKey(
      privBio,
      pkey,
      nullptr,
      nullptr,
      0,
      nullptr,
      nullptr,
    );
    _b.evpPkeyFree(pkey); // Free pkey after both extractions

    if (privResult != 1) {
      _b.bioFree(privBio);
      return _error(keyType, 'Failed to write private key');
    }

    final privateKeyPem = bioToString(_b, privBio);
    _b.bioFree(privBio);

    return CryptoSuccess(
      KeyPair(publicKeyPem: publicKeyPem, privateKeyPem: privateKeyPem),
    );
  }

  CryptoFailure<KeyPair> _error(String keyType, String reason) {
    return CryptoFailure(
      KeygenError(
        keyType: keyType,
        reason: reason,
        openSslError: getOpenSslError(_b),
      ),
    );
  }
}
