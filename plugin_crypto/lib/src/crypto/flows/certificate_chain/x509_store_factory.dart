library;

import 'dart:ffi';
import 'dart:typed_data';

import '../../../ffi/openssl_bindings.dart';
import '../../utils/bio_utils.dart';
import '../../utils/openssl_error.dart';

/// Creates and populates OpenSSL trust stores.
class X509StoreFactory {
  final OpenSslBindings _b;

  /// Creates a factory backed by the given bindings.
  X509StoreFactory(this._b);

  Pointer<Void> createStore({List<Uint8List>? trustedCerts}) {
    final store = _b.x509StoreNew();
    if (store == nullptr) {
      throw StateError('X509_STORE_new returned null');
    }
    if (trustedCerts != null) {
      for (final cert in trustedCerts) {
        addCert(store, cert);
      }
    }
    return store;
  }

  void addCert(Pointer<Void> store, Uint8List certPem) {
    final bio = bioFromData(_b, certPem);
    if (bio == nullptr) {
      throw StateError('BIO_new(addCert) failed');
    }
    try {
      final x509 = _b.pemReadBioX509(bio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) {
        final err = getOpenSslError(_b);
        _b.errClearError();
        throw StateError(
          'Failed to parse certificate${err != null ? ': $err' : ''}',
        );
      }
      try {
        final result = _b.x509StoreAddCert(store, x509);
        if (result != 1) {
          final err = getOpenSslError(_b);
          _b.errClearError();
          throw StateError(
            'X509_STORE_add_cert failed${err != null ? ': $err' : ''}',
          );
        }
      } finally {
        _b.x509Free(x509);
      }
    } finally {
      _b.bioFree(bio);
    }
  }
}
