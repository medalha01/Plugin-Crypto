/// Canonical X.509/CRL PEM→DER loader with fallback.
library;

import 'dart:ffi';
import 'dart:typed_data';

import '../../ffi/openssl_bindings.dart';
import 'bio_utils.dart';

/// Loads a certificate from PEM or DER data.
/// Tries PEM first, falls back to DER on failure.
X509 loadX509(OpenSslBindings b, Uint8List data) {
  final pemBio = bioFromData(b, data);
  final x509 = b.pemReadBioX509(pemBio, nullptr, nullptr, nullptr);
  b.bioFree(pemBio);

  if (x509 != nullptr) return x509;

  b.errClearError();
  final derBio = bioFromData(b, data);
  final derX509 = b.d2iX509Bio(derBio, nullptr);
  b.bioFree(derBio);
  return derX509;
}

/// Loads a CRL from PEM or DER data.
X509_CRL loadCrl(OpenSslBindings b, Uint8List data) {
  final pemBio = bioFromData(b, data);
  final crl = b.pemReadBioX509Crl(pemBio, nullptr, nullptr, nullptr);
  b.bioFree(pemBio);

  if (crl != nullptr) return crl;

  b.errClearError();
  final derBio = bioFromData(b, data);
  final derCrl = b.d2iX509CrlBio(derBio, nullptr);
  b.bioFree(derBio);
  return derCrl;
}
