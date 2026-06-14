/// DER→PEM certificate serialization utility.
library;

import 'dart:ffi';
import 'dart:typed_data';

import '../../ffi/openssl_bindings.dart';
import '../models/crypto_error.dart';
import '../models/crypto_result.dart';
import 'bio_utils.dart';
import 'openssl_error.dart';

/// Converts DER-encoded X.509 certificate bytes to PEM format.
CryptoResult<String> derToPem(OpenSslBindings b, Uint8List der) {
  final pemBio = b.bioNew(b.bioSMem());
  if (pemBio == nullptr) {
    return CryptoFailure(CertificateError(reason: 'Failed to create PEM BIO'));
  }

  try {
    final derBio = bioFromData(b, der);
    if (derBio == nullptr) {
      return CryptoFailure(
        CertificateError(
          reason: 'Failed to create DER BIO',
          openSslError: getOpenSslError(b),
        ),
      );
    }
    try {
      final x509 = b.d2iX509Bio(derBio, nullptr);
      if (x509 == nullptr) {
        return CryptoFailure(
          CertificateError(
            reason: 'Failed to parse DER certificate',
            openSslError: getOpenSslError(b),
          ),
        );
      }
      try {
        final writeResult = b.pemWriteBioX509(pemBio, x509);
        if (writeResult != 1) {
          return CryptoFailure(
            CertificateError(
              reason: 'PEM_write_bio_X509 failed',
              openSslError: getOpenSslError(b),
            ),
          );
        }
        final pemBytes = bioToBytes(b, pemBio);
        if (pemBytes.isEmpty) {
          return CryptoFailure(CertificateError(reason: 'Empty PEM output'));
        }
        return CryptoSuccess(String.fromCharCodes(pemBytes));
      } finally {
        b.x509Free(x509);
      }
    } finally {
      b.bioFree(derBio);
    }
  } finally {
    b.bioFree(pemBio);
  }
}
