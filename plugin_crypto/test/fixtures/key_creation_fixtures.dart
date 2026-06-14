library;

import 'package:plugin_crypto/src/crypto/models/key_types.dart';


final validRsa2048Spec = RsaKeySpec(2048);
final validRsa4096Spec = RsaKeySpec(4096);
final validRsa3072Spec = RsaKeySpec(3072);
final validEcP256Spec = EcKeySpec('prime256v1');
final validEcP384Spec = EcKeySpec('secp384r1');
final validEcP521Spec = EcKeySpec('secp521r1');


/// Bits too small (< 1024).  Construction should throw [ArgumentError].
RsaKeySpec get invalidRsaTooSmallSpec {
  try {
    return RsaKeySpec(512);
  } on ArgumentError {
    return RsaKeySpec(2048);
  }
}

/// Bits not a multiple of 1024.
RsaKeySpec get invalidRsaNonMultipleSpec {
  try {
    return RsaKeySpec(1536);
  } on ArgumentError {
    return RsaKeySpec(2048);
  }
}

/// Unsupported curve name.
EcKeySpec get invalidEcSpec {
  try {
    return EcKeySpec('brainpoolP256r1');
  } on ArgumentError {
    return EcKeySpec('prime256v1');
  }
}


final allValidRsaSpecs = [validRsa2048Spec, validRsa3072Spec, validRsa4096Spec];

final allValidEcSpecs = [validEcP256Spec, validEcP384Spec, validEcP521Spec];
