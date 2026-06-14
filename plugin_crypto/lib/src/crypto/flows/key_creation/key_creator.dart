library;

import '../../crypto_api.dart';
import '../../models/crypto_result.dart';
import '../../models/key_types.dart';

abstract class KeyCreator {
  CryptoResult<KeyPair> create(KeySpec spec);

  List<KeySpec> get supportedSpecs;
}
