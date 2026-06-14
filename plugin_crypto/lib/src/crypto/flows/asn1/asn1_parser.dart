library;

import 'dart:typed_data';

import '../../models/asn1_data.dart';
import '../../models/crypto_result.dart';

abstract interface class Asn1Parser {
  CryptoResult<Asn1Node> parse(Uint8List derData);
}
