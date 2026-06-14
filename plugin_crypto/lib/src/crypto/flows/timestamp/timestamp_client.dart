library;

import 'dart:typed_data';

import '../../models/crypto_result.dart';
import '../../models/ts_data.dart';

abstract interface class TimestampClient {
  CryptoResult<Uint8List> createRequest(
    Uint8List data, {
    String hashAlgorithm,
    Uint8List? nonce,
  });

  CryptoResult<TimestampResponse> verifyResponse(
    Uint8List responseData, {
    Uint8List? cert,
  });

  CryptoResult<bool> verify(Uint8List tokenData, Uint8List data);
}
