library;

import 'dart:typed_data';

import 'flows/timestamp/openssl_timestamp_client.dart';
import 'flows/timestamp/timestamp_client.dart';
import 'models/crypto_result.dart';
import 'models/ts_data.dart';
import 'crypto_context.dart';

class TimestampOperations {
  final TimestampClient _client;

  /// Creates [TimestampOperations] using the given [CryptoContext].
  TimestampOperations(CryptoContext ctx)
    : _client = OpenSslTimestampClient(ctx);

  CryptoResult<Uint8List> createRequest(
    Uint8List data, {
    String hashAlgorithm = 'sha256',
    Uint8List? nonce,
  }) => _client.createRequest(
    data,
    hashAlgorithm: hashAlgorithm,
    nonce: nonce,
  );

  CryptoResult<TimestampResponse> verifyResponse(
    Uint8List responseData, {
    Uint8List? cert,
  }) => _client.verifyResponse(responseData, cert: cert);

  CryptoResult<bool> verify(Uint8List tokenData, Uint8List data) =>
      _client.verify(tokenData, data);
}
