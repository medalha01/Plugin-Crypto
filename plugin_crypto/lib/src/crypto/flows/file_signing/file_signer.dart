library;

import 'dart:typed_data';

import '../../models/crypto_result.dart';
import '../../models/signing_algorithm.dart';
import 'file_signing_request.dart';

abstract interface class FileSigner {
  CryptoResult<Uint8List> sign(FileSigningRequest request);

  List<SigningAlgorithm> get supportedAlgorithms;
}
