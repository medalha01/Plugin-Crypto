library;

import '../../models/crypto_result.dart';
import '../../models/csr_data.dart';

abstract interface class CsrGenerator {
  CryptoResult<CsrData> generate(CsrRequest request);
}
