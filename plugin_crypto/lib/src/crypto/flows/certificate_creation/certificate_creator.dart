library;

import '../../models/crypto_result.dart';
import '../../models/certificate_data.dart';
import 'certificate_request.dart';

abstract interface class CertificateCreator {
  CryptoResult<CertificateData> create(CertificateRequest request);
}
