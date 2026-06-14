library;

import 'models/crypto_result.dart';
import 'models/csr_data.dart';
import 'flows/csr/csr_generator.dart';
import 'flows/csr/openssl_csr_generator.dart';
import 'crypto_context.dart';

class CsrOperations {
  final CsrGenerator _generator;

  /// Creates [CsrOperations] using the given [CryptoContext].
  CsrOperations(CryptoContext ctx)
    : _generator = OpenSslCsrGenerator(ctx);

  CryptoResult<CsrData> generate(CsrRequest request) =>
      _generator.generate(request);
}
