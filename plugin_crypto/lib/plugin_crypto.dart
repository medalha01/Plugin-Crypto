
library;

export 'src/crypto/crypto_context.dart';
export 'src/crypto/plugin_crypto_context.dart';
export 'src/crypto/crypto_api.dart';
export 'src/crypto/models/crypto_result.dart';
export 'src/crypto/models/crypto_error.dart';
export 'src/crypto/models/key_types.dart';
export 'src/crypto/models/distinguished_name.dart';
export 'src/crypto/models/certificate_data.dart';
export 'src/crypto/models/asn1_data.dart';
export 'src/crypto/models/crl_data.dart';
export 'src/crypto/models/ocsp_data.dart';
export 'src/crypto/models/csr_data.dart';
export 'src/crypto/models/ts_data.dart';
export 'src/crypto/models/signing_algorithm.dart';
export 'src/crypto/extensions/key_pair_extensions.dart';
export 'src/crypto/flows/key_creation/key_creator.dart';
export 'src/crypto/flows/key_creation/key_creator_factory.dart';
export 'src/crypto/flows/key_creation/ml_kem_key_creator.dart';
export 'src/crypto/flows/key_creation/ml_dsa_key_creator.dart';
export 'src/crypto/flows/certificate_creation/certificate_request.dart';
export 'src/crypto/flows/certificate_creation/certificate_builder.dart';
export 'src/crypto/flows/certificate_creation/certificate_creator.dart';
export 'src/crypto/flows/certificate_chain/chain_verifier.dart';
export 'src/crypto/flows/certificate_chain/chain_verification_request.dart';
export 'src/crypto/flows/certificate_chain/openssl_chain_verifier.dart';
export 'src/crypto/flows/file_signing/file_signer.dart';
export 'src/crypto/flows/file_signing/file_signing_request.dart';
export 'src/crypto/utils/x509_ext_parser.dart';
export 'src/crypto/flows/asn1/asn1_parser.dart';
export 'src/crypto/flows/asn1/openssl_asn1_parser.dart';
export 'src/crypto/flows/revocation/crl_verifier.dart';
export 'src/crypto/flows/revocation/ocsp_verifier.dart';
export 'src/crypto/flows/csr/csr_generator.dart';
export 'src/crypto/flows/csr/openssl_csr_generator.dart';
export 'src/crypto/flows/timestamp/timestamp_client.dart';
export 'src/crypto/flows/timestamp/openssl_timestamp_client.dart';

import 'plugin_crypto_platform_interface.dart';
import 'src/crypto/crypto_api.dart';

PluginCryptoAPI get crypto => PluginCryptoAPI.instance;

/// PluginCrypto — classe de conveniência que expõe informações de criptografia e plataforma.
class PluginCrypto {
  PluginCrypto._();

  static final PluginCrypto _instance = PluginCrypto._();

  /// Instância singleton.
  static PluginCrypto get instance => _instance;

  /// Acessa a API criptográfica nativa completa.
  PluginCryptoAPI get api => PluginCryptoAPI.instance;

  /// Retorna a versão da plataforma (Android/Linux).
  Future<String?> getPlatformVersion() {
    return PluginCryptoPlatform.instance.getPlatformVersion();
  }
}
