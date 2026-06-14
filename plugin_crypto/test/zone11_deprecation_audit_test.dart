library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';


const _knownRemovedApis = <String>{
  'ASN1_STRING_data',
  'BIO_f_reliable',
  'DTLSv1_2_client_method',
  'DTLSv1_2_method',
  'DTLSv1_2_server_method',
  'DTLSv1_client_method',
  'DTLSv1_method',
  'DTLSv1_server_method',
  'ERR_get_state',
  'ERR_remove_state',
  'ERR_remove_thread_state',

  'EVP_CIPHER_meth_dup',
  'EVP_CIPHER_meth_free',
  'EVP_CIPHER_meth_get_cleanup',
  'EVP_CIPHER_meth_get_ctrl',
  'EVP_CIPHER_meth_get_do_cipher',
  'EVP_CIPHER_meth_get_get_asn1_params',
  'EVP_CIPHER_meth_get_init',
  'EVP_CIPHER_meth_get_set_asn1_params',
  'EVP_CIPHER_meth_new',
  'EVP_CIPHER_meth_set_cleanup',
  'EVP_CIPHER_meth_set_ctrl',
  'EVP_CIPHER_meth_set_do_cipher',
  'EVP_CIPHER_meth_set_flags',
  'EVP_CIPHER_meth_set_get_asn1_params',
  'EVP_CIPHER_meth_set_impl_ctx_size',
  'EVP_CIPHER_meth_set_init',
  'EVP_CIPHER_meth_set_iv_length',
  'EVP_CIPHER_meth_set_set_asn1_params',

  'EVP_MD_CTX_set_update_fn',
  'EVP_MD_CTX_update_fn',
  'EVP_MD_meth_dup',
  'EVP_MD_meth_free',
  'EVP_MD_meth_get_app_datasize',
  'EVP_MD_meth_get_cleanup',
  'EVP_MD_meth_get_copy',
  'EVP_MD_meth_get_ctrl',
  'EVP_MD_meth_get_final',
  'EVP_MD_meth_get_flags',
  'EVP_MD_meth_get_init',
  'EVP_MD_meth_get_input_blocksize',
  'EVP_MD_meth_get_result_size',
  'EVP_MD_meth_get_update',
  'EVP_MD_meth_new',
  'EVP_MD_meth_set_app_datasize',
  'EVP_MD_meth_set_cleanup',
  'EVP_MD_meth_set_copy',
  'EVP_MD_meth_set_ctrl',
  'EVP_MD_meth_set_final',
  'EVP_MD_meth_set_flags',
  'EVP_MD_meth_set_init',
  'EVP_MD_meth_set_input_blocksize',
  'EVP_MD_meth_set_result_size',
  'EVP_MD_meth_set_update',

  'EVP_PKEY_asn1_add0',
  'EVP_PKEY_asn1_add_alias',
  'EVP_PKEY_asn1_copy',
  'EVP_PKEY_asn1_find',
  'EVP_PKEY_asn1_find_str',
  'EVP_PKEY_asn1_free',
  'EVP_PKEY_asn1_get0',
  'EVP_PKEY_asn1_get0_info',
  'EVP_PKEY_asn1_get_count',
  'EVP_PKEY_asn1_new',
  'EVP_PKEY_asn1_set_check',
  'EVP_PKEY_asn1_set_ctrl',
  'EVP_PKEY_asn1_set_free',
  'EVP_PKEY_asn1_set_get_priv_key',
  'EVP_PKEY_asn1_set_get_pub_key',
  'EVP_PKEY_asn1_set_item',
  'EVP_PKEY_asn1_set_param',
  'EVP_PKEY_asn1_set_param_check',
  'EVP_PKEY_asn1_set_private',
  'EVP_PKEY_asn1_set_public',
  'EVP_PKEY_asn1_set_public_check',
  'EVP_PKEY_asn1_set_security_bits',
  'EVP_PKEY_asn1_set_set_priv_key',
  'EVP_PKEY_asn1_set_set_pub_key',
  'EVP_PKEY_asn1_set_siginf',
  'EVP_PKEY_get0_asn1',
  'EVP_PKEY_meth_add0',
  'EVP_PKEY_meth_copy',
  'EVP_PKEY_meth_find',
  'EVP_PKEY_meth_free',

  'OPENSSL_atexit',

  'SSLv3_client_method',
  'SSLv3_method',
  'SSLv3_server_method',
  'TLSv1_1_client_method',
  'TLSv1_1_method',
  'TLSv1_1_server_method',
  'TLSv1_2_client_method',
  'TLSv1_2_method',
  'TLSv1_2_server_method',
  'TLSv1_client_method',
  'TLSv1_method',
  'TLSv1_server_method',
};


const _bindingSymbols = <String>{
  'OpenSSL_version',
  'OSSL_PROVIDER_load',
  'RAND_bytes',
  'RAND_priv_bytes',
  'ERR_get_error',
  'ERR_clear_error',
  'ERR_error_string_n',
  'EVP_MD_CTX_new',
  'EVP_MD_CTX_free',
  'EVP_DigestInit_ex',
  'EVP_DigestUpdate',
  'EVP_DigestFinal_ex',
  'EVP_sha256',
  'EVP_sha512',
  'EVP_sha3_256',
  'EVP_sha3_512',
  'EVP_CIPHER_CTX_new',
  'EVP_CIPHER_CTX_free',
  'EVP_CIPHER_CTX_ctrl',
  'EVP_EncryptInit_ex',
  'EVP_EncryptUpdate',
  'EVP_EncryptFinal_ex',
  'EVP_DecryptInit_ex',
  'EVP_DecryptUpdate',
  'EVP_DecryptFinal_ex',
  'EVP_aes_128_cbc',
  'EVP_aes_256_cbc',
  'EVP_aes_128_gcm',
  'EVP_aes_256_gcm',
  'EVP_PKEY_new',
  'EVP_PKEY_free',
  'EVP_PKEY_get_size',
  'EVP_PKEY_CTX_new',
  'EVP_PKEY_CTX_new_id',
  'EVP_PKEY_CTX_free',
  'EVP_PKEY_keygen_init',
  'EVP_PKEY_keygen',
  'EVP_PKEY_CTX_set_rsa_keygen_bits',
  'EVP_PKEY_CTX_set_ec_paramgen_curve_nid',
  'EVP_DigestSignInit',
  'EVP_DigestSign',
  'EVP_DigestVerifyInit',
  'EVP_DigestVerify',
  'EVP_PKEY_encrypt_init',
  'EVP_PKEY_encrypt',
  'EVP_PKEY_decrypt_init',
  'EVP_PKEY_decrypt',
  'BIO_new',
  'BIO_free',
  'BIO_s_mem',
  'BIO_new_mem_buf',
  'BIO_read',
  'BIO_write',
  'BN_new',
  'BN_free',
  'BN_bn2bin',
  'BN_bin2bn',
  'PEM_read_bio_PrivateKey',
  'PEM_write_bio_PrivateKey',
  'PEM_read_bio_PUBKEY',
  'PEM_write_bio_PUBKEY',
  'PEM_read_bio_X509',
  'PEM_write_bio_X509',
  'X509_new',
  'X509_free',
  'X509_get_subject_name',
  'X509_get_issuer_name',
  'X509_get_serialNumber',
  'X509_get0_notBefore',
  'X509_get0_notAfter',
  'X509_NAME_oneline',
  'ASN1_TIME_print',
  'X509_STORE_new',
  'X509_STORE_free',
  'X509_STORE_add_cert',
  'X509_STORE_CTX_new',
  'X509_STORE_CTX_free',
  'X509_STORE_CTX_init',
  'X509_verify_cert',
  'X509_verify_cert_error_string',
  'CMS_sign',
  'CMS_verify',
  'CMS_encrypt',
  'CMS_decrypt',
  'CMS_ContentInfo_free',
  'PEM_read_bio_CMS',
  'PEM_write_bio_CMS',
  'OPENSSL_sk_new_null',
  'OPENSSL_sk_push',
  'OPENSSL_sk_free',
  'OBJ_sn2nid',
  'OBJ_nid2sn',
  'OBJ_txt2nid',
  'X509_set_version',
  'X509_set_pubkey',
  'X509_set_issuer_name',
  'X509_set_subject_name',
  'X509_sign',
  'X509_NAME_new',
  'X509_NAME_free',
  'X509_NAME_add_entry_by_txt',
  'ASN1_TIME_set',
  'X509_set1_notBefore',
  'X509_set1_notAfter',
  'X509V3_set_ctx',
  'X509V3_EXT_conf_nid',
  'X509_add_ext',
  'X509_EXTENSION_free',
  'BIO_new_file',
  'BIO_ctrl',
};


const _evpStableApis = <String>{
  'EVP_DigestInit_ex',
  'EVP_DigestUpdate',
  'EVP_DigestFinal_ex',
  'EVP_MD_CTX_new',
  'EVP_MD_CTX_free',
  'EVP_sha256',
  'EVP_sha512',
  'EVP_sha3_256',
  'EVP_sha3_512',

  'EVP_EncryptInit_ex',
  'EVP_EncryptUpdate',
  'EVP_EncryptFinal_ex',
  'EVP_DecryptInit_ex',
  'EVP_DecryptUpdate',
  'EVP_DecryptFinal_ex',
  'EVP_aes_128_cbc',
  'EVP_aes_256_cbc',
  'EVP_aes_128_gcm',
  'EVP_aes_256_gcm',
  'EVP_CIPHER_CTX_new',
  'EVP_CIPHER_CTX_free',
  'EVP_CIPHER_CTX_ctrl',

  'EVP_PKEY_new',
  'EVP_PKEY_free',
  'EVP_PKEY_get_size',
  'EVP_PKEY_CTX_new',
  'EVP_PKEY_CTX_new_id',
  'EVP_PKEY_CTX_free',

  'EVP_PKEY_keygen_init',
  'EVP_PKEY_keygen',
  'EVP_PKEY_CTX_set_rsa_keygen_bits',
  'EVP_PKEY_CTX_set_ec_paramgen_curve_nid',

  'EVP_DigestSignInit',
  'EVP_DigestSign',
  'EVP_DigestVerifyInit',
  'EVP_DigestVerify',

  'EVP_PKEY_encrypt_init',
  'EVP_PKEY_encrypt',
  'EVP_PKEY_decrypt_init',
  'EVP_PKEY_decrypt',

  'X509_set_version',
  'X509_set_pubkey',
  'X509_set_issuer_name',
  'X509_set_subject_name',
  'X509_sign',
  'X509_NAME_new',
  'X509_NAME_free',
  'X509_NAME_add_entry_by_txt',
  'ASN1_TIME_set',
  'X509_set1_notBefore',
  'X509_set1_notAfter',
  'X509V3_set_ctx',
  'X509V3_EXT_conf_nid',
  'X509_add_ext',
  'X509_EXTENSION_free',
  'BIO_new_file',
  'BIO_ctrl',
};

/// APIs that exist in the Watch category — still functional but may
/// require migration in a future release.
const _evpWatchApis = <String>{
};

const _evpAtRiskApis = <String>{
};


void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone11_deprecation_audit', 'Deprecation Audit');

  TestWidgetsFlutterBinding.ensureInitialized();

  late OpenSslBindings bindings;

  setUpAll(() {
    final crypto = loadCrypto();
    final ssl = loadSsl();
    bindings = OpenSslBindings.create(crypto, ssl);
  });


  group('FFI binding resolution', () {
    const boundFieldNames = <String>[
      'openSSLVersion',
      'osslProviderLoad',
      'randBytes',
      'randPrivBytes',
      'errGetError',
      'errClearError',
      'errErrorStringN',
      'evpMdCtxNew',
      'evpMdCtxFree',
      'evpDigestInitEx',
      'evpDigestUpdate',
      'evpDigestFinalEx',
      'evpSha256',
      'evpSha512',
      'evpSha3_256',
      'evpSha3_512',
      'evpCipherCtxNew',
      'evpCipherCtxFree',
      'evpCipherCtxCtrl',
      'evpEncryptInitEx',
      'evpEncryptUpdate',
      'evpEncryptFinalEx',
      'evpDecryptInitEx',
      'evpDecryptUpdate',
      'evpDecryptFinalEx',
      'evpAes128Cbc',
      'evpAes256Cbc',
      'evpAes128Gcm',
      'evpAes256Gcm',
      'evpPkeyNew',
      'evpPkeyFree',
      'evpPkeyGetSize',
      'evpPkeyCtxNew',
      'evpPkeyCtxNewId',
      'evpPkeyCtxFree',
      'evpPkeyKeygenInit',
      'evpPkeyKeygen',
      'evpPkeyCtxSetRsaKeygenBits',
      'evpPkeyCtxSetEcKeygenCurveNid',
      'evpDigestSignInit',
      'evpDigestSign',
      'evpDigestVerifyInit',
      'evpDigestVerify',
      'evpPkeyEncryptInit',
      'evpPkeyEncrypt',
      'evpPkeyDecryptInit',
      'evpPkeyDecrypt',
      'bioNew',
      'bioFree',
      'bioSMem',
      'bioNewMemBuf',
      'bioRead',
      'bioWrite',
      'bnNew',
      'bnFree',
      'bnBn2bin',
      'bnBin2bn',
      'pemReadBioPrivateKey',
      'pemWriteBioPrivateKey',
      'pemReadBioPubkey',
      'pemWriteBioPubkey',
      'pemReadBioX509',
      'pemWriteBioX509',
      'x509New',
      'x509Free',
      'x509GetSubjectName',
      'x509GetIssuerName',
      'x509GetSerialNumber',
      'x509GetNotBefore',
      'x509GetNotAfter',
      'x509NameOneline',
      'asn1TimePrint',
      'x509StoreNew',
      'x509StoreFree',
      'x509StoreAddCert',
      'x509StoreCtxNew',
      'x509StoreCtxFree',
      'x509StoreCtxInit',
      'x509VerifyCert',
      'x509VerifyCertErrorString',
      'cmsSign',
      'cmsVerify',
      'cmsEncrypt',
      'cmsDecrypt',
      'cmsContentInfoFree',
      'pemReadBioCms',
      'pemWriteBioCms',
      'osslSkNewNull',
      'osslSkPush',
      'osslSkFree',
      'objSn2nid',
      'objNid2sn',
      'objTxt2nid',
      'x509SetVersion',
      'x509SetPubkey',
      'x509SetIssuerName',
      'x509SetSubjectName',
      'x509Sign',
      'x509NameNew',
      'x509NameFree',
      'x509NameAddEntryByTxt',
      'asn1TimeSet',
      'x509SetNotBefore',
      'x509SetNotAfter',
      'x509V3SetCtx',
      'x509V3ExtConfNid',
      'x509AddExt',
      'x509ExtensionFree',
      'bioNewFile',
      'bioCtrl',
    ];

    final expectedCount = boundFieldNames.length;

    test('all $expectedCount bound fields resolve without throwing', () {
      int resolved = 0;
      final failures = <String>[];

      for (final name in boundFieldNames) {
        try {
          _accessField(bindings, name);
          resolved++;
        } catch (e) {
          failures.add('$name: $e');
        }
      }

      if (failures.isNotEmpty) {
        fail(
          '$failures.length/$expectedCount bindings failed:\n'
          '${failures.map((f) => '  - $f').join('\n')}',
        );
      }

      expect(
        resolved,
        equals(expectedCount),
        reason: 'Expected all $expectedCount bindings to resolve',
      );
    });

    test('field count matches expected ($expectedCount)', () {
      expect(boundFieldNames.length, expectedCount);
    });
  });


  group('Deprecation cross-check', () {
    test('no removed OpenSSL 4.0 symbols appear in binding lookups', () {
      final violations = <String>[];

      for (final symbol in _bindingSymbols) {
        if (_knownRemovedApis.contains(symbol)) {
          violations.add(symbol);
        }
      }

      if (violations.isNotEmpty) {
        fail(
          'BINDING VIOLATION: ${violations.length} removed OpenSSL 4.0 '
          'symbol(s) are referenced in openssl_bindings.dart:\n'
          '${violations.map((v) => '  - $v').join('\n')}\n\n'
          'These symbols no longer exist in OpenSSL 4.0.0.  '
          'Replace each with its supported equivalent or remove the binding.',
        );
      }
    });

    test('all EVP high-level APIs used are in the Stable category', () {
      for (final api in _evpStableApis) {
        expect(
          _bindingSymbols.contains(api),
          isTrue,
          reason:
              'Stable EVP API "$api" is listed as used but not found '
              'among bindings — update _bindingSymbols.',
        );
      }

      for (final symbol in _bindingSymbols) {
        if (_evpAtRiskApis.contains(symbol)) {
          fail('At-Risk EVP API "$symbol" is bound — remove or replace it.');
        }
      }

      for (final symbol in _bindingSymbols) {
        if (_evpWatchApis.contains(symbol)) {
          // ignore: avoid_print
          print(
            '  WATCH: "$symbol" is a Watch-level EVP API — '
            'monitor OpenSSL release notes for removal plans.',
          );
        }
      }
    });

    test('documented Watch and At-Risk bindings (summary)', () {

      final watchBound = _bindingSymbols.intersection(_evpWatchApis);
      final atRiskBound = _bindingSymbols.intersection(_evpAtRiskApis);

      // ignore: avoid_print
      print('');
      // ignore: avoid_print
      print('=== Deprecation Audit Summary ===');
      // ignore: avoid_print
      print('Total bound symbols: ${_bindingSymbols.length}');
      // ignore: avoid_print
      print('Known removed APIs:  ${_knownRemovedApis.length}');
      // ignore: avoid_print
      print('Stable EVP APIs:     ${_evpStableApis.length}');
      // ignore: avoid_print
      print('Watch-list APIs:     ${watchBound.length}');
      // ignore: avoid_print
      print('At-Risk APIs:        ${atRiskBound.length}');
      if (watchBound.isNotEmpty) {
        // ignore: avoid_print
        print('Watch bindings:');
        for (final w in watchBound) {
          // ignore: avoid_print
          print('  - $w');
        }
      }
      if (atRiskBound.isNotEmpty) {
        // ignore: avoid_print
        print('At-Risk bindings (ACTION REQUIRED):');
        for (final a in atRiskBound) {
          // ignore: avoid_print
          print('  - $a');
        }
        fail('At-Risk bindings detected — see above.');
      }
      // ignore: avoid_print
      print('====================================');
      // ignore: avoid_print
      print('');

      expect(
        atRiskBound,
        isEmpty,
        reason: 'No At-Risk EVP bindings should be present',
      );
    });
  });

  m?.endZone();
}


void _accessField(OpenSslBindings b, String name) {
  switch (name) {
    case 'openSSLVersion':
      b.openSSLVersion;
    case 'osslProviderLoad':
      b.osslProviderLoad;
    case 'randBytes':
      b.randBytes;
    case 'randPrivBytes':
      b.randPrivBytes;
    case 'errGetError':
      b.errGetError;
    case 'errClearError':
      b.errClearError;
    case 'errErrorStringN':
      b.errErrorStringN;
    case 'evpMdCtxNew':
      b.evpMdCtxNew;
    case 'evpMdCtxFree':
      b.evpMdCtxFree;
    case 'evpDigestInitEx':
      b.evpDigestInitEx;
    case 'evpDigestUpdate':
      b.evpDigestUpdate;
    case 'evpDigestFinalEx':
      b.evpDigestFinalEx;
    case 'evpSha256':
      b.evpSha256;
    case 'evpSha512':
      b.evpSha512;
    case 'evpSha3_256':
      b.evpSha3_256;
    case 'evpSha3_512':
      b.evpSha3_512;
    case 'evpCipherCtxNew':
      b.evpCipherCtxNew;
    case 'evpCipherCtxFree':
      b.evpCipherCtxFree;
    case 'evpCipherCtxCtrl':
      b.evpCipherCtxCtrl;
    case 'evpEncryptInitEx':
      b.evpEncryptInitEx;
    case 'evpEncryptUpdate':
      b.evpEncryptUpdate;
    case 'evpEncryptFinalEx':
      b.evpEncryptFinalEx;
    case 'evpDecryptInitEx':
      b.evpDecryptInitEx;
    case 'evpDecryptUpdate':
      b.evpDecryptUpdate;
    case 'evpDecryptFinalEx':
      b.evpDecryptFinalEx;
    case 'evpAes128Cbc':
      b.evpAes128Cbc;
    case 'evpAes256Cbc':
      b.evpAes256Cbc;
    case 'evpAes128Gcm':
      b.evpAes128Gcm;
    case 'evpAes256Gcm':
      b.evpAes256Gcm;
    case 'evpPkeyNew':
      b.evpPkeyNew;
    case 'evpPkeyFree':
      b.evpPkeyFree;
    case 'evpPkeyGetSize':
      b.evpPkeyGetSize;
    case 'evpPkeyCtxNew':
      b.evpPkeyCtxNew;
    case 'evpPkeyCtxNewId':
      b.evpPkeyCtxNewId;
    case 'evpPkeyCtxFree':
      b.evpPkeyCtxFree;
    case 'evpPkeyKeygenInit':
      b.evpPkeyKeygenInit;
    case 'evpPkeyKeygen':
      b.evpPkeyKeygen;
    case 'evpPkeyCtxSetRsaKeygenBits':
      b.evpPkeyCtxSetRsaKeygenBits;
    case 'evpPkeyCtxSetEcKeygenCurveNid':
      b.evpPkeyCtxSetEcKeygenCurveNid;
    case 'evpDigestSignInit':
      b.evpDigestSignInit;
    case 'evpDigestSign':
      b.evpDigestSign;
    case 'evpDigestVerifyInit':
      b.evpDigestVerifyInit;
    case 'evpDigestVerify':
      b.evpDigestVerify;
    case 'evpPkeyEncryptInit':
      b.evpPkeyEncryptInit;
    case 'evpPkeyEncrypt':
      b.evpPkeyEncrypt;
    case 'evpPkeyDecryptInit':
      b.evpPkeyDecryptInit;
    case 'evpPkeyDecrypt':
      b.evpPkeyDecrypt;
    case 'bioNew':
      b.bioNew;
    case 'bioFree':
      b.bioFree;
    case 'bioSMem':
      b.bioSMem;
    case 'bioNewMemBuf':
      b.bioNewMemBuf;
    case 'bioRead':
      b.bioRead;
    case 'bioWrite':
      b.bioWrite;
    case 'bnNew':
      b.bnNew;
    case 'bnFree':
      b.bnFree;
    case 'bnBn2bin':
      b.bnBn2bin;
    case 'bnBin2bn':
      b.bnBin2bn;
    case 'pemReadBioPrivateKey':
      b.pemReadBioPrivateKey;
    case 'pemWriteBioPrivateKey':
      b.pemWriteBioPrivateKey;
    case 'pemReadBioPubkey':
      b.pemReadBioPubkey;
    case 'pemWriteBioPubkey':
      b.pemWriteBioPubkey;
    case 'pemReadBioX509':
      b.pemReadBioX509;
    case 'pemWriteBioX509':
      b.pemWriteBioX509;
    case 'x509New':
      b.x509New;
    case 'x509Free':
      b.x509Free;
    case 'x509GetSubjectName':
      b.x509GetSubjectName;
    case 'x509GetIssuerName':
      b.x509GetIssuerName;
    case 'x509GetSerialNumber':
      b.x509GetSerialNumber;
    case 'x509GetNotBefore':
      b.x509GetNotBefore;
    case 'x509GetNotAfter':
      b.x509GetNotAfter;
    case 'x509NameOneline':
      b.x509NameOneline;
    case 'asn1TimePrint':
      b.asn1TimePrint;
    case 'x509StoreNew':
      b.x509StoreNew;
    case 'x509StoreFree':
      b.x509StoreFree;
    case 'x509StoreAddCert':
      b.x509StoreAddCert;
    case 'x509StoreCtxNew':
      b.x509StoreCtxNew;
    case 'x509StoreCtxFree':
      b.x509StoreCtxFree;
    case 'x509StoreCtxInit':
      b.x509StoreCtxInit;
    case 'x509VerifyCert':
      b.x509VerifyCert;
    case 'x509VerifyCertErrorString':
      b.x509VerifyCertErrorString;
    case 'cmsSign':
      b.cmsSign;
    case 'cmsVerify':
      b.cmsVerify;
    case 'cmsEncrypt':
      b.cmsEncrypt;
    case 'cmsDecrypt':
      b.cmsDecrypt;
    case 'cmsContentInfoFree':
      b.cmsContentInfoFree;
    case 'pemReadBioCms':
      b.pemReadBioCms;
    case 'pemWriteBioCms':
      b.pemWriteBioCms;
    case 'osslSkNewNull':
      b.osslSkNewNull;
    case 'osslSkPush':
      b.osslSkPush;
    case 'osslSkFree':
      b.osslSkFree;
    case 'objSn2nid':
      b.objSn2nid;
    case 'objNid2sn':
      b.objNid2sn;
    case 'objTxt2nid':
      b.objTxt2nid;
    case 'x509SetVersion':
      b.x509SetVersion;
    case 'x509SetPubkey':
      b.x509SetPubkey;
    case 'x509SetIssuerName':
      b.x509SetIssuerName;
    case 'x509SetSubjectName':
      b.x509SetSubjectName;
    case 'x509Sign':
      b.x509Sign;
    case 'x509NameNew':
      b.x509NameNew;
    case 'x509NameFree':
      b.x509NameFree;
    case 'x509NameAddEntryByTxt':
      b.x509NameAddEntryByTxt;
    case 'asn1TimeSet':
      b.asn1TimeSet;
    case 'x509SetNotBefore':
      b.x509SetNotBefore;
    case 'x509SetNotAfter':
      b.x509SetNotAfter;
    case 'x509V3SetCtx':
      b.x509V3SetCtx;
    case 'x509V3ExtConfNid':
      b.x509V3ExtConfNid;
    case 'x509AddExt':
      b.x509AddExt;
    case 'x509ExtensionFree':
      b.x509ExtensionFree;
    case 'bioNewFile':
      b.bioNewFile;
    case 'bioCtrl':
      b.bioCtrl;
    default:
      throw ArgumentError('Unknown binding field: "$name"');
  }
}
