
// ignore_for_file: camel_case_types, non_constant_identifier_names

library;

import 'dart:ffi';
import 'package:ffi/ffi.dart';


typedef EVP_MD = Pointer<Void>;
typedef EVP_MD_CTX = Pointer<Void>;
typedef EVP_CIPHER = Pointer<Void>;
typedef EVP_CIPHER_CTX = Pointer<Void>;
typedef EVP_PKEY = Pointer<Void>;
typedef EVP_PKEY_CTX = Pointer<Void>;
typedef ENGINE = Pointer<Void>;
typedef BIO = Pointer<Void>;
typedef BIO_METHOD = Pointer<Void>;
typedef BIGNUM = Pointer<Void>;
typedef EC_KEY = Pointer<Void>;
typedef EC_GROUP = Pointer<Void>;
typedef EC_POINT = Pointer<Void>;
typedef X509 = Pointer<Void>;
typedef X509_STORE = Pointer<Void>;
typedef X509_STORE_CTX = Pointer<Void>;
typedef X509_NAME = Pointer<Void>;
typedef CMS_ContentInfo = Pointer<Void>;
typedef OSSL_PROVIDER = Pointer<Void>;
typedef OSSL_LIB_CTX = Pointer<Void>;
typedef X509V3_CTX = Pointer<Void>;
typedef ASN1_TIME = Pointer<Void>;
typedef X509_EXTENSION = Pointer<Void>;
typedef CONF = Pointer<Void>;
typedef X509_CRL = Pointer<Void>;
typedef X509_REVOKED = Pointer<Void>;
typedef ASN1_STRING = Pointer<Void>;
typedef ASN1_OBJECT = Pointer<Void>;
typedef GENERAL_NAME = Pointer<Void>;
typedef BASIC_CONSTRAINTS = Pointer<Void>;
typedef OCSP_REQUEST = Pointer<Void>;
typedef OCSP_RESPONSE = Pointer<Void>;
typedef OCSP_BASICRESP = Pointer<Void>;
typedef OCSP_CERTID = Pointer<Void>;
typedef OCSP_SINGLERESP = Pointer<Void>;
typedef ASN1_BIT_STRING = Pointer<Void>;
typedef ASN1_INTEGER = Pointer<Void>;
typedef ASN1_GENERALIZEDTIME = Pointer<Void>;
typedef X509_REQ = Pointer<Void>;
typedef CMS_SignerInfo = Pointer<Void>;
typedef STACK_OF_X509_EXTENSION = Pointer<Void>;
typedef ASN1_TYPE = Pointer<Void>;


typedef OpenSSLVersionNative = NativeFunction<Pointer<Utf8> Function(Int)>;
typedef OpenSSLVersionDart = Pointer<Utf8> Function(int type);

typedef RAND_bytesNative = NativeFunction<Int Function(Pointer<Uint8>, Int)>;
typedef RAND_bytesDart = int Function(Pointer<Uint8> buf, int num);

typedef RAND_priv_bytesNative =
    NativeFunction<Int Function(Pointer<Uint8>, Int)>;
typedef RAND_priv_bytesDart = int Function(Pointer<Uint8> buf, int num);

typedef ERR_get_errorNative = NativeFunction<UnsignedLong Function()>;
typedef ERR_get_errorDart = int Function();

typedef ERR_clear_errorNative = NativeFunction<Void Function()>;
typedef ERR_clear_errorDart = void Function();

typedef ERR_error_string_nNative =
    NativeFunction<Void Function(UnsignedLong, Pointer<Utf8>, Size)>;
typedef ERR_error_string_nDart =
    void Function(int e, Pointer<Utf8> buf, int len);

typedef CRYPTO_freeNative =
    NativeFunction<Void Function(Pointer<Void>, Pointer<Utf8>, Int)>;
typedef CRYPTO_freeDart =
    void Function(Pointer<Void> ptr, Pointer<Utf8> file, int line);

typedef OPENSSL_cleanseNative =
    NativeFunction<Void Function(Pointer<Void>, Size)>;
typedef OPENSSL_cleanseDart =
    void Function(Pointer<Void> ptr, int len);

typedef ASN1_INTEGER_to_BNNative =
    NativeFunction<BIGNUM Function(ASN1_INTEGER, BIGNUM)>;
typedef ASN1_INTEGER_to_BNDart =
    BIGNUM Function(ASN1_INTEGER value, BIGNUM result);

typedef BN_bn2hexNative = NativeFunction<Pointer<Utf8> Function(BIGNUM)>;
typedef BN_bn2hexDart = Pointer<Utf8> Function(BIGNUM value);

typedef EVP_MD_CTX_newNative = NativeFunction<EVP_MD_CTX Function()>;
typedef EVP_MD_CTX_newDart = EVP_MD_CTX Function();

typedef EVP_MD_CTX_freeNative = NativeFunction<Void Function(EVP_MD_CTX)>;
typedef EVP_MD_CTX_freeDart = void Function(EVP_MD_CTX ctx);

typedef OSSL_PROVIDER_loadNative =
    NativeFunction<OSSL_PROVIDER Function(OSSL_LIB_CTX, Pointer<Utf8>)>;
typedef OSSL_PROVIDER_loadDart =
    OSSL_PROVIDER Function(OSSL_LIB_CTX libctx, Pointer<Utf8> name);

typedef EVP_DigestInit_exNative =
    NativeFunction<Int Function(EVP_MD_CTX, EVP_MD, ENGINE)>;
typedef EVP_DigestInit_exDart =
    int Function(EVP_MD_CTX ctx, EVP_MD type, ENGINE engine);

typedef EVP_DigestUpdateNative =
    NativeFunction<Int Function(EVP_MD_CTX, Pointer<Void>, Size)>;
typedef EVP_DigestUpdateDart =
    int Function(EVP_MD_CTX ctx, Pointer<Void> data, int size);

typedef EVP_DigestFinal_exNative =
    NativeFunction<Int Function(EVP_MD_CTX, Pointer<Uint8>, Pointer<Uint32>)>;
typedef EVP_DigestFinal_exDart =
    int Function(EVP_MD_CTX ctx, Pointer<Uint8> md, Pointer<Uint32> s);

typedef EVP_sha256Native = NativeFunction<EVP_MD Function()>;
typedef EVP_sha256Dart = EVP_MD Function();

typedef EVP_sha512Native = NativeFunction<EVP_MD Function()>;
typedef EVP_sha512Dart = EVP_MD Function();
typedef EVP_sha384Native = NativeFunction<EVP_MD Function()>;
typedef EVP_sha384Dart = EVP_MD Function();

typedef EVP_sha3_256Native = NativeFunction<EVP_MD Function()>;
typedef EVP_sha3_256Dart = EVP_MD Function();

typedef EVP_sha3_512Native = NativeFunction<EVP_MD Function()>;
typedef EVP_sha3_512Dart = EVP_MD Function();

typedef EVP_CIPHER_CTX_newNative = NativeFunction<EVP_CIPHER_CTX Function()>;
typedef EVP_CIPHER_CTX_newDart = EVP_CIPHER_CTX Function();

typedef EVP_CIPHER_CTX_freeNative =
    NativeFunction<Void Function(EVP_CIPHER_CTX)>;
typedef EVP_CIPHER_CTX_freeDart = void Function(EVP_CIPHER_CTX c);

typedef EVP_CIPHER_CTX_ctrlNative =
    NativeFunction<Int Function(EVP_CIPHER_CTX, Int, Int, Pointer<Void>)>;
typedef EVP_CIPHER_CTX_ctrlDart =
    int Function(EVP_CIPHER_CTX ctx, int type, int arg, Pointer<Void> ptr);

typedef EVP_EncryptInit_exNative =
    NativeFunction<
      Int Function(
        EVP_CIPHER_CTX,
        EVP_CIPHER,
        ENGINE,
        Pointer<Uint8>,
        Pointer<Uint8>,
      )
    >;
typedef EVP_EncryptInit_exDart =
    int Function(
      EVP_CIPHER_CTX ctx,
      EVP_CIPHER type,
      ENGINE impl,
      Pointer<Uint8> key,
      Pointer<Uint8> iv,
    );

typedef EVP_EncryptUpdateNative =
    NativeFunction<
      Int Function(
        EVP_CIPHER_CTX,
        Pointer<Uint8>,
        Pointer<Int>,
        Pointer<Uint8>,
        Int,
      )
    >;
typedef EVP_EncryptUpdateDart =
    int Function(
      EVP_CIPHER_CTX ctx,
      Pointer<Uint8> out,
      Pointer<Int> outl,
      Pointer<Uint8> src,
      int srcLen,
    );

typedef EVP_EncryptFinal_exNative =
    NativeFunction<Int Function(EVP_CIPHER_CTX, Pointer<Uint8>, Pointer<Int>)>;
typedef EVP_EncryptFinal_exDart =
    int Function(EVP_CIPHER_CTX ctx, Pointer<Uint8> out, Pointer<Int> outl);

typedef EVP_DecryptInit_exNative =
    NativeFunction<
      Int Function(
        EVP_CIPHER_CTX,
        EVP_CIPHER,
        ENGINE,
        Pointer<Uint8>,
        Pointer<Uint8>,
      )
    >;
typedef EVP_DecryptInit_exDart =
    int Function(
      EVP_CIPHER_CTX ctx,
      EVP_CIPHER type,
      ENGINE impl,
      Pointer<Uint8> key,
      Pointer<Uint8> iv,
    );

typedef EVP_DecryptUpdateNative =
    NativeFunction<
      Int Function(
        EVP_CIPHER_CTX,
        Pointer<Uint8>,
        Pointer<Int>,
        Pointer<Uint8>,
        Int,
      )
    >;
typedef EVP_DecryptUpdateDart =
    int Function(
      EVP_CIPHER_CTX ctx,
      Pointer<Uint8> out,
      Pointer<Int> outl,
      Pointer<Uint8> src,
      int srcLen,
    );

typedef EVP_DecryptFinal_exNative =
    NativeFunction<Int Function(EVP_CIPHER_CTX, Pointer<Uint8>, Pointer<Int>)>;
typedef EVP_DecryptFinal_exDart =
    int Function(EVP_CIPHER_CTX ctx, Pointer<Uint8> out, Pointer<Int> outl);

typedef EVP_aes_128_cbcNative = NativeFunction<EVP_CIPHER Function()>;
typedef EVP_aes_128_cbcDart = EVP_CIPHER Function();

typedef EVP_aes_256_cbcNative = NativeFunction<EVP_CIPHER Function()>;
typedef EVP_aes_256_cbcDart = EVP_CIPHER Function();

typedef EVP_aes_128_gcmNative = NativeFunction<EVP_CIPHER Function()>;
typedef EVP_aes_128_gcmDart = EVP_CIPHER Function();

typedef EVP_aes_256_gcmNative = NativeFunction<EVP_CIPHER Function()>;
typedef EVP_aes_256_gcmDart = EVP_CIPHER Function();

typedef EVP_PKEY_newNative = NativeFunction<EVP_PKEY Function()>;
typedef EVP_PKEY_newDart = EVP_PKEY Function();

typedef EVP_PKEY_freeNative = NativeFunction<Void Function(EVP_PKEY)>;
typedef EVP_PKEY_freeDart = void Function(EVP_PKEY pkey);

typedef EVP_PKEY_get_sizeNative = NativeFunction<Int Function(EVP_PKEY)>;
typedef EVP_PKEY_get_sizeDart = int Function(EVP_PKEY pkey);

typedef EVP_PKEY_CTX_newNative =
    NativeFunction<EVP_PKEY_CTX Function(EVP_PKEY, ENGINE)>;
typedef EVP_PKEY_CTX_newDart = EVP_PKEY_CTX Function(EVP_PKEY pkey, ENGINE e);

typedef EVP_PKEY_CTX_new_idNative =
    NativeFunction<EVP_PKEY_CTX Function(Int, ENGINE)>;
typedef EVP_PKEY_CTX_new_idDart = EVP_PKEY_CTX Function(int id, ENGINE e);

typedef EVP_PKEY_CTX_freeNative = NativeFunction<Void Function(EVP_PKEY_CTX)>;
typedef EVP_PKEY_CTX_freeDart = void Function(EVP_PKEY_CTX ctx);

typedef EVP_PKEY_keygen_initNative = NativeFunction<Int Function(EVP_PKEY_CTX)>;
typedef EVP_PKEY_keygen_initDart = int Function(EVP_PKEY_CTX ctx);

typedef EVP_PKEY_keygenNative =
    NativeFunction<Int Function(EVP_PKEY_CTX, Pointer<EVP_PKEY>)>;
typedef EVP_PKEY_keygenDart =
    int Function(EVP_PKEY_CTX ctx, Pointer<EVP_PKEY> ppkey);

typedef EVP_PKEY_CTX_set_rsa_keygen_bitsNative =
    NativeFunction<Int Function(EVP_PKEY_CTX, Int)>;
typedef EVP_PKEY_CTX_set_rsa_keygen_bitsDart =
    int Function(EVP_PKEY_CTX ctx, int mbits);

typedef EVP_PKEY_CTX_set_ec_paramgen_curve_nidNative =
    NativeFunction<Int Function(EVP_PKEY_CTX, Int)>;
typedef EVP_PKEY_CTX_set_ec_paramgen_curve_nidDart =
    int Function(EVP_PKEY_CTX ctx, int nid);

typedef EVP_default_properties_is_fipsNative =
    NativeFunction<Int Function(OSSL_LIB_CTX)>;
typedef EVP_default_properties_is_fipsDart =
    int Function(OSSL_LIB_CTX libctx);

typedef EVP_DigestSignInitNative =
    NativeFunction<
      Int Function(EVP_MD_CTX, Pointer<EVP_PKEY_CTX>, EVP_MD, ENGINE, EVP_PKEY)
    >;
typedef EVP_DigestSignInitDart =
    int Function(
      EVP_MD_CTX ctx,
      Pointer<EVP_PKEY_CTX> pctx,
      EVP_MD type,
      ENGINE e,
      EVP_PKEY pkey,
    );

typedef EVP_DigestSignUpdateNative =
    NativeFunction<Int Function(EVP_MD_CTX, Pointer<Void>, Size)>;
typedef EVP_DigestSignUpdateDart =
    int Function(EVP_MD_CTX ctx, Pointer<Void> d, int cnt);

typedef EVP_DigestSignNative =
    NativeFunction<
      Int Function(
        EVP_MD_CTX,
        Pointer<Uint8>,
        Pointer<Size>,
        Pointer<Uint8>,
        Size,
      )
    >;
typedef EVP_DigestSignDart =
    int Function(
      EVP_MD_CTX ctx,
      Pointer<Uint8> sigret,
      Pointer<Size> siglen,
      Pointer<Uint8> tbs,
      int tbslen,
    );

typedef EVP_DigestVerifyInitNative =
    NativeFunction<
      Int Function(EVP_MD_CTX, Pointer<EVP_PKEY_CTX>, EVP_MD, ENGINE, EVP_PKEY)
    >;
typedef EVP_DigestVerifyInitDart =
    int Function(
      EVP_MD_CTX ctx,
      Pointer<EVP_PKEY_CTX> pctx,
      EVP_MD type,
      ENGINE e,
      EVP_PKEY pkey,
    );

typedef EVP_DigestVerifyNative =
    NativeFunction<
      Int Function(EVP_MD_CTX, Pointer<Uint8>, Size, Pointer<Uint8>, Size)
    >;
typedef EVP_DigestVerifyDart =
    int Function(
      EVP_MD_CTX ctx,
      Pointer<Uint8> sig,
      int siglen,
      Pointer<Uint8> tbs,
      int tbslen,
    );

typedef EVP_PKEY_encrypt_initNative =
    NativeFunction<Int Function(EVP_PKEY_CTX)>;
typedef EVP_PKEY_encrypt_initDart = int Function(EVP_PKEY_CTX ctx);

typedef EVP_PKEY_encryptNative =
    NativeFunction<
      Int Function(
        EVP_PKEY_CTX,
        Pointer<Uint8>,
        Pointer<Size>,
        Pointer<Uint8>,
        Size,
      )
    >;
typedef EVP_PKEY_encryptDart =
    int Function(
      EVP_PKEY_CTX ctx,
      Pointer<Uint8> out,
      Pointer<Size> outlen,
      Pointer<Uint8> src,
      int srclen,
    );

typedef EVP_PKEY_decrypt_initNative =
    NativeFunction<Int Function(EVP_PKEY_CTX)>;
typedef EVP_PKEY_decrypt_initDart = int Function(EVP_PKEY_CTX ctx);

typedef EVP_PKEY_decryptNative =
    NativeFunction<
      Int Function(
        EVP_PKEY_CTX,
        Pointer<Uint8>,
        Pointer<Size>,
        Pointer<Uint8>,
        Size,
      )
    >;
typedef EVP_PKEY_decryptDart =
    int Function(
      EVP_PKEY_CTX ctx,
      Pointer<Uint8> out,
      Pointer<Size> outlen,
      Pointer<Uint8> src,
      int srclen,
    );

typedef EVP_PKEY_encapsulate_initNative
    = NativeFunction<Int32 Function(EVP_PKEY_CTX, Pointer<Void>)>;
typedef EVP_PKEY_encapsulate_initDart = int Function(
    EVP_PKEY_CTX ctx, Pointer<Void> params);

typedef EVP_PKEY_encapsulateNative = NativeFunction<
    Int32 Function(EVP_PKEY_CTX, Pointer<Uint8>, Pointer<Size>,
        Pointer<Uint8>, Pointer<Size>)>;
typedef EVP_PKEY_encapsulateDart = int Function(
    EVP_PKEY_CTX ctx,
    Pointer<Uint8> wrappedkey,
    Pointer<Size> wrappedkeylen,
    Pointer<Uint8> genkey,
    Pointer<Size> genkeylen);

typedef EVP_PKEY_decapsulate_initNative
    = NativeFunction<Int32 Function(EVP_PKEY_CTX, Pointer<Void>)>;
typedef EVP_PKEY_decapsulate_initDart = int Function(
    EVP_PKEY_CTX ctx, Pointer<Void> params);

typedef EVP_PKEY_decapsulateNative = NativeFunction<
    Int32 Function(EVP_PKEY_CTX, Pointer<Uint8>, Pointer<Size>,
        Pointer<Uint8>, Size)>;
typedef EVP_PKEY_decapsulateDart = int Function(
    EVP_PKEY_CTX ctx,
    Pointer<Uint8> unwrapped,
    Pointer<Size> unwrappedlen,
    Pointer<Uint8> wrapped,
    int wrappedlen);

typedef BIO_newNative = NativeFunction<BIO Function(BIO_METHOD)>;
typedef BIO_newDart = BIO Function(BIO_METHOD type);

typedef BIO_freeNative = NativeFunction<Int Function(BIO)>;
typedef BIO_freeDart = int Function(BIO a);

typedef BIO_s_memNative = NativeFunction<BIO_METHOD Function()>;
typedef BIO_s_memDart = BIO_METHOD Function();

typedef BIO_new_mem_bufNative =
    NativeFunction<BIO Function(Pointer<Void>, Int)>;
typedef BIO_new_mem_bufDart = BIO Function(Pointer<Void> buf, int len);

typedef BIO_readNative = NativeFunction<Int Function(BIO, Pointer<Void>, Int)>;
typedef BIO_readDart = int Function(BIO b, Pointer<Void> data, int dlen);

typedef BIO_writeNative = NativeFunction<Int Function(BIO, Pointer<Void>, Int)>;
typedef BIO_writeDart = int Function(BIO b, Pointer<Void> data, int dlen);

typedef BN_newNative = NativeFunction<BIGNUM Function()>;
typedef BN_newDart = BIGNUM Function();

typedef BN_freeNative = NativeFunction<Void Function(BIGNUM)>;
typedef BN_freeDart = void Function(BIGNUM a);

typedef BN_bn2binNative = NativeFunction<Int Function(BIGNUM, Pointer<Uint8>)>;
typedef BN_bn2binDart = int Function(BIGNUM a, Pointer<Uint8> to);

typedef BN_bin2bnNative =
    NativeFunction<BIGNUM Function(Pointer<Uint8>, Int, BIGNUM)>;
typedef BN_bin2bnDart = BIGNUM Function(Pointer<Uint8> s, int len, BIGNUM ret);

typedef EVP_PKEY_get_bn_paramNative = NativeFunction<
    Int Function(EVP_PKEY, Pointer<Utf8>, Pointer<BIGNUM>)>;
typedef EVP_PKEY_get_bn_paramDart =
    int Function(EVP_PKEY pkey, Pointer<Utf8> name, Pointer<BIGNUM> value);

typedef EC_GROUP_new_by_curve_nameNative =
    NativeFunction<EC_GROUP Function(Int)>;
typedef EC_GROUP_new_by_curve_nameDart = EC_GROUP Function(int nid);
typedef EC_GROUP_get_cofactorNative =
    NativeFunction<Int Function(EC_GROUP, BIGNUM, Pointer<Void>)>;
typedef EC_GROUP_get_cofactorDart =
    int Function(EC_GROUP group, BIGNUM cofactor, Pointer<Void> context);
typedef EC_GROUP_freeNative = NativeFunction<Void Function(EC_GROUP)>;
typedef EC_GROUP_freeDart = void Function(EC_GROUP group);

typedef PEM_read_bio_PrivateKeyNative =
    NativeFunction<
      EVP_PKEY Function(
        BIO,
        Pointer<EVP_PKEY>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_PrivateKeyDart =
    EVP_PKEY Function(
      BIO bp,
      Pointer<EVP_PKEY> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_PrivateKeyNative =
    NativeFunction<
      Int Function(
        BIO,
        EVP_PKEY,
        EVP_CIPHER,
        Pointer<Uint8>,
        Int,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_write_bio_PrivateKeyDart =
    int Function(
      BIO bp,
      EVP_PKEY x,
      EVP_CIPHER enc,
      Pointer<Uint8> kstr,
      int klen,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_read_bio_PUBKEYNative =
    NativeFunction<
      EVP_PKEY Function(
        BIO,
        Pointer<EVP_PKEY>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_PUBKEYDart =
    EVP_PKEY Function(
      BIO bp,
      Pointer<EVP_PKEY> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_PUBKEYNative =
    NativeFunction<Int Function(BIO, EVP_PKEY)>;
typedef PEM_write_bio_PUBKEYDart = int Function(BIO bp, EVP_PKEY x);

typedef PEM_read_bio_X509Native =
    NativeFunction<
      X509 Function(
        BIO,
        Pointer<X509>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_X509Dart =
    X509 Function(
      BIO bp,
      Pointer<X509> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_X509Native = NativeFunction<Int Function(BIO, X509)>;
typedef PEM_write_bio_X509Dart = int Function(BIO bp, X509 x);

typedef PEM_read_bio_CMSNative =
    NativeFunction<
      CMS_ContentInfo Function(
        BIO,
        Pointer<CMS_ContentInfo>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_CMSDart =
    CMS_ContentInfo Function(
      BIO bp,
      Pointer<CMS_ContentInfo> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_CMSNative =
    NativeFunction<Int Function(BIO, CMS_ContentInfo)>;
typedef PEM_write_bio_CMSDart = int Function(BIO bp, CMS_ContentInfo x);

typedef i2d_CMS_bioNative =
    NativeFunction<Int Function(BIO, CMS_ContentInfo)>;
typedef i2d_CMS_bioDart = int Function(BIO bp, CMS_ContentInfo cms);

typedef d2i_CMS_bioNative =
    NativeFunction<CMS_ContentInfo Function(BIO, Pointer<CMS_ContentInfo>)>;
typedef d2i_CMS_bioDart =
    CMS_ContentInfo Function(BIO bp, Pointer<CMS_ContentInfo> cms);

typedef X509_newNative = NativeFunction<X509 Function()>;
typedef X509_newDart = X509 Function();

typedef X509_freeNative = NativeFunction<Void Function(X509)>;
typedef X509_freeDart = void Function(X509 a);

typedef X509_get_subject_nameNative = NativeFunction<X509_NAME Function(X509)>;
typedef X509_get_subject_nameDart = X509_NAME Function(X509 a);

typedef X509_get_issuer_nameNative = NativeFunction<X509_NAME Function(X509)>;
typedef X509_get_issuer_nameDart = X509_NAME Function(X509 a);

typedef X509_get_serialNumberNative =
    NativeFunction<Pointer<Void> Function(X509)>;
typedef X509_get_serialNumberDart = Pointer<Void> Function(X509 x);

typedef X509_get_notBeforeNative = NativeFunction<Pointer<Void> Function(X509)>;
typedef X509_get_notBeforeDart = Pointer<Void> Function(X509 x);

typedef X509_get_notAfterNative = NativeFunction<Pointer<Void> Function(X509)>;
typedef X509_get_notAfterDart = Pointer<Void> Function(X509 x);

typedef X509_NAME_onelineNative =
    NativeFunction<Pointer<Utf8> Function(X509_NAME, Pointer<Utf8>, Int)>;
typedef X509_NAME_onelineDart =
    Pointer<Utf8> Function(X509_NAME a, Pointer<Utf8> buf, int size);

typedef ASN1_TIME_printNative =
    NativeFunction<Int Function(Pointer<Void>, Pointer<Void>)>;
typedef ASN1_TIME_printDart = int Function(Pointer<Void> bp, Pointer<Void> tm);

typedef X509_STORE_newNative = NativeFunction<X509_STORE Function()>;
typedef X509_STORE_newDart = X509_STORE Function();

typedef X509_STORE_freeNative = NativeFunction<Void Function(X509_STORE)>;
typedef X509_STORE_freeDart = void Function(X509_STORE v);

typedef X509_STORE_add_certNative =
    NativeFunction<Int Function(X509_STORE, X509)>;
typedef X509_STORE_add_certDart = int Function(X509_STORE store, X509 x509);

typedef X509_STORE_CTX_newNative = NativeFunction<X509_STORE_CTX Function()>;
typedef X509_STORE_CTX_newDart = X509_STORE_CTX Function();

typedef X509_STORE_CTX_freeNative =
    NativeFunction<Void Function(X509_STORE_CTX)>;
typedef X509_STORE_CTX_freeDart = void Function(X509_STORE_CTX ctx);

typedef X509_STORE_CTX_initNative =
    NativeFunction<
      Int Function(X509_STORE_CTX, X509_STORE, X509, Pointer<Void>)
    >;
typedef X509_STORE_CTX_initDart =
    int Function(
      X509_STORE_CTX ctx,
      X509_STORE store,
      X509 x509,
      Pointer<Void> chain,
    );

typedef X509_STORE_CTX_get0_paramNative
    = NativeFunction<Pointer<Void> Function(X509_STORE_CTX)>;
typedef X509_STORE_CTX_get0_paramDart
    = Pointer<Void> Function(X509_STORE_CTX ctx);

typedef X509_VERIFY_PARAM_set_timeNative
    = NativeFunction<Int32 Function(Pointer<Void>, Int64)>;
typedef X509_VERIFY_PARAM_set_timeDart
    = int Function(Pointer<Void> param, int time);

typedef X509_verify_certNative = NativeFunction<Int Function(X509_STORE_CTX)>;
typedef X509_verify_certDart = int Function(X509_STORE_CTX ctx);

typedef X509_verify_cert_error_stringNative =
    NativeFunction<Pointer<Utf8> Function(Long)>;
typedef X509_verify_cert_error_stringDart = Pointer<Utf8> Function(int n);

typedef X509_STORE_CTX_get_errorNative =
    NativeFunction<Int Function(X509_STORE_CTX)>;
typedef X509_STORE_CTX_get_errorDart = int Function(X509_STORE_CTX ctx);

typedef X509_STORE_CTX_get_error_depthNative =
    NativeFunction<Int Function(X509_STORE_CTX)>;
typedef X509_STORE_CTX_get_error_depthDart = int Function(X509_STORE_CTX ctx);

typedef CMS_signNative =
    NativeFunction<
      CMS_ContentInfo Function(X509, EVP_PKEY, Pointer<Void>, BIO, UnsignedInt)
    >;
typedef CMS_signDart =
    CMS_ContentInfo Function(
      X509 signcert,
      EVP_PKEY pkey,
      Pointer<Void> certs,
      BIO data,
      int flags,
    );

typedef CMS_verifyNative =
    NativeFunction<
      Int Function(
        CMS_ContentInfo,
        Pointer<Void>,
        X509_STORE,
        BIO,
        BIO,
        UnsignedInt,
      )
    >;
typedef CMS_verifyDart =
    int Function(
      CMS_ContentInfo cms,
      Pointer<Void> certs,
      X509_STORE store,
      BIO dcont,
      BIO out,
      int flags,
    );

typedef CMS_encryptNative =
    NativeFunction<
      CMS_ContentInfo Function(Pointer<Void>, BIO, EVP_CIPHER, UnsignedInt)
    >;
typedef CMS_encryptDart =
    CMS_ContentInfo Function(
      Pointer<Void> certs,
      BIO src,
      EVP_CIPHER cipher,
      int flags,
    );

typedef CMS_decryptNative =
    NativeFunction<
      Int Function(
        CMS_ContentInfo,
        EVP_PKEY,
        X509,
        Pointer<Void>,
        BIO,
        UnsignedInt,
      )
    >;
typedef CMS_decryptDart =
    int Function(
      CMS_ContentInfo cms,
      EVP_PKEY pkey,
      X509 cert,
      Pointer<Void> dcont,
      BIO out,
      int flags,
    );

typedef CMS_ContentInfo_freeNative =
    NativeFunction<Void Function(CMS_ContentInfo)>;
typedef CMS_ContentInfo_freeDart = void Function(CMS_ContentInfo cms);

typedef OPENSSL_sk_new_nullNative = NativeFunction<Pointer<Void> Function()>;
typedef OPENSSL_sk_new_nullDart = Pointer<Void> Function();

typedef OPENSSL_sk_pushNative =
    NativeFunction<Int Function(Pointer<Void>, Pointer<Void>)>;
typedef OPENSSL_sk_pushDart =
    int Function(Pointer<Void> st, Pointer<Void> data);

typedef OPENSSL_sk_freeNative = NativeFunction<Void Function(Pointer<Void>)>;
typedef OPENSSL_sk_freeDart = void Function(Pointer<Void> st);

typedef OBJ_sn2nidNative = NativeFunction<Int Function(Pointer<Utf8>)>;
typedef OBJ_sn2nidDart = int Function(Pointer<Utf8> sn);

typedef OBJ_nid2snNative = NativeFunction<Pointer<Utf8> Function(Int)>;
typedef OBJ_nid2snDart = Pointer<Utf8> Function(int nid);

typedef OBJ_obj2txtNative =
    NativeFunction<Int Function(Pointer<Utf8>, Int, ASN1_OBJECT, Int)>;
typedef OBJ_obj2txtDart =
    int Function(Pointer<Utf8> buf, int bufLen, ASN1_OBJECT a, int noName);

typedef X509_set_versionNative = NativeFunction<Int Function(X509, Long)>;
typedef X509_set_versionDart = int Function(X509 x, int version);

typedef X509_set_pubkeyNative = NativeFunction<Int Function(X509, EVP_PKEY)>;
typedef X509_set_pubkeyDart = int Function(X509 x, EVP_PKEY pkey);

typedef X509_set_issuer_nameNative =
    NativeFunction<Int Function(X509, X509_NAME)>;
typedef X509_set_issuer_nameDart = int Function(X509 x, X509_NAME name);

typedef X509_set_subject_nameNative =
    NativeFunction<Int Function(X509, X509_NAME)>;
typedef X509_set_subject_nameDart = int Function(X509 x, X509_NAME name);

typedef X509_signNative = NativeFunction<Int Function(X509, EVP_PKEY, EVP_MD)>;
typedef X509_signDart = int Function(X509 x, EVP_PKEY pkey, EVP_MD md);

typedef X509_get_pubkeyNative = NativeFunction<EVP_PKEY Function(X509)>;
typedef X509_get_pubkeyDart = EVP_PKEY Function(X509 x);

typedef X509_NAME_newNative = NativeFunction<X509_NAME Function()>;
typedef X509_NAME_newDart = X509_NAME Function();

typedef X509_NAME_freeNative = NativeFunction<Void Function(X509_NAME)>;
typedef X509_NAME_freeDart = void Function(X509_NAME name);

typedef X509_NAME_add_entry_by_txtNative =
    NativeFunction<
      Int Function(X509_NAME, Pointer<Utf8>, Int, Pointer<Uint8>, Int, Int, Int)
    >;
typedef X509_NAME_add_entry_by_txtDart =
    int Function(
      X509_NAME name,
      Pointer<Utf8> field,
      int type,
      Pointer<Uint8> bytes,
      int len,
      int loc,
      int set,
    );

typedef ASN1_TIME_setNative =
    NativeFunction<ASN1_TIME Function(ASN1_TIME, Long)>;
typedef ASN1_TIME_setDart = ASN1_TIME Function(ASN1_TIME s, int t);

typedef X509_set1_notBeforeNative =
    NativeFunction<Int Function(X509, ASN1_TIME)>;
typedef X509_set1_notBeforeDart = int Function(X509 x, ASN1_TIME tm);

typedef X509_set1_notAfterNative =
    NativeFunction<Int Function(X509, ASN1_TIME)>;
typedef X509_set1_notAfterDart = int Function(X509 x, ASN1_TIME tm);

typedef X509V3_set_ctxNative =
    NativeFunction<
      Void Function(X509V3_CTX, X509, X509, Pointer<Void>, Pointer<Void>, Int)
    >;
typedef X509V3_set_ctxDart =
    void Function(
      X509V3_CTX ctx,
      X509 issuer,
      X509 subject,
      Pointer<Void> req,
      Pointer<Void> crl,
      int flags,
    );

typedef X509V3_EXT_conf_nidNative =
    NativeFunction<
      X509_EXTENSION Function(Pointer<Void>, X509V3_CTX, Int, Pointer<Utf8>)
    >;
typedef X509V3_EXT_conf_nidDart =
    X509_EXTENSION Function(
      Pointer<Void> conf,
      X509V3_CTX ctx,
      int extNid,
      Pointer<Utf8> value,
    );

typedef X509_add_extNative =
    NativeFunction<Int Function(X509, X509_EXTENSION, Int)>;
typedef X509_add_extDart = int Function(X509 x, X509_EXTENSION ex, int loc);

typedef X509_EXTENSION_freeNative =
    NativeFunction<Void Function(X509_EXTENSION)>;
typedef X509_EXTENSION_freeDart = void Function(X509_EXTENSION ex);

typedef X509_get_ext_countNative = NativeFunction<Int Function(X509)>;
typedef X509_get_ext_countDart = int Function(X509 x);

typedef X509_get_extNative = NativeFunction<X509_EXTENSION Function(X509, Int)>;
typedef X509_get_extDart = X509_EXTENSION Function(X509 x, int loc);

typedef X509_EXTENSION_get_objectNative =
    NativeFunction<ASN1_OBJECT Function(X509_EXTENSION)>;
typedef X509_EXTENSION_get_objectDart = ASN1_OBJECT Function(X509_EXTENSION ex);

typedef X509_EXTENSION_get_dataNative =
    NativeFunction<ASN1_STRING Function(X509_EXTENSION)>;
typedef X509_EXTENSION_get_dataDart = ASN1_STRING Function(X509_EXTENSION ex);

typedef X509V3_EXT_printNative =
    NativeFunction<Int Function(BIO, X509_EXTENSION, UnsignedLong, Int)>;
typedef X509V3_EXT_printDart =
    int Function(BIO out, X509_EXTENSION ext, int flag, int indent);

typedef X509_get_key_usageNative = NativeFunction<UnsignedLong Function(X509)>;
typedef X509_get_key_usageDart = int Function(X509 x);

typedef X509_get_extended_key_usageNative =
    NativeFunction<UnsignedLong Function(X509)>;
typedef X509_get_extended_key_usageDart = int Function(X509 x);

typedef X509_get_ext_by_NIDNative =
    NativeFunction<Int Function(X509, Int, Int)>;
typedef X509_get_ext_by_NIDDart = int Function(X509 x, int nid, int lastPos);

typedef X509_get_ext_d2iNative =
    NativeFunction<
      Pointer<Void> Function(X509, Int, Pointer<Int>, Pointer<Int>)
    >;
typedef X509_get_ext_d2iDart =
    Pointer<Void> Function(
      X509 x,
      int nid,
      Pointer<Int> crit,
      Pointer<Int> idx,
    );

typedef ASN1_STRING_get0_dataNative =
    NativeFunction<Pointer<Uint8> Function(ASN1_STRING)>;
typedef ASN1_STRING_get0_dataDart = Pointer<Uint8> Function(ASN1_STRING s);

typedef ASN1_STRING_lengthNative = NativeFunction<Int Function(ASN1_STRING)>;
typedef ASN1_STRING_lengthDart = int Function(ASN1_STRING s);

typedef X509_CRL_newNative = NativeFunction<X509_CRL Function()>;
typedef X509_CRL_newDart = X509_CRL Function();

typedef X509_CRL_freeNative = NativeFunction<Void Function(X509_CRL)>;
typedef X509_CRL_freeDart = void Function(X509_CRL crl);

typedef d2i_X509_CRL_bioNative =
    NativeFunction<X509_CRL Function(BIO, Pointer<X509_CRL>)>;
typedef d2i_X509_CRL_bioDart = X509_CRL Function(BIO bp, Pointer<X509_CRL> x);

typedef X509_CRL_verifyNative =
    NativeFunction<Int Function(X509_CRL, EVP_PKEY)>;
typedef X509_CRL_verifyDart = int Function(X509_CRL crl, EVP_PKEY pkey);

typedef X509_CRL_get0_lastUpdateNative =
    NativeFunction<ASN1_TIME Function(X509_CRL)>;
typedef X509_CRL_get0_lastUpdateDart = ASN1_TIME Function(X509_CRL crl);

typedef X509_CRL_get0_nextUpdateNative =
    NativeFunction<ASN1_TIME Function(X509_CRL)>;
typedef X509_CRL_get0_nextUpdateDart = ASN1_TIME Function(X509_CRL crl);

typedef X509_CRL_get_REVOKEDNative =
    NativeFunction<Pointer<Void> Function(X509_CRL)>;
typedef X509_CRL_get_REVOKEDDart = Pointer<Void> Function(X509_CRL crl);

typedef OPENSSL_sk_numNative = NativeFunction<Int Function(Pointer<Void>)>;
typedef OPENSSL_sk_numDart = int Function(Pointer<Void> st);

typedef OPENSSL_sk_valueNative =
    NativeFunction<Pointer<Void> Function(Pointer<Void>, Int)>;
typedef OPENSSL_sk_valueDart =
    Pointer<Void> Function(Pointer<Void> st, int idx);

typedef X509_REVOKED_get0_serialNumberNative =
    NativeFunction<ASN1_STRING Function(X509_REVOKED)>;
typedef X509_REVOKED_get0_serialNumberDart =
    ASN1_STRING Function(X509_REVOKED r);

typedef X509_REVOKED_get0_revocationDateNative =
    NativeFunction<ASN1_TIME Function(X509_REVOKED)>;
typedef X509_REVOKED_get0_revocationDateDart =
    ASN1_TIME Function(X509_REVOKED r);

typedef PEM_read_bio_X509_CRLNative =
    NativeFunction<
      X509_CRL Function(
        BIO,
        Pointer<X509_CRL>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_X509_CRLDart =
    X509_CRL Function(
      BIO bp,
      Pointer<X509_CRL> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_X509_CRLNative =
    NativeFunction<Int Function(BIO, X509_CRL)>;
typedef PEM_write_bio_X509_CRLDart = int Function(BIO bp, X509_CRL crl);

typedef OCSP_REQUEST_newNative = NativeFunction<OCSP_REQUEST Function()>;
typedef OCSP_REQUEST_newDart = OCSP_REQUEST Function();

typedef OCSP_REQUEST_freeNative = NativeFunction<Void Function(OCSP_REQUEST)>;
typedef OCSP_REQUEST_freeDart = void Function(OCSP_REQUEST req);

typedef OCSP_request_add0_idNative =
    NativeFunction<OCSP_CERTID Function(OCSP_REQUEST, OCSP_CERTID)>;
typedef OCSP_request_add0_idDart =
    OCSP_CERTID Function(OCSP_REQUEST req, OCSP_CERTID cid);

typedef OCSP_RESPONSE_freeNative = NativeFunction<Void Function(OCSP_RESPONSE)>;
typedef OCSP_RESPONSE_freeDart = void Function(OCSP_RESPONSE resp);

typedef OCSP_response_statusNative =
    NativeFunction<Int Function(OCSP_RESPONSE)>;
typedef OCSP_response_statusDart = int Function(OCSP_RESPONSE resp);

typedef OCSP_response_get1_basicNative =
    NativeFunction<OCSP_BASICRESP Function(OCSP_RESPONSE)>;
typedef OCSP_response_get1_basicDart =
    OCSP_BASICRESP Function(OCSP_RESPONSE resp);

typedef OCSP_BASICRESP_freeNative =
    NativeFunction<Void Function(OCSP_BASICRESP)>;
typedef OCSP_BASICRESP_freeDart = void Function(OCSP_BASICRESP bs);

typedef OCSP_basic_verifyNative =
    NativeFunction<
      Int Function(OCSP_BASICRESP, Pointer<Void>, X509_STORE, UnsignedLong)
    >;
typedef OCSP_basic_verifyDart =
    int Function(
      OCSP_BASICRESP bs,
      Pointer<Void> certs,
      X509_STORE st,
      int flags,
    );

typedef OCSP_resp_find_statusNative =
    NativeFunction<
      OCSP_SINGLERESP Function(
        OCSP_BASICRESP,
        OCSP_CERTID,
        Pointer<Int>,
        Pointer<Int>,
        Pointer<ASN1_GENERALIZEDTIME>,
        Pointer<ASN1_GENERALIZEDTIME>,
        Pointer<ASN1_GENERALIZEDTIME>,
      )
    >;
typedef OCSP_resp_find_statusDart =
    OCSP_SINGLERESP Function(
      OCSP_BASICRESP bs,
      OCSP_CERTID id,
      Pointer<Int> status,
      Pointer<Int> reason,
      Pointer<ASN1_GENERALIZEDTIME> revtime,
      Pointer<ASN1_GENERALIZEDTIME> thisupd,
      Pointer<ASN1_GENERALIZEDTIME> nextupd,
    );

typedef OCSP_single_get0_statusNative =
    NativeFunction<
      Int Function(
        OCSP_SINGLERESP,
        Pointer<Int>,
        Pointer<ASN1_GENERALIZEDTIME>,
        Pointer<ASN1_GENERALIZEDTIME>,
        Pointer<ASN1_GENERALIZEDTIME>,
      )
    >;
typedef OCSP_single_get0_statusDart =
    int Function(
      OCSP_SINGLERESP single,
      Pointer<Int> reason,
      Pointer<ASN1_GENERALIZEDTIME> revtime,
      Pointer<ASN1_GENERALIZEDTIME> thisupd,
      Pointer<ASN1_GENERALIZEDTIME> nextupd,
    );

typedef OCSP_check_validityNative =
    NativeFunction<
      Int Function(ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME, Long, Long)
    >;
typedef OCSP_check_validityDart =
    int Function(
      ASN1_GENERALIZEDTIME thisupd,
      ASN1_GENERALIZEDTIME nextupd,
      int sec,
      int maxsec,
    );

typedef OCSP_resp_countNative = NativeFunction<Int Function(OCSP_BASICRESP)>;
typedef OCSP_resp_countDart = int Function(OCSP_BASICRESP bs);

typedef OCSP_resp_get0Native =
    NativeFunction<OCSP_SINGLERESP Function(OCSP_BASICRESP, Int)>;
typedef OCSP_resp_get0Dart =
    OCSP_SINGLERESP Function(OCSP_BASICRESP bs, int idx);

typedef OCSP_resp_get0_produced_atNative =
    NativeFunction<ASN1_GENERALIZEDTIME Function(OCSP_BASICRESP)>;
typedef OCSP_resp_get0_produced_atDart =
    ASN1_GENERALIZEDTIME Function(OCSP_BASICRESP bs);

typedef OCSP_CERTID_freeNative = NativeFunction<Void Function(OCSP_CERTID)>;
typedef OCSP_CERTID_freeDart = void Function(OCSP_CERTID cid);

typedef OCSP_cert_id_newNative =
    NativeFunction<
      OCSP_CERTID Function(EVP_MD, X509_NAME, ASN1_BIT_STRING, ASN1_INTEGER)
    >;
typedef OCSP_cert_id_newDart =
    OCSP_CERTID Function(
      EVP_MD dgst,
      X509_NAME issuerName,
      ASN1_BIT_STRING issuerKey,
      ASN1_INTEGER serialNumber,
    );

typedef i2d_OCSP_REQUESTNative =
    NativeFunction<Int Function(OCSP_REQUEST, Pointer<Pointer<Uint8>>)>;
typedef i2d_OCSP_REQUESTDart =
    int Function(OCSP_REQUEST a, Pointer<Pointer<Uint8>> out);

typedef d2i_OCSP_RESPONSENative =
    NativeFunction<
      OCSP_RESPONSE Function(
        Pointer<OCSP_RESPONSE>,
        Pointer<Pointer<Uint8>>,
        Long,
      )
    >;
typedef d2i_OCSP_RESPONSEDart =
    OCSP_RESPONSE Function(
      Pointer<OCSP_RESPONSE> a,
      Pointer<Pointer<Uint8>> inp,
      int len,
    );

typedef X509_get0_pubkey_bitstrNative =
    NativeFunction<ASN1_BIT_STRING Function(X509)>;
typedef X509_get0_pubkey_bitstrDart = ASN1_BIT_STRING Function(X509 x);

typedef X509_REQ_newNative = NativeFunction<X509_REQ Function()>;
typedef X509_REQ_newDart = X509_REQ Function();

typedef X509_REQ_freeNative = NativeFunction<Void Function(X509_REQ)>;
typedef X509_REQ_freeDart = void Function(X509_REQ req);

typedef X509_REQ_set_versionNative =
    NativeFunction<Int Function(X509_REQ, Long)>;
typedef X509_REQ_set_versionDart = int Function(X509_REQ req, int version);

typedef X509_REQ_set_subject_nameNative =
    NativeFunction<Int Function(X509_REQ, X509_NAME)>;
typedef X509_REQ_set_subject_nameDart =
    int Function(X509_REQ req, X509_NAME name);

typedef X509_REQ_get_subject_nameNative =
    NativeFunction<X509_NAME Function(X509_REQ)>;
typedef X509_REQ_get_subject_nameDart = X509_NAME Function(X509_REQ req);

typedef X509_REQ_set_pubkeyNative =
    NativeFunction<Int Function(X509_REQ, EVP_PKEY)>;
typedef X509_REQ_set_pubkeyDart = int Function(X509_REQ req, EVP_PKEY pkey);

typedef X509_REQ_get_pubkeyNative = NativeFunction<EVP_PKEY Function(X509_REQ)>;
typedef X509_REQ_get_pubkeyDart = EVP_PKEY Function(X509_REQ req);

typedef X509_REQ_signNative =
    NativeFunction<Int Function(X509_REQ, EVP_PKEY, EVP_MD)>;
typedef X509_REQ_signDart =
    int Function(X509_REQ req, EVP_PKEY pkey, EVP_MD md);

typedef X509_REQ_add_extensionsNative =
    NativeFunction<Int Function(X509_REQ, Pointer<Void>)>;
typedef X509_REQ_add_extensionsDart =
    int Function(X509_REQ req, Pointer<Void> exts);

typedef PEM_read_bio_X509_REQNative =
    NativeFunction<
      X509_REQ Function(
        BIO,
        Pointer<X509_REQ>,
        Pointer<NativeFunction<Void Function()>>,
        Pointer<Void>,
      )
    >;
typedef PEM_read_bio_X509_REQDart =
    X509_REQ Function(
      BIO bp,
      Pointer<X509_REQ> x,
      Pointer<NativeFunction<Void Function()>> cb,
      Pointer<Void> u,
    );

typedef PEM_write_bio_X509_REQNative =
    NativeFunction<Int Function(BIO, X509_REQ)>;
typedef PEM_write_bio_X509_REQDart = int Function(BIO bp, X509_REQ req);

typedef i2d_X509_REQ_bioNative = NativeFunction<Int Function(BIO, X509_REQ)>;
typedef i2d_X509_REQ_bioDart = int Function(BIO bp, X509_REQ req);

typedef CMS_signed_add1_attr_by_txtNative =
    NativeFunction<
      Int Function(CMS_SignerInfo, Pointer<Utf8>, Int, Pointer<Void>, Int)
    >;
typedef CMS_signed_add1_attr_by_txtDart =
    int Function(
      CMS_SignerInfo si,
      Pointer<Utf8> attrName,
      int attrNid,
      Pointer<Void> bytes,
      int len,
    );

typedef CMS_add0_certNative =
    NativeFunction<Int Function(CMS_ContentInfo, X509)>;
typedef CMS_add0_certDart = int Function(CMS_ContentInfo cms, X509 x);

typedef CMS_add0_crlNative =
    NativeFunction<Int Function(CMS_ContentInfo, Pointer<Void>)>;
typedef CMS_add0_crlDart = int Function(CMS_ContentInfo cms, Pointer<Void> crl);

typedef CMS_get0_signersNative =
    NativeFunction<Pointer<Void> Function(CMS_ContentInfo)>;
typedef CMS_get0_signersDart = Pointer<Void> Function(CMS_ContentInfo cms);

typedef CMS_SignerInfo_get0_signer_idNative =
    NativeFunction<
      Void Function(
        CMS_SignerInfo,
        Pointer<X509_NAME>,
        Pointer<ASN1_INTEGER>,
        Pointer<ASN1_OBJECT>,
      )
    >;
typedef CMS_SignerInfo_get0_signer_idDart =
    void Function(
      CMS_SignerInfo si,
      Pointer<X509_NAME> sid,
      Pointer<ASN1_INTEGER> serial,
      Pointer<ASN1_OBJECT> algo,
    );

typedef BIO_new_fileNative =
    NativeFunction<BIO Function(Pointer<Utf8>, Pointer<Utf8>)>;
typedef BIO_new_fileDart =
    BIO Function(Pointer<Utf8> filename, Pointer<Utf8> mode);

typedef BIO_ctrlNative =
    NativeFunction<Long Function(BIO, Int, Long, Pointer<Void>)>;
typedef BIO_ctrlDart =
    int Function(BIO bp, int cmd, int larg, Pointer<Void> parg);

typedef i2d_X509_bioNative = NativeFunction<Int Function(BIO, X509)>;
typedef i2d_X509_bioDart = int Function(BIO bp, X509 x);

typedef d2i_X509_bioNative = NativeFunction<X509 Function(BIO, Pointer<X509>)>;
typedef d2i_X509_bioDart = X509 Function(BIO bp, Pointer<X509> x);

typedef OBJ_txt2nidNative = NativeFunction<Int Function(Pointer<Utf8>)>;
typedef OBJ_txt2nidDart = int Function(Pointer<Utf8> s);

typedef d2i_ASN1_TYPE_bioNative =
    NativeFunction<ASN1_TYPE Function(BIO, Pointer<ASN1_TYPE>)>;
typedef d2i_ASN1_TYPE_bioDart =
    ASN1_TYPE Function(BIO bp, Pointer<ASN1_TYPE> x);

typedef ASN1_TYPE_freeNative = NativeFunction<Void Function(ASN1_TYPE)>;
typedef ASN1_TYPE_freeDart = void Function(ASN1_TYPE a);

typedef ASN1_TYPE_getNative = NativeFunction<Int Function(ASN1_TYPE)>;
typedef ASN1_TYPE_getDart = int Function(ASN1_TYPE a);

typedef ASN1_tag2strNative = NativeFunction<Pointer<Utf8> Function(Int)>;
typedef ASN1_tag2strDart = Pointer<Utf8> Function(int tag);


class OpenSslBindings {
  final DynamicLibrary _crypto;
  // ignore: unused_field — libssl may be used for fallback symbol lookups
  final DynamicLibrary _ssl;

  OpenSslBindings._(this._crypto, this._ssl);

  factory OpenSslBindings.create(DynamicLibrary crypto, DynamicLibrary ssl) {
    return OpenSslBindings._(crypto, ssl);
  }


  late final OpenSSLVersionDart openSSLVersion = _crypto
      .lookup<OpenSSLVersionNative>('OpenSSL_version')
      .asFunction<OpenSSLVersionDart>();
  late final OSSL_PROVIDER_loadDart osslProviderLoad = _crypto
      .lookup<OSSL_PROVIDER_loadNative>('OSSL_PROVIDER_load')
      .asFunction<OSSL_PROVIDER_loadDart>();


  late final RAND_bytesDart randBytes = _crypto
      .lookup<RAND_bytesNative>('RAND_bytes')
      .asFunction<RAND_bytesDart>();
  late final RAND_priv_bytesDart randPrivBytes = _crypto
      .lookup<RAND_priv_bytesNative>('RAND_priv_bytes')
      .asFunction<RAND_priv_bytesDart>();


  late final ERR_get_errorDart errGetError = _crypto
      .lookup<ERR_get_errorNative>('ERR_get_error')
      .asFunction<ERR_get_errorDart>();
  late final ERR_clear_errorDart errClearError = _crypto
      .lookup<ERR_clear_errorNative>('ERR_clear_error')
      .asFunction<ERR_clear_errorDart>();
  late final ERR_error_string_nDart errErrorStringN = _crypto
      .lookup<ERR_error_string_nNative>('ERR_error_string_n')
      .asFunction<ERR_error_string_nDart>();


  late final CRYPTO_freeDart cryptoFree = _crypto
      .lookup<CRYPTO_freeNative>('CRYPTO_free')
      .asFunction<CRYPTO_freeDart>();
  late final OPENSSL_cleanseDart opensslCleanse = _crypto
      .lookup<OPENSSL_cleanseNative>('OPENSSL_cleanse')
      .asFunction<OPENSSL_cleanseDart>();
  late final ASN1_INTEGER_to_BNDart asn1IntegerToBn = _crypto
      .lookup<ASN1_INTEGER_to_BNNative>('ASN1_INTEGER_to_BN')
      .asFunction<ASN1_INTEGER_to_BNDart>();
  late final BN_bn2hexDart bnToHex = _crypto
      .lookup<BN_bn2hexNative>('BN_bn2hex')
      .asFunction<BN_bn2hexDart>();


  late final EVP_MD_CTX_newDart evpMdCtxNew = _crypto
      .lookup<EVP_MD_CTX_newNative>('EVP_MD_CTX_new')
      .asFunction<EVP_MD_CTX_newDart>();
  late final EVP_MD_CTX_freeDart evpMdCtxFree = _crypto
      .lookup<EVP_MD_CTX_freeNative>('EVP_MD_CTX_free')
      .asFunction<EVP_MD_CTX_freeDart>();
  late final EVP_default_properties_is_fipsDart evpDefaultPropertiesIsFips =
      _crypto
          .lookup<EVP_default_properties_is_fipsNative>(
              'EVP_default_properties_is_fips')
          .asFunction<EVP_default_properties_is_fipsDart>();
  late final EVP_DigestInit_exDart evpDigestInitEx = _crypto
      .lookup<EVP_DigestInit_exNative>('EVP_DigestInit_ex')
      .asFunction<EVP_DigestInit_exDart>();
  late final EVP_DigestUpdateDart evpDigestUpdate = _crypto
      .lookup<EVP_DigestUpdateNative>('EVP_DigestUpdate')
      .asFunction<EVP_DigestUpdateDart>();
  late final EVP_DigestFinal_exDart evpDigestFinalEx = _crypto
      .lookup<EVP_DigestFinal_exNative>('EVP_DigestFinal_ex')
      .asFunction<EVP_DigestFinal_exDart>();
  late final EVP_sha256Dart evpSha256 = _crypto
      .lookup<EVP_sha256Native>('EVP_sha256')
      .asFunction<EVP_sha256Dart>();
  late final EVP_sha512Dart evpSha512 = _crypto
      .lookup<EVP_sha512Native>('EVP_sha512')
      .asFunction<EVP_sha512Dart>();
  late final EVP_sha384Dart evpSha384 = _crypto
      .lookup<EVP_sha384Native>('EVP_sha384')
      .asFunction<EVP_sha384Dart>();
  late final EVP_sha3_256Dart evpSha3_256 = _crypto
      .lookup<EVP_sha3_256Native>('EVP_sha3_256')
      .asFunction<EVP_sha3_256Dart>();
  late final EVP_sha3_512Dart evpSha3_512 = _crypto
      .lookup<EVP_sha3_512Native>('EVP_sha3_512')
      .asFunction<EVP_sha3_512Dart>();


  late final EVP_CIPHER_CTX_newDart evpCipherCtxNew = _crypto
      .lookup<EVP_CIPHER_CTX_newNative>('EVP_CIPHER_CTX_new')
      .asFunction<EVP_CIPHER_CTX_newDart>();
  late final EVP_CIPHER_CTX_freeDart evpCipherCtxFree = _crypto
      .lookup<EVP_CIPHER_CTX_freeNative>('EVP_CIPHER_CTX_free')
      .asFunction<EVP_CIPHER_CTX_freeDart>();
  late final EVP_CIPHER_CTX_ctrlDart evpCipherCtxCtrl = _crypto
      .lookup<EVP_CIPHER_CTX_ctrlNative>('EVP_CIPHER_CTX_ctrl')
      .asFunction<EVP_CIPHER_CTX_ctrlDart>();
  late final EVP_EncryptInit_exDart evpEncryptInitEx = _crypto
      .lookup<EVP_EncryptInit_exNative>('EVP_EncryptInit_ex')
      .asFunction<EVP_EncryptInit_exDart>();
  late final EVP_EncryptUpdateDart evpEncryptUpdate = _crypto
      .lookup<EVP_EncryptUpdateNative>('EVP_EncryptUpdate')
      .asFunction<EVP_EncryptUpdateDart>();
  late final EVP_EncryptFinal_exDart evpEncryptFinalEx = _crypto
      .lookup<EVP_EncryptFinal_exNative>('EVP_EncryptFinal_ex')
      .asFunction<EVP_EncryptFinal_exDart>();
  late final EVP_DecryptInit_exDart evpDecryptInitEx = _crypto
      .lookup<EVP_DecryptInit_exNative>('EVP_DecryptInit_ex')
      .asFunction<EVP_DecryptInit_exDart>();
  late final EVP_DecryptUpdateDart evpDecryptUpdate = _crypto
      .lookup<EVP_DecryptUpdateNative>('EVP_DecryptUpdate')
      .asFunction<EVP_DecryptUpdateDart>();
  late final EVP_DecryptFinal_exDart evpDecryptFinalEx = _crypto
      .lookup<EVP_DecryptFinal_exNative>('EVP_DecryptFinal_ex')
      .asFunction<EVP_DecryptFinal_exDart>();

  late final EVP_aes_128_cbcDart evpAes128Cbc = _crypto
      .lookup<EVP_aes_128_cbcNative>('EVP_aes_128_cbc')
      .asFunction<EVP_aes_128_cbcDart>();
  late final EVP_aes_256_cbcDart evpAes256Cbc = _crypto
      .lookup<EVP_aes_256_cbcNative>('EVP_aes_256_cbc')
      .asFunction<EVP_aes_256_cbcDart>();
  late final EVP_aes_128_gcmDart evpAes128Gcm = _crypto
      .lookup<EVP_aes_128_gcmNative>('EVP_aes_128_gcm')
      .asFunction<EVP_aes_128_gcmDart>();
  late final EVP_aes_256_gcmDart evpAes256Gcm = _crypto
      .lookup<EVP_aes_256_gcmNative>('EVP_aes_256_gcm')
      .asFunction<EVP_aes_256_gcmDart>();


  late final EVP_PKEY_newDart evpPkeyNew = _crypto
      .lookup<EVP_PKEY_newNative>('EVP_PKEY_new')
      .asFunction<EVP_PKEY_newDart>();
  late final EVP_PKEY_freeDart evpPkeyFree = _crypto
      .lookup<EVP_PKEY_freeNative>('EVP_PKEY_free')
      .asFunction<EVP_PKEY_freeDart>();
  late final EVP_PKEY_get_sizeDart evpPkeyGetSize = _crypto
      .lookup<EVP_PKEY_get_sizeNative>('EVP_PKEY_get_size')
      .asFunction<EVP_PKEY_get_sizeDart>();
  late final EVP_PKEY_CTX_newDart evpPkeyCtxNew = _crypto
      .lookup<EVP_PKEY_CTX_newNative>('EVP_PKEY_CTX_new')
      .asFunction<EVP_PKEY_CTX_newDart>();
  late final EVP_PKEY_CTX_new_idDart evpPkeyCtxNewId = _crypto
      .lookup<EVP_PKEY_CTX_new_idNative>('EVP_PKEY_CTX_new_id')
      .asFunction<EVP_PKEY_CTX_new_idDart>();
  late final EVP_PKEY_CTX_freeDart evpPkeyCtxFree = _crypto
      .lookup<EVP_PKEY_CTX_freeNative>('EVP_PKEY_CTX_free')
      .asFunction<EVP_PKEY_CTX_freeDart>();


  late final EVP_PKEY_keygen_initDart evpPkeyKeygenInit = _crypto
      .lookup<EVP_PKEY_keygen_initNative>('EVP_PKEY_keygen_init')
      .asFunction<EVP_PKEY_keygen_initDart>();
  late final EVP_PKEY_keygenDart evpPkeyKeygen = _crypto
      .lookup<EVP_PKEY_keygenNative>('EVP_PKEY_keygen')
      .asFunction<EVP_PKEY_keygenDart>();
  late final EVP_PKEY_CTX_set_rsa_keygen_bitsDart evpPkeyCtxSetRsaKeygenBits =
      _crypto
          .lookup<EVP_PKEY_CTX_set_rsa_keygen_bitsNative>(
            'EVP_PKEY_CTX_set_rsa_keygen_bits',
          )
          .asFunction<EVP_PKEY_CTX_set_rsa_keygen_bitsDart>();
  late final EVP_PKEY_CTX_set_ec_paramgen_curve_nidDart
  evpPkeyCtxSetEcKeygenCurveNid = _crypto
      .lookup<EVP_PKEY_CTX_set_ec_paramgen_curve_nidNative>(
        'EVP_PKEY_CTX_set_ec_paramgen_curve_nid',
      )
      .asFunction<EVP_PKEY_CTX_set_ec_paramgen_curve_nidDart>();


  late final EVP_DigestSignInitDart evpDigestSignInit = _crypto
      .lookup<EVP_DigestSignInitNative>('EVP_DigestSignInit')
      .asFunction<EVP_DigestSignInitDart>();
  late final EVP_DigestSignUpdateDart evpDigestSignUpdate = _crypto
      .lookup<EVP_DigestSignUpdateNative>('EVP_DigestSignUpdate')
      .asFunction<EVP_DigestSignUpdateDart>();
  late final EVP_DigestSignDart evpDigestSign = _crypto
      .lookup<EVP_DigestSignNative>('EVP_DigestSign')
      .asFunction<EVP_DigestSignDart>();
  late final EVP_DigestVerifyInitDart evpDigestVerifyInit = _crypto
      .lookup<EVP_DigestVerifyInitNative>('EVP_DigestVerifyInit')
      .asFunction<EVP_DigestVerifyInitDart>();
  late final EVP_DigestVerifyDart evpDigestVerify = _crypto
      .lookup<EVP_DigestVerifyNative>('EVP_DigestVerify')
      .asFunction<EVP_DigestVerifyDart>();


  late final EVP_PKEY_encrypt_initDart evpPkeyEncryptInit = _crypto
      .lookup<EVP_PKEY_encrypt_initNative>('EVP_PKEY_encrypt_init')
      .asFunction<EVP_PKEY_encrypt_initDart>();
  late final EVP_PKEY_encryptDart evpPkeyEncrypt = _crypto
      .lookup<EVP_PKEY_encryptNative>('EVP_PKEY_encrypt')
      .asFunction<EVP_PKEY_encryptDart>();
  late final EVP_PKEY_decrypt_initDart evpPkeyDecryptInit = _crypto
      .lookup<EVP_PKEY_decrypt_initNative>('EVP_PKEY_decrypt_init')
      .asFunction<EVP_PKEY_decrypt_initDart>();
  late final EVP_PKEY_decryptDart evpPkeyDecrypt = _crypto
      .lookup<EVP_PKEY_decryptNative>('EVP_PKEY_decrypt')
      .asFunction<EVP_PKEY_decryptDart>();
  late final EVP_PKEY_encapsulate_initDart evpPkeyEncapsulateInit = _crypto
      .lookup<EVP_PKEY_encapsulate_initNative>(
          'EVP_PKEY_encapsulate_init')
      .asFunction<EVP_PKEY_encapsulate_initDart>();
  late final EVP_PKEY_encapsulateDart evpPkeyEncapsulate = _crypto
      .lookup<EVP_PKEY_encapsulateNative>('EVP_PKEY_encapsulate')
      .asFunction<EVP_PKEY_encapsulateDart>();
  late final EVP_PKEY_decapsulate_initDart evpPkeyDecapsulateInit = _crypto
      .lookup<EVP_PKEY_decapsulate_initNative>(
          'EVP_PKEY_decapsulate_init')
      .asFunction<EVP_PKEY_decapsulate_initDart>();
  late final EVP_PKEY_decapsulateDart evpPkeyDecapsulate = _crypto
      .lookup<EVP_PKEY_decapsulateNative>('EVP_PKEY_decapsulate')
      .asFunction<EVP_PKEY_decapsulateDart>();


  late final BIO_newDart bioNew = _crypto
      .lookup<BIO_newNative>('BIO_new')
      .asFunction<BIO_newDart>();
  late final BIO_freeDart bioFree = _crypto
      .lookup<BIO_freeNative>('BIO_free')
      .asFunction<BIO_freeDart>();
  late final BIO_s_memDart bioSMem = _crypto
      .lookup<BIO_s_memNative>('BIO_s_mem')
      .asFunction<BIO_s_memDart>();
  late final BIO_new_mem_bufDart bioNewMemBuf = _crypto
      .lookup<BIO_new_mem_bufNative>('BIO_new_mem_buf')
      .asFunction<BIO_new_mem_bufDart>();
  late final BIO_readDart bioRead = _crypto
      .lookup<BIO_readNative>('BIO_read')
      .asFunction<BIO_readDart>();
  late final BIO_writeDart bioWrite = _crypto
      .lookup<BIO_writeNative>('BIO_write')
      .asFunction<BIO_writeDart>();


  late final BN_newDart bnNew = _crypto
      .lookup<BN_newNative>('BN_new')
      .asFunction<BN_newDart>();
  late final BN_freeDart bnFree = _crypto
      .lookup<BN_freeNative>('BN_free')
      .asFunction<BN_freeDart>();
  late final BN_bn2binDart bnBn2bin = _crypto
      .lookup<BN_bn2binNative>('BN_bn2bin')
      .asFunction<BN_bn2binDart>();
  late final BN_bin2bnDart bnBin2bn = _crypto
      .lookup<BN_bin2bnNative>('BN_bin2bn')
      .asFunction<BN_bin2bnDart>();
  late final EVP_PKEY_get_bn_paramDart evpPkeyGetBnParam = _crypto
      .lookup<EVP_PKEY_get_bn_paramNative>('EVP_PKEY_get_bn_param')
      .asFunction<EVP_PKEY_get_bn_paramDart>();
  late final EC_GROUP_new_by_curve_nameDart ecGroupNewByCurveName = _crypto
      .lookup<EC_GROUP_new_by_curve_nameNative>('EC_GROUP_new_by_curve_name')
      .asFunction<EC_GROUP_new_by_curve_nameDart>();
  late final EC_GROUP_get_cofactorDart ecGroupGetCofactor = _crypto
      .lookup<EC_GROUP_get_cofactorNative>('EC_GROUP_get_cofactor')
      .asFunction<EC_GROUP_get_cofactorDart>();
  late final EC_GROUP_freeDart ecGroupFree = _crypto
      .lookup<EC_GROUP_freeNative>('EC_GROUP_free')
      .asFunction<EC_GROUP_freeDart>();


  late final PEM_read_bio_PrivateKeyDart pemReadBioPrivateKey = _crypto
      .lookup<PEM_read_bio_PrivateKeyNative>('PEM_read_bio_PrivateKey')
      .asFunction<PEM_read_bio_PrivateKeyDart>();
  late final PEM_write_bio_PrivateKeyDart pemWriteBioPrivateKey = _crypto
      .lookup<PEM_write_bio_PrivateKeyNative>('PEM_write_bio_PrivateKey')
      .asFunction<PEM_write_bio_PrivateKeyDart>();
  late final PEM_read_bio_PUBKEYDart pemReadBioPubkey = _crypto
      .lookup<PEM_read_bio_PUBKEYNative>('PEM_read_bio_PUBKEY')
      .asFunction<PEM_read_bio_PUBKEYDart>();
  late final PEM_write_bio_PUBKEYDart pemWriteBioPubkey = _crypto
      .lookup<PEM_write_bio_PUBKEYNative>('PEM_write_bio_PUBKEY')
      .asFunction<PEM_write_bio_PUBKEYDart>();


  late final PEM_read_bio_X509Dart pemReadBioX509 = _crypto
      .lookup<PEM_read_bio_X509Native>('PEM_read_bio_X509')
      .asFunction<PEM_read_bio_X509Dart>();
  late final PEM_write_bio_X509Dart pemWriteBioX509 = _crypto
      .lookup<PEM_write_bio_X509Native>('PEM_write_bio_X509')
      .asFunction<PEM_write_bio_X509Dart>();
  late final i2d_CMS_bioDart i2dCmsBio = _crypto
      .lookup<i2d_CMS_bioNative>('i2d_CMS_bio')
      .asFunction<i2d_CMS_bioDart>();
  late final d2i_CMS_bioDart d2iCmsBio = _crypto
      .lookup<d2i_CMS_bioNative>('d2i_CMS_bio')
      .asFunction<d2i_CMS_bioDart>();
  late final X509_newDart x509New = _crypto
      .lookup<X509_newNative>('X509_new')
      .asFunction<X509_newDart>();
  late final X509_freeDart x509Free = _crypto
      .lookup<X509_freeNative>('X509_free')
      .asFunction<X509_freeDart>();
  late final X509_get_subject_nameDart x509GetSubjectName = _crypto
      .lookup<X509_get_subject_nameNative>('X509_get_subject_name')
      .asFunction<X509_get_subject_nameDart>();
  late final X509_get_issuer_nameDart x509GetIssuerName = _crypto
      .lookup<X509_get_issuer_nameNative>('X509_get_issuer_name')
      .asFunction<X509_get_issuer_nameDart>();
  late final X509_get_serialNumberDart x509GetSerialNumber = _crypto
      .lookup<X509_get_serialNumberNative>('X509_get_serialNumber')
      .asFunction<X509_get_serialNumberDart>();
  late final X509_get_notBeforeDart x509GetNotBefore = _crypto
      .lookup<X509_get_notBeforeNative>('X509_get0_notBefore')
      .asFunction<X509_get_notBeforeDart>();
  late final X509_get_notAfterDart x509GetNotAfter = _crypto
      .lookup<X509_get_notAfterNative>('X509_get0_notAfter')
      .asFunction<X509_get_notAfterDart>();

  late final X509_NAME_onelineDart x509NameOneline = _crypto
      .lookup<X509_NAME_onelineNative>('X509_NAME_oneline')
      .asFunction<X509_NAME_onelineDart>();
  late final ASN1_TIME_printDart asn1TimePrint = _crypto
      .lookup<ASN1_TIME_printNative>('ASN1_TIME_print')
      .asFunction<ASN1_TIME_printDart>();


  late final X509_STORE_newDart x509StoreNew = _crypto
      .lookup<X509_STORE_newNative>('X509_STORE_new')
      .asFunction<X509_STORE_newDart>();
  late final X509_STORE_freeDart x509StoreFree = _crypto
      .lookup<X509_STORE_freeNative>('X509_STORE_free')
      .asFunction<X509_STORE_freeDart>();
  late final X509_STORE_add_certDart x509StoreAddCert = _crypto
      .lookup<X509_STORE_add_certNative>('X509_STORE_add_cert')
      .asFunction<X509_STORE_add_certDart>();
  late final X509_STORE_CTX_newDart x509StoreCtxNew = _crypto
      .lookup<X509_STORE_CTX_newNative>('X509_STORE_CTX_new')
      .asFunction<X509_STORE_CTX_newDart>();
  late final X509_STORE_CTX_freeDart x509StoreCtxFree = _crypto
      .lookup<X509_STORE_CTX_freeNative>('X509_STORE_CTX_free')
      .asFunction<X509_STORE_CTX_freeDart>();
  late final X509_STORE_CTX_initDart x509StoreCtxInit = _crypto
      .lookup<X509_STORE_CTX_initNative>('X509_STORE_CTX_init')
      .asFunction<X509_STORE_CTX_initDart>();
  late final X509_STORE_CTX_get0_paramDart x509StoreCtxGet0Param = _crypto
      .lookup<X509_STORE_CTX_get0_paramNative>(
        'X509_STORE_CTX_get0_param',
      )
      .asFunction<X509_STORE_CTX_get0_paramDart>();
  late final X509_VERIFY_PARAM_set_timeDart x509VerifyParamSetTime = _crypto
      .lookup<X509_VERIFY_PARAM_set_timeNative>(
        'X509_VERIFY_PARAM_set_time',
      )
      .asFunction<X509_VERIFY_PARAM_set_timeDart>();
  late final X509_verify_certDart x509VerifyCert = _crypto
      .lookup<X509_verify_certNative>('X509_verify_cert')
      .asFunction<X509_verify_certDart>();
  late final X509_verify_cert_error_stringDart x509VerifyCertErrorString =
      _crypto
          .lookup<X509_verify_cert_error_stringNative>(
            'X509_verify_cert_error_string',
          )
          .asFunction<X509_verify_cert_error_stringDart>();


  late final CMS_signDart cmsSign = _crypto
      .lookup<CMS_signNative>('CMS_sign')
      .asFunction<CMS_signDart>();
  late final CMS_verifyDart cmsVerify = _crypto
      .lookup<CMS_verifyNative>('CMS_verify')
      .asFunction<CMS_verifyDart>();
  late final CMS_encryptDart cmsEncrypt = _crypto
      .lookup<CMS_encryptNative>('CMS_encrypt')
      .asFunction<CMS_encryptDart>();
  late final CMS_decryptDart cmsDecrypt = _crypto
      .lookup<CMS_decryptNative>('CMS_decrypt')
      .asFunction<CMS_decryptDart>();
  late final CMS_ContentInfo_freeDart cmsContentInfoFree = _crypto
      .lookup<CMS_ContentInfo_freeNative>('CMS_ContentInfo_free')
      .asFunction<CMS_ContentInfo_freeDart>();
  late final PEM_read_bio_CMSDart pemReadBioCms = _crypto
      .lookup<PEM_read_bio_CMSNative>('PEM_read_bio_CMS')
      .asFunction<PEM_read_bio_CMSDart>();
  late final PEM_write_bio_CMSDart pemWriteBioCms = _crypto
      .lookup<PEM_write_bio_CMSNative>('PEM_write_bio_CMS')
      .asFunction<PEM_write_bio_CMSDart>();


  late final OPENSSL_sk_new_nullDart osslSkNewNull = _crypto
      .lookup<OPENSSL_sk_new_nullNative>('OPENSSL_sk_new_null')
      .asFunction<OPENSSL_sk_new_nullDart>();
  late final OPENSSL_sk_pushDart osslSkPush = _crypto
      .lookup<OPENSSL_sk_pushNative>('OPENSSL_sk_push')
      .asFunction<OPENSSL_sk_pushDart>();
  late final OPENSSL_sk_freeDart osslSkFree = _crypto
      .lookup<OPENSSL_sk_freeNative>('OPENSSL_sk_free')
      .asFunction<OPENSSL_sk_freeDart>();


  late final OBJ_sn2nidDart objSn2nid = _crypto
      .lookup<OBJ_sn2nidNative>('OBJ_sn2nid')
      .asFunction<OBJ_sn2nidDart>();
  late final OBJ_nid2snDart objNid2sn = _crypto
      .lookup<OBJ_nid2snNative>('OBJ_nid2sn')
      .asFunction<OBJ_nid2snDart>();


  late final X509_set_versionDart x509SetVersion = _crypto
      .lookup<X509_set_versionNative>('X509_set_version')
      .asFunction<X509_set_versionDart>();
  late final X509_set_pubkeyDart x509SetPubkey = _crypto
      .lookup<X509_set_pubkeyNative>('X509_set_pubkey')
      .asFunction<X509_set_pubkeyDart>();
  late final X509_set_issuer_nameDart x509SetIssuerName = _crypto
      .lookup<X509_set_issuer_nameNative>('X509_set_issuer_name')
      .asFunction<X509_set_issuer_nameDart>();
  late final X509_set_subject_nameDart x509SetSubjectName = _crypto
      .lookup<X509_set_subject_nameNative>('X509_set_subject_name')
      .asFunction<X509_set_subject_nameDart>();
  late final X509_signDart x509Sign = _crypto
      .lookup<X509_signNative>('X509_sign')
      .asFunction<X509_signDart>();

  late final X509_get_pubkeyDart x509GetPubkey = _crypto
      .lookup<X509_get_pubkeyNative>('X509_get_pubkey')
      .asFunction<X509_get_pubkeyDart>();


  late final X509_NAME_newDart x509NameNew = _crypto
      .lookup<X509_NAME_newNative>('X509_NAME_new')
      .asFunction<X509_NAME_newDart>();
  late final X509_NAME_freeDart x509NameFree = _crypto
      .lookup<X509_NAME_freeNative>('X509_NAME_free')
      .asFunction<X509_NAME_freeDart>();
  late final X509_NAME_add_entry_by_txtDart x509NameAddEntryByTxt = _crypto
      .lookup<X509_NAME_add_entry_by_txtNative>('X509_NAME_add_entry_by_txt')
      .asFunction<X509_NAME_add_entry_by_txtDart>();


  late final ASN1_TIME_setDart asn1TimeSet = _crypto
      .lookup<ASN1_TIME_setNative>('ASN1_TIME_set')
      .asFunction<ASN1_TIME_setDart>();
  late final X509_set1_notBeforeDart x509SetNotBefore = _crypto
      .lookup<X509_set1_notBeforeNative>('X509_set1_notBefore')
      .asFunction<X509_set1_notBeforeDart>();
  late final X509_set1_notAfterDart x509SetNotAfter = _crypto
      .lookup<X509_set1_notAfterNative>('X509_set1_notAfter')
      .asFunction<X509_set1_notAfterDart>();


  late final X509V3_set_ctxDart x509V3SetCtx = _crypto
      .lookup<X509V3_set_ctxNative>('X509V3_set_ctx')
      .asFunction<X509V3_set_ctxDart>();
  late final X509V3_EXT_conf_nidDart x509V3ExtConfNid = _crypto
      .lookup<X509V3_EXT_conf_nidNative>('X509V3_EXT_conf_nid')
      .asFunction<X509V3_EXT_conf_nidDart>();
  late final X509_add_extDart x509AddExt = _crypto
      .lookup<X509_add_extNative>('X509_add_ext')
      .asFunction<X509_add_extDart>();
  late final X509_EXTENSION_freeDart x509ExtensionFree = _crypto
      .lookup<X509_EXTENSION_freeNative>('X509_EXTENSION_free')
      .asFunction<X509_EXTENSION_freeDart>();


  late final BIO_new_fileDart bioNewFile = _crypto
      .lookup<BIO_new_fileNative>('BIO_new_file')
      .asFunction<BIO_new_fileDart>();
  late final BIO_ctrlDart bioCtrl = _crypto
      .lookup<BIO_ctrlNative>('BIO_ctrl')
      .asFunction<BIO_ctrlDart>();


  late final i2d_X509_bioDart i2dX509Bio = _crypto
      .lookup<i2d_X509_bioNative>('i2d_X509_bio')
      .asFunction<i2d_X509_bioDart>();

  late final d2i_X509_bioDart d2iX509Bio = _crypto
      .lookup<d2i_X509_bioNative>('d2i_X509_bio')
      .asFunction<d2i_X509_bioDart>();


  late final OBJ_txt2nidDart objTxt2nid = _crypto
      .lookup<OBJ_txt2nidNative>('OBJ_txt2nid')
      .asFunction<OBJ_txt2nidDart>();


  late final OBJ_obj2txtDart objObj2txt = _crypto
      .lookup<OBJ_obj2txtNative>('OBJ_obj2txt')
      .asFunction<OBJ_obj2txtDart>();


  late final X509_STORE_CTX_get_errorDart x509StoreCtxGetError = _crypto
      .lookup<X509_STORE_CTX_get_errorNative>('X509_STORE_CTX_get_error')
      .asFunction<X509_STORE_CTX_get_errorDart>();
  late final X509_STORE_CTX_get_error_depthDart x509StoreCtxGetErrorDepth =
      _crypto
          .lookup<X509_STORE_CTX_get_error_depthNative>(
            'X509_STORE_CTX_get_error_depth',
          )
          .asFunction<X509_STORE_CTX_get_error_depthDart>();


  late final X509_get_ext_countDart x509GetExtCount = _crypto
      .lookup<X509_get_ext_countNative>('X509_get_ext_count')
      .asFunction<X509_get_ext_countDart>();
  late final X509_get_extDart x509GetExt = _crypto
      .lookup<X509_get_extNative>('X509_get_ext')
      .asFunction<X509_get_extDart>();
  late final X509_EXTENSION_get_objectDart x509ExtensionGetObject = _crypto
      .lookup<X509_EXTENSION_get_objectNative>('X509_EXTENSION_get_object')
      .asFunction<X509_EXTENSION_get_objectDart>();
  late final X509_EXTENSION_get_dataDart x509ExtensionGetData = _crypto
      .lookup<X509_EXTENSION_get_dataNative>('X509_EXTENSION_get_data')
      .asFunction<X509_EXTENSION_get_dataDart>();
  late final X509V3_EXT_printDart x509V3ExtPrint = _crypto
      .lookup<X509V3_EXT_printNative>('X509V3_EXT_print')
      .asFunction<X509V3_EXT_printDart>();
  late final X509_get_key_usageDart x509GetKeyUsage = _crypto
      .lookup<X509_get_key_usageNative>('X509_get_key_usage')
      .asFunction<X509_get_key_usageDart>();
  late final X509_get_extended_key_usageDart x509GetExtendedKeyUsage = _crypto
      .lookup<X509_get_extended_key_usageNative>('X509_get_extended_key_usage')
      .asFunction<X509_get_extended_key_usageDart>();
  late final X509_get_ext_by_NIDDart x509GetExtByNid = _crypto
      .lookup<X509_get_ext_by_NIDNative>('X509_get_ext_by_NID')
      .asFunction<X509_get_ext_by_NIDDart>();
  late final X509_get_ext_d2iDart x509GetExtD2i = _crypto
      .lookup<X509_get_ext_d2iNative>('X509_get_ext_d2i')
      .asFunction<X509_get_ext_d2iDart>();


  late final ASN1_STRING_get0_dataDart asn1StringGet0Data = _crypto
      .lookup<ASN1_STRING_get0_dataNative>('ASN1_STRING_get0_data')
      .asFunction<ASN1_STRING_get0_dataDart>();
  late final ASN1_STRING_lengthDart asn1StringLength = _crypto
      .lookup<ASN1_STRING_lengthNative>('ASN1_STRING_length')
      .asFunction<ASN1_STRING_lengthDart>();


  late final X509_CRL_newDart x509CrlNew = _crypto
      .lookup<X509_CRL_newNative>('X509_CRL_new')
      .asFunction<X509_CRL_newDart>();
  late final X509_CRL_freeDart x509CrlFree = _crypto
      .lookup<X509_CRL_freeNative>('X509_CRL_free')
      .asFunction<X509_CRL_freeDart>();
  late final d2i_X509_CRL_bioDart d2iX509CrlBio = _crypto
      .lookup<d2i_X509_CRL_bioNative>('d2i_X509_CRL_bio')
      .asFunction<d2i_X509_CRL_bioDart>();
  late final X509_CRL_verifyDart x509CrlVerify = _crypto
      .lookup<X509_CRL_verifyNative>('X509_CRL_verify')
      .asFunction<X509_CRL_verifyDart>();
  late final X509_CRL_get0_lastUpdateDart x509CrlGet0LastUpdate = _crypto
      .lookup<X509_CRL_get0_lastUpdateNative>('X509_CRL_get0_lastUpdate')
      .asFunction<X509_CRL_get0_lastUpdateDart>();
  late final X509_CRL_get0_nextUpdateDart x509CrlGet0NextUpdate = _crypto
      .lookup<X509_CRL_get0_nextUpdateNative>('X509_CRL_get0_nextUpdate')
      .asFunction<X509_CRL_get0_nextUpdateDart>();
  late final X509_CRL_get_REVOKEDDart x509CrlGetRevoked = _crypto
      .lookup<X509_CRL_get_REVOKEDNative>('X509_CRL_get_REVOKED')
      .asFunction<X509_CRL_get_REVOKEDDart>();


  late final OPENSSL_sk_numDart osslSkNum = _crypto
      .lookup<OPENSSL_sk_numNative>('OPENSSL_sk_num')
      .asFunction<OPENSSL_sk_numDart>();
  late final OPENSSL_sk_valueDart osslSkValue = _crypto
      .lookup<OPENSSL_sk_valueNative>('OPENSSL_sk_value')
      .asFunction<OPENSSL_sk_valueDart>();


  late final X509_REVOKED_get0_serialNumberDart x509RevokedGet0SerialNumber =
      _crypto
          .lookup<X509_REVOKED_get0_serialNumberNative>(
            'X509_REVOKED_get0_serialNumber',
          )
          .asFunction<X509_REVOKED_get0_serialNumberDart>();
  late final X509_REVOKED_get0_revocationDateDart
  x509RevokedGet0RevocationDate = _crypto
      .lookup<X509_REVOKED_get0_revocationDateNative>(
        'X509_REVOKED_get0_revocationDate',
      )
      .asFunction<X509_REVOKED_get0_revocationDateDart>();


  late final PEM_read_bio_X509_CRLDart pemReadBioX509Crl = _crypto
      .lookup<PEM_read_bio_X509_CRLNative>('PEM_read_bio_X509_CRL')
      .asFunction<PEM_read_bio_X509_CRLDart>();
  late final PEM_write_bio_X509_CRLDart pemWriteBioX509Crl = _crypto
      .lookup<PEM_write_bio_X509_CRLNative>('PEM_write_bio_X509_CRL')
      .asFunction<PEM_write_bio_X509_CRLDart>();


  late final OCSP_REQUEST_newDart ocspRequestNew = _crypto
      .lookup<OCSP_REQUEST_newNative>('OCSP_REQUEST_new')
      .asFunction<OCSP_REQUEST_newDart>();
  late final OCSP_REQUEST_freeDart ocspRequestFree = _crypto
      .lookup<OCSP_REQUEST_freeNative>('OCSP_REQUEST_free')
      .asFunction<OCSP_REQUEST_freeDart>();
  late final OCSP_request_add0_idDart ocspRequestAdd0Id = _crypto
      .lookup<OCSP_request_add0_idNative>('OCSP_request_add0_id')
      .asFunction<OCSP_request_add0_idDart>();


  late final OCSP_RESPONSE_freeDart ocspResponseFree = _crypto
      .lookup<OCSP_RESPONSE_freeNative>('OCSP_RESPONSE_free')
      .asFunction<OCSP_RESPONSE_freeDart>();
  late final OCSP_response_statusDart ocspResponseStatus = _crypto
      .lookup<OCSP_response_statusNative>('OCSP_response_status')
      .asFunction<OCSP_response_statusDart>();
  late final OCSP_response_get1_basicDart ocspResponseGetBasic = _crypto
      .lookup<OCSP_response_get1_basicNative>('OCSP_response_get1_basic')
      .asFunction<OCSP_response_get1_basicDart>();


  late final OCSP_BASICRESP_freeDart ocspBasicrespFree = _crypto
      .lookup<OCSP_BASICRESP_freeNative>('OCSP_BASICRESP_free')
      .asFunction<OCSP_BASICRESP_freeDart>();
  late final OCSP_basic_verifyDart ocspBasicVerify = _crypto
      .lookup<OCSP_basic_verifyNative>('OCSP_basic_verify')
      .asFunction<OCSP_basic_verifyDart>();
  late final OCSP_resp_find_statusDart ocspRespFindStatus = _crypto
      .lookup<OCSP_resp_find_statusNative>('OCSP_resp_find_status')
      .asFunction<OCSP_resp_find_statusDart>();
  late final OCSP_single_get0_statusDart ocspSingleGet0Status = _crypto
      .lookup<OCSP_single_get0_statusNative>('OCSP_single_get0_status')
      .asFunction<OCSP_single_get0_statusDart>();
  late final OCSP_check_validityDart ocspCheckValidity = _crypto
      .lookup<OCSP_check_validityNative>('OCSP_check_validity')
      .asFunction<OCSP_check_validityDart>();


  late final OCSP_resp_countDart ocspRespCount = _crypto
      .lookup<OCSP_resp_countNative>('OCSP_resp_count')
      .asFunction<OCSP_resp_countDart>();
  late final OCSP_resp_get0Dart ocspRespGet0 = _crypto
      .lookup<OCSP_resp_get0Native>('OCSP_resp_get0')
      .asFunction<OCSP_resp_get0Dart>();
  late final OCSP_resp_get0_produced_atDart ocspRespGet0ProducedAt = _crypto
      .lookup<OCSP_resp_get0_produced_atNative>('OCSP_resp_get0_produced_at')
      .asFunction<OCSP_resp_get0_produced_atDart>();


  late final OCSP_CERTID_freeDart ocspCertidFree = _crypto
      .lookup<OCSP_CERTID_freeNative>('OCSP_CERTID_free')
      .asFunction<OCSP_CERTID_freeDart>();
  late final OCSP_cert_id_newDart ocspCertIdNew = _crypto
      .lookup<OCSP_cert_id_newNative>('OCSP_cert_id_new')
      .asFunction<OCSP_cert_id_newDart>();


  late final i2d_OCSP_REQUESTDart i2dOcspRequest = _crypto
      .lookup<i2d_OCSP_REQUESTNative>('i2d_OCSP_REQUEST')
      .asFunction<i2d_OCSP_REQUESTDart>();
  late final d2i_OCSP_RESPONSEDart d2iOcspResponse = _crypto
      .lookup<d2i_OCSP_RESPONSENative>('d2i_OCSP_RESPONSE')
      .asFunction<d2i_OCSP_RESPONSEDart>();


  late final X509_get0_pubkey_bitstrDart x509Get0PubkeyBitstr = _crypto
      .lookup<X509_get0_pubkey_bitstrNative>('X509_get0_pubkey_bitstr')
      .asFunction<X509_get0_pubkey_bitstrDart>();


  late final X509_REQ_newDart x509ReqNew = _crypto
      .lookup<X509_REQ_newNative>('X509_REQ_new')
      .asFunction<X509_REQ_newDart>();
  late final X509_REQ_freeDart x509ReqFree = _crypto
      .lookup<X509_REQ_freeNative>('X509_REQ_free')
      .asFunction<X509_REQ_freeDart>();
  late final X509_REQ_set_versionDart x509ReqSetVersion = _crypto
      .lookup<X509_REQ_set_versionNative>('X509_REQ_set_version')
      .asFunction<X509_REQ_set_versionDart>();
  late final X509_REQ_set_subject_nameDart x509ReqSetSubjectName = _crypto
      .lookup<X509_REQ_set_subject_nameNative>('X509_REQ_set_subject_name')
      .asFunction<X509_REQ_set_subject_nameDart>();
  late final X509_REQ_get_subject_nameDart x509ReqGetSubjectName = _crypto
      .lookup<X509_REQ_get_subject_nameNative>('X509_REQ_get_subject_name')
      .asFunction<X509_REQ_get_subject_nameDart>();
  late final X509_REQ_set_pubkeyDart x509ReqSetPubkey = _crypto
      .lookup<X509_REQ_set_pubkeyNative>('X509_REQ_set_pubkey')
      .asFunction<X509_REQ_set_pubkeyDart>();
  late final X509_REQ_get_pubkeyDart x509ReqGetPubkey = _crypto
      .lookup<X509_REQ_get_pubkeyNative>('X509_REQ_get_pubkey')
      .asFunction<X509_REQ_get_pubkeyDart>();
  late final X509_REQ_signDart x509ReqSign = _crypto
      .lookup<X509_REQ_signNative>('X509_REQ_sign')
      .asFunction<X509_REQ_signDart>();
  late final X509_REQ_add_extensionsDart x509ReqAddExtensions = _crypto
      .lookup<X509_REQ_add_extensionsNative>('X509_REQ_add_extensions')
      .asFunction<X509_REQ_add_extensionsDart>();
  late final PEM_read_bio_X509_REQDart pemReadBioX509Req = _crypto
      .lookup<PEM_read_bio_X509_REQNative>('PEM_read_bio_X509_REQ')
      .asFunction<PEM_read_bio_X509_REQDart>();
  late final PEM_write_bio_X509_REQDart pemWriteBioX509Req = _crypto
      .lookup<PEM_write_bio_X509_REQNative>('PEM_write_bio_X509_REQ')
      .asFunction<PEM_write_bio_X509_REQDart>();
  late final i2d_X509_REQ_bioDart i2dX509ReqBio = _crypto
      .lookup<i2d_X509_REQ_bioNative>('i2d_X509_REQ_bio')
      .asFunction<i2d_X509_REQ_bioDart>();


  late final CMS_signed_add1_attr_by_txtDart cmsSignedAdd1AttrByTxt = _crypto
      .lookup<CMS_signed_add1_attr_by_txtNative>('CMS_signed_add1_attr_by_txt')
      .asFunction<CMS_signed_add1_attr_by_txtDart>();
  late final CMS_add0_certDart cmsAdd0Cert = _crypto
      .lookup<CMS_add0_certNative>('CMS_add0_cert')
      .asFunction<CMS_add0_certDart>();
  late final CMS_add0_crlDart cmsAdd0Crl = _crypto
      .lookup<CMS_add0_crlNative>('CMS_add0_crl')
      .asFunction<CMS_add0_crlDart>();
  late final CMS_get0_signersDart cmsGet0Signers = _crypto
      .lookup<CMS_get0_signersNative>('CMS_get0_signers')
      .asFunction<CMS_get0_signersDart>();
  late final CMS_SignerInfo_get0_signer_idDart cmsSignerInfoGet0SignerId =
      _crypto
          .lookup<CMS_SignerInfo_get0_signer_idNative>(
            'CMS_SignerInfo_get0_signer_id',
          )
          .asFunction<CMS_SignerInfo_get0_signer_idDart>();


  late final d2i_ASN1_TYPE_bioDart d2iAsn1TypeBio = _crypto
      .lookup<d2i_ASN1_TYPE_bioNative>('d2i_ASN1_TYPE_bio')
      .asFunction<d2i_ASN1_TYPE_bioDart>();
  late final ASN1_TYPE_freeDart asn1TypeFree = _crypto
      .lookup<ASN1_TYPE_freeNative>('ASN1_TYPE_free')
      .asFunction<ASN1_TYPE_freeDart>();
  late final ASN1_TYPE_getDart asn1TypeGet = _crypto
      .lookup<ASN1_TYPE_getNative>('ASN1_TYPE_get')
      .asFunction<ASN1_TYPE_getDart>();
  late final ASN1_tag2strDart asn1Tag2str = _crypto
      .lookup<ASN1_tag2strNative>('ASN1_tag2str')
      .asFunction<ASN1_tag2strDart>();
}
