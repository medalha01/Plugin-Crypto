# Documentacao de Modulos -- PluginCrypto (74 arquivos)

> Versao: 2.0 | Data: 2026-06-14 | Idioma: pt-BR
> Detalhamento extremo: caminho, linhas, classes, assinaturas Dart, funcoes C OpenSSL, fluxo interno, tratamento de erro.

---

## Sumario

1. [Arquitetura Geral](#1-arquitetura-geral)
2. [ffi/ -- Bindings Nativos (2)](#2-ffi)
3. [crypto/ -- Nucleo de Operacoes (16)](#3-crypto)
4. [crypto/models/ -- Modelos de Dados (11)](#4-crypto-models)
5. [crypto/flows/ -- Fluxos de Alto Nivel (8 dirs, 24)](#5-crypto-flows)
6. [metrics/ -- Coleta de Metricas (12)](#6-metrics)
7. [crypto/utils/ -- Utilitarios (9)](#7-crypto-utils)
8. [Tabela Cruzada OpenSSL](#8-tabela-cruzada-openssl)

---

## 1. Arquitetura Geral

```
PluginCryptoAPI (singleton facade, crypto_api.dart)
  |-- CryptoOperations     (hash, random bytes)
  |-- AesOperations        (AES-CBC/GCM)
  |-- AsymmetricOperations (RSA, EC, ML-KEM, ML-DSA)
  |-- X509Operations       (parse, verify chain)
  |-- CmsOperations        (CMS sign/verify/encrypt/decrypt, CAdES)
  |-- CrlOperations  -> CrlVerifier  -> OpenSslCrlVerifier
  |-- OcspOperations -> OcspVerifier -> OpenSslOcspVerifier
  |-- CsrOperations  -> CsrGenerator -> OpenSslCsrGenerator
  |-- TimestampOperations -> TimestampClient -> OpenSslTimestampClient
  +-- OpenSslBindings (FFI, ~120 simbolos C)
        +-- native_loader.dart (DynamicLibrary.open)
```

### Classes de Dados Compartilhadas

| Classe | Arquivo | Descricao |
|--------|---------|-----------|
| `AesGcmResult` | crypto_data.dart:9 | `ciphertext: Uint8List`, `tag: Uint8List` |
| `KeyPair` | crypto_data.dart:15 | `publicKeyPem: String`, `privateKeyPem: String` |
| `X509Certificate` | crypto_data.dart:21 | `subject`, `issuer`, `serialNumber`, `notBefore/After`, `rawDer`, `extensions?` |
| `CertificateData` | certificate_data.dart:8 | `derBytes`, `pemString`, `parsed`, DNs, datas |
| `CryptoResult<T>` | crypto_result.dart:6 | sealed: `CryptoSuccess<T>` \| `CryptoFailure<T>` |
| `CryptoError` | crypto_error.dart:4 | sealed + 12 subclasses tipadas |

### Hierarquia de Erro

```
CryptoError (sealed)
  +-- KeygenError          (keyType, reason, openSslError?)
  +-- CertificateError     (reason, openSslError?)
  +-- FileSigningError     (filePath, reason, openSslError?)
  +-- ValidationError      (field, reason)
  +-- ChainValidationError (chainDetail?, errorDepth?, openSslError?)
  +-- CrlError             (reason, openSslError?)
  +-- X509ExtensionError   (oid?, reason, openSslError?)
  +-- OcspError            (reason, openSslError?)
  +-- Asn1Error            (reason, openSslError?)
  +-- AesGcmAuthFailure    (reason, openSslError?)
  +-- CsrError             (reason, openSslError?)
  +-- TimestampError       (reason, openSslError?)
```

Top-level: `CryptoError mapExceptionToCryptoError(Object e, String operation)` em `crypto_error.dart:179`.

### Constantes Globais (constants.dart)

```
nidRsa=6, nidEc=408, nidMlKem512=1454, nidMlKem768=1455, nidMlKem1024=1456
nidMlDsa44=1457, nidMlDsa65=1458, nidMlDsa87=1459
nidSubjectAltName=85, nidBasicConstraints=87, nidKeyUsage=83, nidExtendedKeyUsage=126
mbstringAsc=0x1000
```

### Extensao KeyPair (extensions/key_pair_extensions.dart)

```dart
extension KeyPairExtensions on KeyPair {
  bool get isRsa          // publicKeyPem.contains('RSA')
  bool get isEc           // publicKeyPem.contains('EC')
  String get keyTypeLabel // 'RSA' / 'EC' / 'Unknown'
}
```

---

## 2. ffi/ -- Bindings Nativos (2 arquivos)

**Agrupa**: chamadas FFI para ~120 funcoes C das bibliotecas libcrypto e libssl.

### 2.1 `ffi/openssl_bindings.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho completo** | `plugin_crypto/lib/src/ffi/openssl_bindings.dart` |
| **Classe** | `OpenSslBindings` (linha 1201) |
| **Construtor** | `factory OpenSslBindings.create(DynamicLibrary crypto, DynamicLibrary ssl)` |

Classe plana de bindings: ~120 campos `late final` resolvidos via `DynamicLibrary.lookup()`. Nao ha fluxo de chamadas -- apenas declaracoes FFI. Nao ha tratamento de erro.

**Inventario de Funcoes C (agrupado por dominio):**

**RAND/ERR:**
| Campo Dart | Simbolo C | Assinatura C |
|------------|-----------|--------------|
| `randBytes` | `RAND_bytes` | `int RAND_bytes(unsigned char *buf, int num)` |
| `randPrivBytes` | `RAND_priv_bytes` | `int RAND_priv_bytes(unsigned char *buf, int num)` |
| `errGetError` | `ERR_get_error` | `unsigned long ERR_get_error(void)` |
| `errClearError` | `ERR_clear_error` | `void ERR_clear_error(void)` |
| `errErrorStringN` | `ERR_error_string_n` | `void ERR_error_string_n(unsigned long e, char *buf, size_t len)` |
| `cryptoFree` | `CRYPTO_free` | `void CRYPTO_free(void *ptr, const char *file, int line)` |

**EVP Digests:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `evpMdCtxNew/Free` | `EVP_MD_CTX_new` / `EVP_MD_CTX_free` |
| `evpDigestInitEx` | `EVP_DigestInit_ex` |
| `evpDigestUpdate` | `EVP_DigestUpdate` |
| `evpDigestFinalEx` | `EVP_DigestFinal_ex` |
| `evpSha256/512/384` | `EVP_sha256/sha512/sha384` |
| `evpSha3_256/512` | `EVP_sha3_256/sha3_512` |

**EVP Cipher:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `evpCipherCtxNew/Free` | `EVP_CIPHER_CTX_new` / `_free` |
| `evpCipherCtxCtrl` | `EVP_CIPHER_CTX_ctrl` (cmds 16=GET_TAG, 17=SET_TAG) |
| `evpEncryptInitEx/Update/FinalEx` | `EVP_EncryptInit_ex/Update/Final_ex` |
| `evpDecryptInitEx/Update/FinalEx` | `EVP_DecryptInit_ex/Update/Final_ex` |
| `evpAes128Cbc/256Cbc` | `EVP_aes_128_cbc` / `EVP_aes_256_cbc` |
| `evpAes128Gcm/256Gcm` | `EVP_aes_128_gcm` / `EVP_aes_256_gcm` |

**EVP PKEY:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `evpPkeyNew/Free/GetSize` | `EVP_PKEY_new/free/get_size` |
| `evpPkeyCtxNew/NewId/Free` | `EVP_PKEY_CTX_new/new_id/free` |
| `evpPkeyKeygenInit/Keygen` | `EVP_PKEY_keygen_init` / `EVP_PKEY_keygen` |
| `evpPkeyCtxSetRsaKeygenBits` | `EVP_PKEY_CTX_set_rsa_keygen_bits` |
| `evpPkeyCtxSetEcKeygenCurveNid` | `EVP_PKEY_CTX_set_ec_paramgen_curve_nid` |
| `evpPkeyEncryptInit/Encrypt` | `EVP_PKEY_encrypt_init` / `EVP_PKEY_encrypt` |
| `evpPkeyDecryptInit/Decrypt` | `EVP_PKEY_decrypt_init` / `EVP_PKEY_decrypt` |
| `evpPkeyEncapsulateInit/Encapsulate` | `EVP_PKEY_encapsulate_init` / `EVP_PKEY_encapsulate` |
| `evpPkeyDecapsulateInit/Decapsulate` | `EVP_PKEY_decapsulate_init` / `EVP_PKEY_decapsulate` |

**EVP Sign/Verify:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `evpDigestSignInit` | `EVP_DigestSignInit` |
| `evpDigestSignUpdate` | `EVP_DigestSignUpdate` |
| `evpDigestSign` | `EVP_DigestSign` |
| `evpDigestVerifyInit` | `EVP_DigestVerifyInit` |
| `evpDigestVerify` | `EVP_DigestVerify` |

**BIO:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `bioNew/Free` | `BIO_new` / `BIO_free` |
| `bioSMem` | `BIO_s_mem` |
| `bioNewMemBuf` | `BIO_new_mem_buf` |
| `bioRead/Write` | `BIO_read` / `BIO_write` |
| `bioNewFile` | `BIO_new_file` |
| `bioCtrl` | `BIO_ctrl` |

**PEM:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `pemReadBioPrivateKey` | `PEM_read_bio_PrivateKey` |
| `pemWriteBioPrivateKey` | `PEM_write_bio_PrivateKey` |
| `pemReadBioPubkey` | `PEM_read_bio_PUBKEY` |
| `pemWriteBioPubkey` | `PEM_write_bio_PUBKEY` |
| `pemReadBioX509` | `PEM_read_bio_X509` |
| `pemWriteBioX509` | `PEM_write_bio_X509` |
| `pemReadBioX509Crl` | `PEM_read_bio_X509_CRL` |
| `pemWriteBioX509Crl` | `PEM_write_bio_X509_CRL` |
| `pemReadBioCms` | `PEM_read_bio_CMS` |
| `pemWriteBioCms` | `PEM_write_bio_CMS` |
| `pemReadBioX509Req` | `PEM_read_bio_X509_REQ` |
| `pemWriteBioX509Req` | `PEM_write_bio_X509_REQ` |

**X509:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `x509New/Free` | `X509_new` / `X509_free` |
| `x509GetSubjectName/IssuerName` | `X509_get_subject_name` / `X509_get_issuer_name` |
| `x509GetSerialNumber` | `X509_get_serialNumber` |
| `x509GetNotBefore/NotAfter` | `X509_get0_notBefore` / `X509_get0_notAfter` |
| `x509GetPubkey` | `X509_get_pubkey` |
| `x509Get0PubkeyBitstr` | `X509_get0_pubkey_bitstr` |
| `x509SetVersion` | `X509_set_version` |
| `x509SetPubkey` | `X509_set_pubkey` |
| `x509SetSubjectName/IssuerName` | `X509_set_subject_name` / `X509_set_issuer_name` |
| `x509SetNotBefore/NotAfter` | `X509_set1_notBefore` / `X509_set1_notAfter` |
| `x509Sign` | `X509_sign` |
| `i2dX509Bio` / `d2iX509Bio` | `i2d_X509_bio` / `d2i_X509_bio` |
| `x509NameOneline` | `X509_NAME_oneline` |
| `asn1TimePrint` | `ASN1_TIME_print` |
| `asn1TimeSet` | `ASN1_TIME_set` |

**X509 Extensoes:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `x509GetExtCount` | `X509_get_ext_count` |
| `x509GetExt` | `X509_get_ext` |
| `x509ExtensionGetObject` | `X509_EXTENSION_get_object` |
| `x509ExtensionGetData` | `X509_EXTENSION_get_data` |
| `x509GetKeyUsage` | `X509_get_key_usage` |
| `x509GetExtendedKeyUsage` | `X509_get_extended_key_usage` |
| `x509GetExtByNid` | `X509_get_ext_by_NID` |
| `x509GetExtD2i` | `X509_get_ext_d2i` |
| `x509V3SetCtx` | `X509V3_set_ctx` |
| `x509V3ExtConfNid` | `X509V3_EXT_conf_nid` |
| `x509V3ExtPrint` | `X509V3_EXT_print` |
| `x509AddExt` | `X509_add_ext` |
| `x509ExtensionFree` | `X509_EXTENSION_free` |

**X509_STORE (verificacao de cadeia):**
| Campo Dart | Simbolo C |
|------------|-----------|
| `x509StoreNew/Free` | `X509_STORE_new` / `X509_STORE_free` |
| `x509StoreAddCert` | `X509_STORE_add_cert` |
| `x509StoreCtxNew/Free` | `X509_STORE_CTX_new` / `X509_STORE_CTX_free` |
| `x509StoreCtxInit` | `X509_STORE_CTX_init` |
| `x509StoreCtxGet0Param` | `X509_STORE_CTX_get0_param` |
| `x509StoreCtxGetError` | `X509_STORE_CTX_get_error` |
| `x509StoreCtxGetErrorDepth` | `X509_STORE_CTX_get_error_depth` |
| `x509VerifyParamSetTime` | `X509_VERIFY_PARAM_set_time` |
| `x509VerifyCert` | `X509_verify_cert` |
| `x509VerifyCertErrorString` | `X509_verify_cert_error_string` |

**X509_CRL:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `x509CrlNew/Free` | `X509_CRL_new` / `X509_CRL_free` |
| `d2iX509CrlBio` | `d2i_X509_CRL_bio` |
| `x509CrlVerify` | `X509_CRL_verify` |
| `x509CrlGet0LastUpdate/NextUpdate` | `X509_CRL_get0_lastUpdate` / `X509_CRL_get0_nextUpdate` |
| `x509CrlGetRevoked` | `X509_CRL_get_REVOKED` |

**X509_REQ (CSR):**
| Campo Dart | Simbolo C |
|------------|-----------|
| `x509ReqNew/Free` | `X509_REQ_new` / `X509_REQ_free` |
| `x509ReqSetVersion` | `X509_REQ_set_version` |
| `x509ReqSetSubjectName` | `X509_REQ_set_subject_name` |
| `x509ReqGetSubjectName` | `X509_REQ_get_subject_name` |
| `x509ReqSetPubkey` | `X509_REQ_set_pubkey` |
| `x509ReqGetPubkey` | `X509_REQ_get_pubkey` |
| `x509ReqSign` | `X509_REQ_sign` |
| `x509ReqAddExtensions` | `X509_REQ_add_extensions` |
| `i2dX509ReqBio` | `i2d_X509_REQ_bio` |

**BN (BigNum):**
| Campo Dart | Simbolo C |
|------------|-----------|
| `bnNew/Free` | `BN_new` / `BN_free` |
| `bnBn2bin` / `bnBin2bn` | `BN_bn2bin` / `BN_bin2bn` |

**CMS:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `cmsSign` | `CMS_sign` |
| `cmsVerify` | `CMS_verify` |
| `cmsEncrypt` | `CMS_encrypt` |
| `cmsDecrypt` | `CMS_decrypt` |
| `cmsContentInfoFree` | `CMS_ContentInfo_free` |
| `cmsGet0Signers` | `CMS_get0_signers` |
| `cmsSignerInfoGet0SignerId` | `CMS_SignerInfo_get0_signer_id` |
| `cmsSignedAdd1AttrByTxt` | `CMS_signed_add1_attr_by_txt` |
| `cmsAdd0Cert` | `CMS_add0_cert` |
| `cmsAdd0Crl` | `CMS_add0_crl` |

**OCSP:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `ocspRequestNew/Free` | `OCSP_REQUEST_new` / `OCSP_REQUEST_free` |
| `ocspRequestAdd0Id` | `OCSP_request_add0_id` |
| `ocspCertIdNew` | `OCSP_cert_id_new` |
| `ocspCertidFree` | `OCSP_CERTID_free` |
| `ocspResponseFree` | `OCSP_RESPONSE_free` |
| `ocspResponseStatus` | `OCSP_response_status` |
| `ocspResponseGetBasic` | `OCSP_response_get1_basic` |
| `ocspBasicrespFree` | `OCSP_BASICRESP_free` |
| `ocspBasicVerify` | `OCSP_basic_verify` |
| `ocspRespCount` | `OCSP_resp_count` |
| `ocspRespGet0` | `OCSP_resp_get0` |
| `ocspSingleGet0Status` | `OCSP_single_get0_status` |
| `ocspRespGet0ProducedAt` | `OCSP_resp_get0_produced_at` |
| `ocspCheckValidity` | `OCSP_check_validity` |
| `i2dOcspRequest` | `i2d_OCSP_REQUEST` |
| `d2iOcspResponse` | `d2i_OCSP_RESPONSE` |

**OPENSSL Stack / OBJ / ASN1 aux:**
| Campo Dart | Simbolo C |
|------------|-----------|
| `osslSkNewNull/Push/Free` | `OPENSSL_sk_new_null` / `_push` / `_free` |
| `osslSkNum/Value` | `OPENSSL_sk_num` / `OPENSSL_sk_value` |
| `objSn2nid` / `objNid2sn` | `OBJ_sn2nid` / `OBJ_nid2sn` |
| `objTxt2nid` / `objObj2txt` | `OBJ_txt2nid` / `OBJ_obj2txt` |
| `x509NameNew/Free` | `X509_NAME_new` / `X509_NAME_free` |
| `x509NameAddEntryByTxt` | `X509_NAME_add_entry_by_txt` |
| `asn1StringGet0Data/Length` | `ASN1_STRING_get0_data` / `ASN1_STRING_length` |
| `x509RevokedGet0SerialNumber` | `X509_REVOKED_get0_serialNumber` |
| `x509RevokedGet0RevocationDate` | `X509_REVOKED_get0_revocationDate` |
| `d2iAsn1TypeBio` | `d2i_ASN1_TYPE_bio` |
| `asn1TypeFree/Get` | `ASN1_TYPE_free` / `ASN1_TYPE_get` |
| `asn1Tag2str` | `ASN1_tag2str` |

### 2.2 `ffi/native_loader.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/ffi/native_loader.dart` |
| **Classes** | Nenhuma (funcoes top-level) |

#### Assinaturas Publicas
```dart
DynamicLibrary loadCrypto()
DynamicLibrary loadSsl()
```

#### Funcoes C Chamadas
Nenhuma diretamente. Usa `DynamicLibrary.open()` com nomes de biblioteca por plataforma.

#### Fluxo Interno
1. `_resolveNativeDir()`: verifica env var `PLUGIN_CRYPTO_NATIVE_DIR`, depois `cwd/native/linux/x86_64`. Retorna `null` em falha.
2. `loadCrypto()`: tenta Android (`libcrypto.so`) -> iOS (`DynamicLibrary.process()`) -> Linux (env dir -> `libcrypto.so` -> `libcrypto.so.4` -> `libcrypto.so.3`)
3. `loadSsl()`: mesmo padrao com `libssl.so`, `libssl.so.4`, `libssl.so.3`
4. Fallback final: `throw UnsupportedError('Platform ... is not supported by PluginCrypto.')`

#### Tratamento de Erro
- Cadeia de try/catch com catch blocks vazios para fallback silencioso entre nomes de SO
- `UnsupportedError` como ultimo recurso

---

## 3. crypto/ -- Nucleo de Operacoes (16 arquivos)

**Reune**: todas as operacoes criptograficas core expostas pela fachada PluginCryptoAPI.

### 3.1 `crypto/crypto_operations.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/crypto_operations.dart` |
| **Classe** | `CryptoOperations` |

#### Assinaturas Publicas
```dart
Uint8List randomBytes(int length)
Uint8List sha256(Uint8List data)
Uint8List sha512(Uint8List data)
Uint8List sha3_256(Uint8List data)
Uint8List sha3_512(Uint8List data)
```

#### Privados
```dart
Uint8List _digest(Uint8List data, Pointer<Void> md, int digestLen)
void _check1(int result, String op)  // result != 1 -> StateError
Never _fail(String op)               // sempre lanca StateError
```

#### Funcoes C Chamadas
`RAND_bytes(unsigned char *buf, int num)`, `EVP_MD_CTX_new(void)`, `EVP_DigestInit_ex(ctx, md, nullptr)`, `EVP_DigestUpdate(ctx, d, cnt)`, `EVP_DigestFinal_ex(ctx, md, s)`, `EVP_MD_CTX_free(ctx)`, `EVP_sha256/sha512(void)`, `EVP_sha3_256/sha3_512(void)`, `ERR_get_error(void)`, `ERR_clear_error(void)`

#### Fluxo Interno
```
sha256/512/3-256/3-512(data) -> _digest(data, md, digestLen)
  |-- evpMdCtxNew()
  |-- evpDigestInitEx(ctx, md, nullptr)
  |-- calloc<Uint8>(data.length) -> copia dados -> evpDigestUpdate(ctx, dp, len)
  |-- calloc<Uint8>(digestLen) + calloc<Uint32>(1) -> evpDigestFinalEx(ctx, mdBuf, mdLen)
  |-- Retorna Uint8List.sublist(0, mdLen.value)
  +-- finally: calloc.free(dp, mdBuf, mdLen), evpMdCtxFree(ctx)

randomBytes(length):
  |-- calloc<Uint8>(length) -> randBytes(buf, length) [via _check1]
  +-- finally: calloc.free(buf)
```

#### Tratamento de Erro
- `_check1(result, op)`: se `result != 1`, chama `getOpenSslError(_b)` + `errClearError()`, lanca `StateError`
- Blocos `try/finally` aninhados (profundidade 4) em `_digest`

### 3.2 `crypto/aes_operations.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/aes_operations.dart` |
| **Classe** | `AesOperations` |

#### Assinaturas Publicas
```dart
Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)
Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)
Uint8List aes256CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)
Uint8List aes256CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)
AesGcmResult aes128GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})
Uint8List aes128GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})
AesGcmResult aes256GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})
Uint8List aes256GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})
```

#### Funcoes C Chamadas
`EVP_CIPHER_CTX_new/free`, `EVP_EncryptInit_ex/Update/Final_ex`, `EVP_DecryptInit_ex/Update/Final_ex`, `EVP_CIPHER_CTX_ctrl(ctx, SET_TAG=17/GET_TAG=16, arg, ptr)`, `EVP_aes_128_cbc/256_cbc/128_gcm/256_gcm`, `ERR_get_error/clear_error`

#### Fluxo Interno
```
_cipherOp (CBC): evpCipherCtxNew() -> EncryptInit/DecryptInit -> Update -> Final -> evpCipherCtxFree()
  + Validacao: IV 16 bytes, key 16 (AES-128) ou 32 (AES-256) bytes

_gcmCipherOp (GCM): igual + SET_TAG (decrypt, cmd=17) + AAD via Update(nullptr out) + GET_TAG (encrypt, cmd=16)
```

#### Tratamento de Erro
- `_validateAesInputs`: `ArgumentError` se `iv.length != 16`
- `_validateAesKeyLength`: `ArgumentError` se `key.length != expectedKeyLen`
- `_check1`: `StateError` com erro OpenSSL, EXCETO `EVP_DecryptFinal_ex(GCM)` que lanca `AesGcmAuthFailure`
- Blocos `try/finally` aninhados (profundidade 6) garantem liberacao de memoria nativa

### 3.3 `crypto/asymmetric_operations.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/asymmetric_operations.dart` |
| **Classe** | `AsymmetricOperations` |

#### Assinaturas Publicas
```dart
KeyPair generateRsaKeyPair(int bits)
KeyPair generateEcKeyPair(String curveName)
Uint8List sign(Uint8List data, Uint8List privateKeyPem, {String hashAlgorithm = 'sha256'})
bool verify(Uint8List data, Uint8List publicKeyPem, Uint8List signature, {String hashAlgorithm = 'sha256'})
Uint8List rsaEncrypt(Uint8List publicKeyPem, Uint8List plaintext)
Uint8List rsaDecrypt(Uint8List privateKeyPem, Uint8List ciphertext)
({Uint8List ciphertext, Uint8List sharedSecret}) mlKemEncapsulate(Uint8List publicKeyPem)
Uint8List mlKemDecapsulate(Uint8List privateKeyPem, Uint8List ciphertext)
```

#### Funcoes C Chamadas
`EVP_PKEY_CTX_new_id(6/408)`, `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_rsa_keygen_bits`, `EVP_PKEY_CTX_set_ec_paramgen_curve_nid`, `EVP_PKEY_keygen`, `EVP_DigestSignInit` (fallback md=nullptr para ML-DSA), `EVP_DigestSign` (2-pass), `EVP_DigestVerifyInit/Verify`, `EVP_PKEY_encrypt_init/encrypt` (2-pass), `EVP_PKEY_decrypt_init/decrypt` (2-pass), `EVP_PKEY_encapsulate_init/encapsulate` (2-pass), `EVP_PKEY_decapsulate_init/decapsulate` (2-pass), `OBJ_sn2nid`, `PEM_read/write_bio_PrivateKey/PUBKEY`, `BIO_new/free`, `BIO_s_mem`

#### Fluxo -- Destaques
```
generateRsaKeyPair(bits):
  evpPkeyCtxNewId(6, nullptr) -> keygenInit -> setRsaKeygenBits(bits)
  -> keygen -> _extractKeyPair (PEM_write_bio_PUBKEY + PEM_write_bio_PrivateKey)

sign(data, privKeyPem, hashAlg):
  _loadPrivateKey -> switch hashAlg: evpSha256/384/512/3-256
  -> evpDigestSignInit (fallback md=nullptr para ML-DSA)
  -> evpDigestSign (2-pass: probe length + sign)
```

### 3.4 `crypto/cms_operations.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/cms_operations.dart` |
| **Classe** | `CmsOperations` |

#### Assinaturas Publicas
```dart
Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem)
bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert})
Uint8List cmsEncrypt(Uint8List data, Uint8List certPem)
Uint8List cmsDecrypt(Uint8List encryptedData, Uint8List certPem, Uint8List keyPem)
Uint8List cmsSignCades(Uint8List data, Uint8List certPem, Uint8List keyPem,
    {Uint8List? caCertPem, List<Uint8List>? intermediates,
     bool addSigningTime = true, bool addMessageDigest = true})
```

#### Funcoes C Chamadas
`CMS_sign(cert, pkey, certs, data, flags)`, `CMS_verify(cms, certs, store, dcont, out, flags)`, `CMS_encrypt(certs, in, cipher, flags)`, `CMS_decrypt(cms, pkey, cert, dcont, out, flags)`, `CMS_ContentInfo_free`, `CMS_get0_signers`, `CMS_signed_add1_attr_by_txt`, `OPENSSL_sk_new_null/push/free`, `X509_STORE_new/free/add_cert`, `PEM_read_bio_X509/CMS`, `PEM_write_bio_CMS`, `EVP_aes_256_cbc`

#### Fluxo
```
cmsSign: bioFromData(cert) -> pemReadBioX509 -> _loadPrivateKey -> CMS_sign -> _cmsToDer
cmsVerify: X509_STORE_new -> [trustedCert?] -> pemReadBioCms -> CMS_verify(flags=0x200)
cmsEncrypt: pemReadBioX509 -> OPENSSL_sk_push(certs, x509) -> CMS_encrypt(EVP_aes_256_cbc)
cmsDecrypt: pemReadBioCms -> _loadPrivateKey -> CMS_decrypt -> bioToBytes
cmsSignCades: cmsSign + _buildCertStack + flags CAdES + _addSignedAttr(messageDigest)
```

### 3.5 `crypto/crypto_api.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/crypto_api.dart` |
| **Classe** | `PluginCryptoAPI` (singleton) |

Singleton que agrega todos os subsistemas (CryptoOperations, AesOperations, AsymmetricOperations, X509Operations, CmsOperations, CrlOperations, OcspOperations, CsrOperations, TimestampOperations). Metodo `getOpenSSLVersion()` que chama `OpenSSL_version(0)`. Metodos `getLastError()` e `clearErrors()` para a fila de erro OpenSSL.

### 3.6 `crypto/crypto_context.dart`

Interfaces abstratas `CryptoContext` e `CryptographicOperations`. Definem os contratos para hash, assinatura, verificacao, CMS e parsing de certificados.

### 3.7 `crypto/plugin_crypto_context.dart`

`PluginCryptoContext implements CryptoContext`. Implementacao concreta: cria `PluginCryptoOperations(bindings)`.

### 3.8 `crypto/plugin_crypto_operations.dart`

`PluginCryptoOperations implements CryptographicOperations`. Camada de validacao antes de delegar a `PluginCryptoAPI`:
- Valida bits RSA (>=1024, <=16384, multiplo de 1024)
- Valida dados/keys nao-vazios
- `parseX509ToDer`: se ja DER (0x30), retorna direto; senao PEM->X509->i2d_X509_bio->DER
- `parseX509Certificate`: API parse + parseX509ToDer + d2i_X509_bio + PEM_write_bio_X509
- `sha384`: implementacao propria via `_digest(data, evpSha384(), 48)`

### 3.9 `crypto/x509_operations.dart`

| Propriedade | Detalhe |
|-------------|---------|
| **Caminho** | `plugin_crypto/lib/src/crypto/x509_operations.dart` |
| **Classe** | `X509Operations` |

```dart
X509Certificate parseX509Certificate(Uint8List certData)
bool verifyX509Certificate(Uint8List cert, Uint8List caCert)
```

**Fluxo `parseX509Certificate`**: `PEM_read_bio_X509` (tenta PEM) -> se null: `errClearError()` + `d2i_X509_bio` (fallback DER). Depois `_parseX509`: `X509_get_subject_name/issuer_name` -> `X509_NAME_oneline` -> `CRYPTO_free`, `X509_get_serialNumber`, `X509_get0_notBefore/notAfter` -> `parseAsn1Time`, `_parseExt` -> `X509ExtensionParser.parseExtensions`.

**Fluxo `verifyX509Certificate`**: `X509_STORE_new` -> `PEM_read_bio_X509(caCert)` -> `X509_STORE_add_cert` -> `PEM_read_bio_X509(cert)` -> `X509_STORE_CTX_new` -> `X509_STORE_CTX_init` -> `X509_verify_cert`.

### 3.10 `crypto/crl_operations.dart`

Delega para `CrlVerifier` (abstrato), instancia `OpenSslCrlVerifier`:
```dart
CryptoResult<CrlInfo> parseCrl(Uint8List crlData)
CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert)
CryptoResult<CertificateRevocationStatus> checkRevocation(Uint8List certData, Uint8List crlData)
```

### 3.11 `crypto/csr_operations.dart`

Delega para `CsrGenerator` (abstrato), instancia `OpenSslCsrGenerator`:
```dart
CryptoResult<CsrData> generate(CsrRequest request)
```

### 3.12 `crypto/ocsp_operations.dart`

Delega para `OcspVerifier` (abstrato), instancia `OpenSslOcspVerifier`:
```dart
CryptoResult<Uint8List> buildOcspRequest(Uint8List cert, Uint8List issuerCert)
CryptoResult<OcspResponse> verifyOcspResponse(Uint8List ocspRespBytes, Uint8List issuerCert)
```

### 3.13 `crypto/timestamp_operations.dart`

Delega para `TimestampClient` (abstrato), instancia `OpenSslTimestampClient`:
```dart
CryptoResult<Uint8List> createRequest(Uint8List data, {String hashAlgorithm, Uint8List? nonce})
CryptoResult<TimestampResponse> verifyResponse(Uint8List responseData, {Uint8List? cert})
CryptoResult<bool> verify(Uint8List tokenData, Uint8List data)
```

### 3.14 `crypto/crypto_data.dart`

Classes de dados imutaveis: `AesGcmResult`, `KeyPair`, `X509Certificate`.

### 3.15 `crypto/constants.dart`

Constantes NID (RSA=6, EC=408, ML-KEM 512/768/1024=1454-1456, ML-DSA 44/65/87=1457-1459, SAN=85, BasicConstraints=87, KeyUsage=83, EKU=126) e flags (MBSTRING_ASC=0x1000).

### 3.16 `crypto/extensions/key_pair_extensions.dart`

```dart
extension KeyPairExtensions on KeyPair {
  bool get isRsa          // publicKeyPem.contains('RSA')
  bool get isEc           // publicKeyPem.contains('EC')
  String get keyTypeLabel // 'RSA' / 'EC' / 'Unknown'
}
```

---

## 4. crypto/models/ -- Modelos de Dados (11 arquivos)

**Inclui**: tipos selados (CryptoResult, CryptoError, KeySpec), enums e classes de dados imutaveis.

### Resumo por Arquivo

| # | Arquivo | Classes/Enums |
|---|---------|---------------|
| 1 | `asn1_data.dart` | `Asn1TagClass`, `Asn1TagNumber` (static consts), `Asn1Node` |
| 2 | `certificate_data.dart` | `CertificateData`, `X509Extension`, `BasicConstraints`, `X509ParsedExtensions` |
| 3 | `crl_data.dart` | `RevokedEntry`, `CrlInfo`, `CertificateRevocationStatus` |
| 4 | `crypto_error.dart` | `CryptoError` (sealed) + 12 subclasses + `mapExceptionToCryptoError()` |
| 5 | `crypto_result.dart` | `CryptoResult<T>` (sealed), `CryptoSuccess<T>`, `CryptoFailure<T>` |
| 6 | `csr_data.dart` | `CsrRequest` (com `validate()`), `CsrData` |
| 7 | `distinguished_name.dart` | `DistinguishedName` (com `validate()`, getter `entries`) |
| 8 | `key_types.dart` | `KeySpec` (sealed), `RsaKeySpec`, `EcCurve` (static), `EcKeySpec`, `MlKemParameterSet` (enum), `MlDsaParameterSet` (enum), `MlKemKeySpec`, `MlDsaKeySpec` |
| 9 | `ocsp_data.dart` | `CertificateStatus` (enum: good/revoked/unknown), `OcspResponse` |
| 10 | `signing_algorithm.dart` | `HashAlgorithm` (enum: sha256/512/3_256/3_512), `SigningKeyType` (enum: rsa/ec/ml_dsa), `SigningAlgorithm` (com `==`, `hashCode`) |
| 11 | `ts_data.dart` | `TimestampStatus` (enum 6 valores), `TimestampResponse` (10 campos), `TimestampAccuracy`, `TsHashAlgorithm` (static: OIDs + DER pre-encoded) |

### Destaques

**Asn1Node** (`asn1_data.dart:42`): `tagClass: int`, `tagNumber: int`, `isConstructed: bool`, `length: int`, `value: Uint8List`, `children: List<Asn1Node>`, `parsedValue: String?`. Metodo: `toPrettyString([int indent])`.

**X509ParsedExtensions** (`certificate_data.dart:69`): `keyUsage: List<String>?`, `basicConstraints: BasicConstraints?`, `subjectAltNames: List<String>?`, `crlDistributionPoints: List<String>?`, `ocspResponders: List<String>?`.

**CertificateRevocationStatus** (`crl_data.dart:45`): `isRevoked: bool`, `revocationDate: DateTime?`, `reasonCode: int?`. Static const: `notRevoked`.

**CryptoResult<T>** (`crypto_result.dart:6`): sealed class com `CryptoSuccess<T>(T value)` e `CryptoFailure<T>(CryptoError error)`.

**DistinguishedName** (`distinguished_name.dart:3`): `commonName` (required), `organization?`, `organizationalUnit?`, `locality?`, `state?`, `country?`. Getter `entries` retorna `List<(String, String)>` com tuplas (C, ST, L, O, OU, CN). `validate()`: CN nao-vazio, country exatamente 2 letras ASCII uppercase.

**KeySpec** (`key_types.dart:4`): sealed class com subclasses `RsaKeySpec(bits)` (valida >=1024, <=16384, %1024), `EcKeySpec(curve)` (valida em prime256v1/secp384r1/secp521r1), `MlKemKeySpec(parameterSet)`, `MlDsaKeySpec(parameterSet)`. Enums: `MlKemParameterSet { mlKem512, mlKem768, mlKem1024 }`, `MlDsaParameterSet { mlDsa44, mlDsa65, mlDsa87 }`.

**HashAlgorithm** (`signing_algorithm.dart:7`): enum com metodo `Pointer<Void> evpMd(OpenSslBindings b)` que resolve para `EVP_sha256/sha512/sha3_256/sha3_512`. `SigningAlgorithm` tem operadores `==` e `hashCode`.

**TsHashAlgorithm** (`ts_data.dart:93`): classe static com OIDs (`oidSha256 = '2.16.840.1.101.3.4.2.1'`, etc.), DER AlgorithmIdentifier pre-encoded, e metodos `derForAlgorithm(String) -> Uint8List`, `hashLength(String) -> int` (32/48/64).

**TimestampResponse** (`ts_data.dart:27`): 10 campos optional: `status`, `statusString?`, `tokenData?`, `genTime?`, `serialNumber?`, `hashAlgorithmOid?`, `messageImprint?`, `nonce?`, `policyOid?`, `accuracy?`. Getter: `bool get isGranted`.

---

## 5. crypto/flows/ -- Fluxos de Alto Nivel (8 diretorios, 24 arquivos)

**Agrupa**: 8 workflows com implementacoes concretas via OpenSSL, cada fluxo com interface abstrata + implementacao FFI.

### 5.1 asn1/ (2 arquivos)

**`asn1/asn1_parser.dart`**: `abstract interface class Asn1Parser` com `CryptoResult<Asn1Node> parse(Uint8List derData)`.

**`asn1/openssl_asn1_parser.dart`**: `OpenSslAsn1Parser implements Asn1Parser`. Parser DER puro em Dart -- **nenhuma chamada FFI**. Fluxo:
1. `_parseTag`: classe (bits 7-6), flag constructed (bit 5), numero da tag (short 0-30 ou VLQ base-128 multi-byte)
2. `_parseLength`: short form (<128) ou long form (max 4 bytes, rejeita 0x80 indefinido)
3. Se constructed: recursao `_parseNode` para filhos; se primitivo: `_parsePrimitiveValue` -> INTEGER (BigInt), OID (VLQ), strings (UTF8/Printable/IA5), UTCTime/GeneralizedTime, BOOLEAN, NULL
4. Valida `trailingOffset == derData.length`
5. Retorna `CryptoSuccess(node)` ou `CryptoFailure(Asn1Error)`

### 5.2 certificate_chain/ (4 arquivos)

| Arquivo | Classe | Funcao |
|---------|-------|--------|
| `chain_verification_request.dart` | `ChainVerificationRequest` | `leafCert`, `trustedRoot?`, `intermediates`, `verificationTime?`. `validate()` lanca `ArgumentError` |
| `chain_verifier.dart` | `ChainVerifier` (interface) + `ChainValidationResult` | `verify(request) -> CryptoResult<ChainValidationResult>` |
| `openssl_chain_verifier.dart` | `OpensslChainVerifier` | Implementacao via `X509_STORE_new`, `OPENSSL_sk_new_null/push`, `X509_STORE_CTX_init`, `X509_verify_cert`, `X509_STORE_CTX_get_error`, `X509_verify_cert_error_string` |
| `x509_store_factory.dart` | `X509StoreFactory` | `createStore({trustedCerts?})`, `addCert(store, certPem)`. Lanca `StateError` |

**Fluxo `OpensslChainVerifier.verify`**:
1. `errClearError()`, `request.validate()`
2. `X509_STORE_new()` -> se `trustedRoot`: `loadX509` + `X509_STORE_add_cert`
3. `OPENSSL_sk_new_null()` -> push cada intermediate
4. `loadX509(leafCert)` -> `X509_STORE_CTX_new` -> `X509_STORE_CTX_init(store, leaf, untrusted)`
5. Se `verificationTime`: `X509_STORE_CTX_get0_param` + `X509_VERIFY_PARAM_set_time(param, unixTime)`
6. `X509_verify_cert(vfyCtx)`: ==1 valido; senao `X509_STORE_CTX_get_error` + `X509_STORE_CTX_get_error_depth` + `X509_verify_cert_error_string`
7. Finally: `X509_STORE_CTX_free`, `X509_free(leaf)`, `OPENSSL_sk_free`, `X509_STORE_free`

### 5.3 certificate_creation/ (4 arquivos)

| Arquivo | Classe | Descricao |
|---------|-------|-----------|
| `certificate_creator.dart` | `CertificateCreator` (interface) | `create(CertificateRequest) -> CryptoResult<CertificateData>` |
| `certificate_request.dart` | `CertificateRequest` | `subject`, `issuer`, `subjectPublicKey`, `issuerPrivateKey`, `notBefore`, `notAfter`, `extensions`, `signingAlgorithm`. Getter `isSelfSigned`. Valida datas. |
| `certificate_builder.dart` | `CertificateBuilder` | Builder fluente com 24 funcoes C. `build() -> CryptoResult<Uint8List>`, `buildPem() -> CryptoResult<String>` |
| `self_signed_cert_creator.dart` | `SelfSignedCertCreator` | `create(request)` + `createNew(commonName, validity, signingAlgorithm)`. Usa `CertificateBuilder` + `KeyCreatorFactory`. |

**Fluxo `CertificateBuilder._buildDer()`**:
1. `X509_new()` -> `X509_set_version(x, 2)` (v3)
2. `_loadPublicKey(pem)` -> `X509_set_pubkey(x, pkey)`
3. `X509NameBuilder.build(subject/issuer)` -> `X509_set_subject_name/issuer_name`
4. `ASN1_TIME_set(nullptr, epoch)` -> `X509_set1_notBefore/notAfter`
5. Para cada extensao: `X509V3_set_ctx`, `OBJ_txt2nid`, `X509V3_EXT_conf_nid`, `X509_add_ext`
6. `X509_sign(x, pkey, md)` (md=nullptr para ML-DSA)
7. `BIO_new(BIO_s_mem())` -> `i2d_X509_bio(derBio, x)` -> `bioToBytes` -> DER

### 5.4 csr/ (2 arquivos)

| Arquivo | Classe |
|---------|-------|
| `csr_generator.dart` | `CsrGenerator` (interface) |
| `openssl_csr_generator.dart` | `OpenSslCsrGenerator` (26 funcoes C) |

**Fluxo**: `request.validate()` -> `PEM_read_bio_PrivateKey` -> `X509_REQ_new` -> `X509_REQ_set_version(0)` -> `X509NameBuilder.build(subject)` -> `X509_REQ_set_subject_name/set_pubkey` -> se dnsNames: `X509V3_set_ctx` + `X509V3_EXT_conf_nid` + `OPENSSL_sk_new_null/push` + `X509_REQ_add_extensions` -> `EVP_sha256()` -> `X509_REQ_sign` -> `i2d_X509_REQ_bio` (DER) + `PEM_write_bio_X509_REQ` (PEM) + `X509_REQ_get_subject_name` + `X509_NAME_oneline` (subject DN).

### 5.5 file_signing/ (3 arquivos)

| Arquivo | Classe |
|---------|-------|
| `file_signer.dart` | `FileSigner` (interface) |
| `file_signing_request.dart` | `FileSigningRequest` |
| `streaming_file_signer.dart` | `StreamingFileSigner` (11 funcoes C) |

**Fluxo `StreamingFileSigner.sign`**:
1. `request.validateFileExists()` -> `BIO_new_file(path, "rb")`
2. `PEM_read_bio_PrivateKey` -> `EVP_PKEY*`
3. `EVP_MD_CTX_new` -> `EVP_DigestSignInit` (fallback md=nullptr para ML-DSA)
4. LOOP: `BIO_read(fileBio, chunk, chunkSize)` -> `EVP_DigestSignUpdate(ctx, chunk, n)` ate EOF
5. `EVP_DigestSign` (2-pass: probe tamanho + assinatura final)
6. Finally: `EVP_MD_CTX_free`, `EVP_PKEY_free`, `BIO_free(fileBio)`

### 5.6 key_creation/ (6 arquivos)

| Arquivo | Classe | Funcoes C |
|---------|-------|-----------|
| `key_creator.dart` | `KeyCreator` (abstract) | -- |
| `key_creator_factory.dart` | `KeyCreatorFactory` | -- |
| `rsa_key_creator.dart` | `RsaKeyCreator` | `EVP_PKEY_CTX_new_id(6)`, `keygen_init`, `set_rsa_keygen_bits`, `keygen`, `CTX_free` |
| `ec_key_creator.dart` | `EcKeyCreator` | `OBJ_sn2nid`, `EVP_PKEY_CTX_new_id(408)`, `keygen_init`, `set_ec_paramgen_curve_nid`, `keygen` |
| `ml_dsa_key_creator.dart` | `MlDsaKeyCreator` | `EVP_PKEY_CTX_new_id(nidMlDsa44/65/87)`, `keygen_init`, `keygen` |
| `ml_kem_key_creator.dart` | `MlKemKeyCreator` | `EVP_PKEY_CTX_new_id(nidMlKem512/768/1024)`, `keygen_init`, `keygen` |

**Factory** (`KeyCreatorFactory`): registra `RsaKeySpec->RsaKeyCreator`, `EcKeySpec->EcKeyCreator`, `MlKemKeySpec->MlKemKeyCreator`, `MlDsaKeySpec->MlDsaKeyCreator`.

### 5.7 revocation/ (3 arquivos)

| Arquivo | Classe | Funcoes C |
|---------|-------|-----------|
| `revocation_verifier.dart` | `CrlVerifier`, `OcspVerifier` (interfaces) | -- |
| `crl_verifier.dart` | `OpenSslCrlVerifier` | 19 funcoes: `X509_CRL_*`, `OPENSSL_sk_*`, `X509_REVOKED_*`, `ASN1_STRING_*` |
| `ocsp_verifier.dart` | `OpenSslOcspVerifier` | 26 funcoes: `OCSP_*`, `X509_STORE_*`, `EVP_sha256`, `d2i_OCSP_RESPONSE` |

**Fluxo `OpenSslCrlVerifier.parseCrl`**: `loadCrl` (PEM->DER fallback) -> `X509_CRL_get0_lastUpdate/nextUpdate` -> `parseAsn1Time` -> `X509_CRL_get_REVOKED` -> itera stack: `OPENSSL_sk_num/value` -> cada entry: `X509_REVOKED_get0_serialNumber` + `_asn1StringToHex` (via `ASN1_STRING_get0_data/length`) + `X509_REVOKED_get0_revocationDate`.

**Fluxo `OpenSslOcspVerifier.buildOcspRequest`**: `_parseCert(leaf+issuer)` -> `X509_get_subject_name` + `X509_get0_pubkey_bitstr` + `X509_get_serialNumber` -> `EVP_sha256()` -> `OCSP_cert_id_new` -> `OCSP_REQUEST_new` -> `OCSP_request_add0_id` -> `i2d_OCSP_REQUEST` -> DER.

**Fluxo `OpenSslOcspVerifier.verifyOcspResponse`**: `d2i_OCSP_RESPONSE` -> `OCSP_response_status` (!=0 erro) -> `OCSP_response_get1_basic` -> `X509_STORE_new` + `add_cert(issuer)` -> `OCSP_basic_verify` -> `OCSP_resp_count` + `OCSP_resp_get0(bs,0)` -> `OCSP_single_get0_status` -> `_mapStatus` -> `OCSP_resp_get0_produced_at` -> `parseAsn1Time(thisupd/nextupd)` -> `OCSP_check_validity` -> `OcspResponse`.

### 5.8 timestamp/ (2 arquivos)

| Arquivo | Classe |
|---------|-------|
| `timestamp_client.dart` | `TimestampClient` (interface) |
| `openssl_timestamp_client.dart` | `OpenSslTimestampClient` |

**Funcoes C**: `EVP_Digest*` (via `CryptoContext.operations`), `CMS_verify` (via `CmsOperations`).

**Fluxo `createRequest`**: `_hashData(data, algo)` -> `TsHashAlgorithm.derForAlgorithm(algo)` -> DER encoding manual: `_encodeSequence([INTEGER(1), _encodeSequence([algId, _encodeOctetString(hash)]), _encodeIntegerFromBytes(nonce?)])`.

**Fluxo `verify`**: `CmsOperations.cmsVerify(tokenData)` -> `_extractTstInfo(tokenData)` (scan DER por UTCTime/GeneralizedTime + INTEGER serial + OCTET STRING imprint) -> `_hashData(data, 'sha256')` -> `_bytesEqual(hash, imprint)`.

---

## 6. metrics/ -- Coleta de Metricas (12 arquivos)

**Reune**: coleta, analise e exportacao de metricas de desempenho criptografico e seguranca.

Nenhum arquivo deste diretorio faz chamadas FFI diretamente. Toda interacao com OpenSSL ocorre via `PluginCryptoAPI`.

### 6.1 `metrics/concurrency.dart`

```dart
static Future<Map<String, dynamic>> IsolateBenchmark.measureIsolateScaling({
  required int isolateCount, required int dataSizeBytes,
  required String opType,  // 'sha256' | 'aes128CbcEncrypt' | 'aes256GcmEncrypt'
})
```

**Fluxo**: benchmark single-thread -> spawn N `Isolate` workers -> coleta `throughputMbps` via `SendPort` -> `scalingEfficiency = totalThroughput / (singleThroughput * count)`. Modelo: `IsolateScalingPoint`. Erro: catch-all retorna resultado sintetico.

### 6.2 `metrics/constant_time.dart`

```dart
static ConstantTimeResult ConstantTimeAnalyzer.analyze(List<double> perIterationTimes, String operation)
```

**Fluxo**: ordena tempos -> trim 1% -> media, variancia, stddev, cvPercent -> percentis p1/p95/p99 -> `likelyConstantTime = cvPercent < 15.0 && p99P1Ratio < 8.0`. Modelo: `ConstantTimeResult`.

### 6.3 `metrics/coverage_parser.dart`

```dart
CoverageMetrics LcovParser.parse(String lcovPath)
```

**Fluxo**: le arquivo LCOV -> parse tokens (TN, SF, DA, LF, LH) -> cobertura por arquivo e global. Arquivo nao encontrado -> metricas zeradas com `coverageAvailable: false`. Modelos: `CoverageMetrics`, `FileCoverage`.

### 6.4 `metrics/memory_tracker.dart`

```dart
bool MemoryTracker.rssAvailable              // Platform.isLinux
int MemoryTracker.sampleBytes(String label)  // ProcessInfo.currentRss
int MemoryTracker.delta(String label1, String label2)
```

Non-Linux: `rssAvailable = false`, retorna -1.

### 6.5 `metrics/metrics_collector.dart`

Singleton que agrega todos os dados de metrica. Principais metodos:

```dart
static MetricsCollector create()
void recordOperationTiming(OperationTiming timing)
void recordCipherPerformance(CipherPerformanceMetrics metrics)
void recordConstantTimeResult(ConstantTimeResult r)
void setZeroizationMetrics(ZeroizationMetrics z)
MetricsReport buildReport(TimingMetrics, MemoryMetrics, ThroughputMetrics, SecurityMetrics, ResourceMetrics, CoverageMetrics)
Future<void> writeJson(String path, {...})
List<CategorySummary> computeCategorySummaries()
```

`computeCategorySummaries()`: agrupa timings por categoria, computa `totalWarmMs`, `totalColdMs`, `meanWarmThroughputMbps`, `maxWarmThroughputMbps`, etc.

### 6.6 `metrics/metrics_models.dart`

22 classes de modelo, todas com `toJson()` e `factory fromJson()`. Destaques:

| Classe | Campos Chave |
|--------|-------------|
| `MetricsReport` | schemaVersion, timestamp, timing, memory, throughput, security, resource, coverage, constantTime?, concurrency?, zeroization?, fuzzing? |
| `TimingMetrics` | totalSuiteMs, totalTests, passed, failed, skipped, testResults, zoneDurations |
| `ThroughputMetrics` | 22 campos: sha256/512/3-256 Mbps, aes-128/256 CBC/GCM Mbps, rsaSign/Verify ops/s, ecSign/Verify, keygen ops/min |
| `SecurityMetrics` | 16 campos: entropyBits, chiSquaredPValue, uniquenessRatio, safeCurves, katSummaries |
| `ConstantTimeResult` | cvPercent, p99P1Ratio, p95MinRatio, likelyConstantTime, evidence |
| `HistogramSnapshot` | min, max, mean, median, p5, p25, p75, p95, p99, stddevPop, bucketCounts |
| `CipherPerformanceMetrics` | cipherName, encryptMBps, decryptMBps, hwAccelerated, keySizeBits |
| `ZeroizationMetrics` | opensslCleanseBound, cryptoFreeBound, keyMaterialWiped, buffersCleared |
| `FuzzingMetrics` | iterationsRun, crashesDetected, uniqueCrashes, inputsGenerated, coveragePercent |

### 6.7 `metrics/safe_curves.dart`

```dart
SafeCurveChecklist buildSafeCurveChecklist(String curveName)
int verifyEmbeddingDegree(BigInt prime, BigInt order, {String? curveName})
```

**Fluxo**: lookup de constantes hex para prime256v1/secp384r1/secp521r1. `verifyEmbeddingDegree`: itera k=1..500, `prime^k ≡ 1 (mod order)` via `BigInt.modPow`. `embeddingDegreeSafe = k >= 100 || k == 0`.

### 6.8 `metrics/security_benchmark.dart`

```dart
// SecurityBenchmark (static)
static BatchResult batchHash(PluginCryptoAPI api, int iterations, int dataSizeBytes)
static BatchResult batchEncrypt/Decrypt(api, iterations, dataSizeBytes, String cipher)
static BatchResult batchSign/Verify(api, iterations)
static BatchResult batchKeyGen(api, iterations, String type)

// CipherSuiteComparison (static)
static List<CipherResult> compareCiphers(api, {dataSizeBytes=1MB, iterations=100})

// TlsHandshakeSimulator (static)
static TlsSimulationResult simulateHandshake(api, String cipherSuite)
static TlsSimulationResult simulateBulkTransfer(api, cipherSuite, dataSizeBytes)
```

**Fluxo `simulateHandshake`**: gera EC keypairs -> combina pubkeys -> SHA-256 (key exchange). Assina desafio -> verifica assinatura (certificado). 4x SHA-256 (HMAC). Modelos: `CipherPerformanceMetrics`, `CipherSuiteComparisonMetrics`, `TlsSimulationMetrics`.

### 6.9 `metrics/security_metrics.dart`

```dart
double computeShannonEntropy(Uint8List data)        // -sum(p * log2(p))
ChiSquaredResult computeChiSquared(Uint8List data)  // p-valor via normal approx
double checkUniqueness(List<Uint8List> samples)      // seen.length / samples.length
bool checkSignatureNonDeterminism(Uint8List Function() signFn)
```

`ChiSquaredResult.passed`: getter `pValue > 0.01`.

### 6.10 `metrics/throughput.dart`

```dart
double computeMbps(int bytes, double ms)
double computeOpsPerSec(double ms)
ThroughputMetrics buildThroughputMetrics(List<OperationTiming> timings, int totalBytesProcessed)
```

### 6.11 `metrics/timing.dart`

```dart
class CryptoMicroBenchmark {
  ColdTimingResult measureCold(String label, void Function() op, {int preWarmupCalls, String category, int inputSizeBytes})
  WarmTimingResult measureWarm(String label, void Function() op, {required int dataSizeBytes, int iterations, String category})
  HistogramSnapshot computeHistogram({required String operation, required String category, required WarmTimingResult warm, List<double>? perIterationTimes})
}
```

**Fluxo `measureWarm`**: `_stabilizeHeap()` -> warmup (75 iteracoes) -> batch-measure ou per-iteration (se `_collectPerIterationStats`) -> mean, min, max -> `_computeThroughput()` via `computeMbps`.

**`computeHistogram`**: ordena tempos -> percentis p5/p25/p50/p75/p95/p99 via interpolacao linear -> stddev populacional.

### 6.12 `metrics/zeroization.dart`

```dart
static bool ZeroizationVerifier.isOpensslCleanseBound(OpenSslBindings bindings)
static bool ZeroizationVerifier.isCryptoFreeBound(OpenSslBindings bindings)
```

As métricas de zeroização observam buffers temporários nativos imediatamente
após `OPENSSL_cleanse` e antes de `calloc.free`, usando um callback de teste e
um shim nativo. Memória pertencente ao chamador Dart e alocações internas do
OpenSSL não fazem parte dessa garantia.

---

## 7. crypto/utils/ -- Utilitarios (9 arquivos)

**Inclui**: utilitarios para BIO, ASN1 TIME, X509 parsing, serializacao de chaves e hex encoding.

### 7.1 `utils/asn1_time.dart`

```dart
DateTime? parseAsn1Time(OpenSslBindings b, Pointer<Void> asn1Time)
```

**Funcoes C**: `BIO_new(BIO_s_mem())` -> `ASN1_TIME_print(bio, asn1Time)` -> `BIO_free`. Usa `bioToString()` de `bio_utils.dart`.

**Fluxo**: nullptr guard -> cria memory BIO -> `ASN1_TIME_print` -> `bioToString` -> parse string formato `Mon dd hh:mm:ss yyyy` -> `DateTime.utc`. Retorna `null` em qualquer falha.

### 7.2 `utils/bio_utils.dart`

```dart
BIO bioFromData(OpenSslBindings b, Uint8List data)
BIO bioFromString(OpenSslBindings b, String s)
Uint8List bioToBytes(OpenSslBindings b, BIO bio)
String bioToString(OpenSslBindings b, BIO bio)
```

**Funcoes C**: `BIO_new(BIO_s_mem())`, `BIO_write(bio, dp, len)`, `BIO_read(bio, chunk, 4096)`.

**Fluxo `bioFromData`**: `BIO_new(BIO_s_mem())` -> `calloc` data -> `BIO_write` -> `calloc.free`. `bioToBytes`: loop `BIO_read` em chunks de 4096 ate `n <= 0`.

### 7.3 `utils/certificate_serializer.dart`

```dart
CryptoResult<String> derToPem(OpenSslBindings b, Uint8List der)
```

**Funcoes C**: `BIO_new(BIO_s_mem())`, `d2i_X509_bio(derBio, nullptr)`, `PEM_write_bio_X509(pemBio, x509)`, `X509_free`, `BIO_free`.

**Fluxo**: cria DER BIO -> `d2i_X509_bio` -> `PEM_write_bio_X509` -> `bioToBytes` -> PEM string. 3 try/finally aninhados.

### 7.4 `utils/hex_utils.dart`

```dart
String bytesToHex(Uint8List bytes, {bool truncate = false, int maxLen = 16, bool skipLeadingZero = false})
```

Puro Dart, sem FFI. Converte bytes para hex string, opcionalmente truncando e removendo zero leading.

### 7.5 `utils/key_pair_serializer.dart`

```dart
const KeyPairSerializer(OpenSslBindings _b)
CryptoResult<KeyPair> KeyPairSerializer.extract(EVP_PKEY pkey, String keyType)
```

**Funcoes C**: `BIO_new(BIO_s_mem())`, `PEM_write_bio_PUBKEY`, `PEM_write_bio_PrivateKey(pkey, null, null, 0, null, null)` (sem criptografia), `EVP_PKEY_free`, `BIO_free`.

**Fluxo**: cria pub BIO -> `PEM_write_bio_PUBKEY` -> `bioToString` -> cria priv BIO -> `PEM_write_bio_PrivateKey` -> `bioToString` -> `EVP_PKEY_free` -> `CryptoSuccess(KeyPair(pub, priv))`.

### 7.6 `utils/openssl_error.dart`

```dart
String? getOpenSslError(OpenSslBindings b)
```

**Funcoes C**: `ERR_get_error(void) -> unsigned long`, `ERR_error_string_n(e, buf, 256)`.

**Fluxo**: `ERR_get_error()` -> se 0, retorna `null` -> `calloc<Uint8>(256)` -> `ERR_error_string_n` -> `buf.cast<Utf8>().toDartString()` -> `calloc.free(buf)`.

### 7.7 `utils/x509_ext_parser.dart`

```dart
X509ExtensionParser(OpenSslBindings _b)
X509ParsedExtensions parseExtensions(Pointer<Void> x509)
```

**Funcoes C**: `X509_get_ext_count`, `X509_get_ext`, `X509_EXTENSION_get_object`, `OBJ_obj2txt`, `X509_get_key_usage`, `X509V3_EXT_print`, `BIO_new/free`, `BIO_s_mem`, `BIO_read`.

**Fluxo**: itera extensoes por OID:
- `2.5.29.15` (Key Usage): `X509_get_key_usage()` -> decode bitmask
- `2.5.29.19` (Basic Constraints): `X509V3_EXT_print` -> regex `CA:TRUE`/`pathlen:N`
- `2.5.29.17` (SAN): split by comma
- `2.5.29.31` (CRL DP): regex `URI\s*:\s*(\S+)`
- `1.3.6.1.5.5.7.1.1` (AIA/OCSP): parse lines with `OCSP` + `URI:`

### 7.8 `utils/x509_loader.dart`

```dart
X509 loadX509(OpenSslBindings b, Uint8List data)
X509_CRL loadCrl(OpenSslBindings b, Uint8List data)
```

**Funcoes C**: `PEM_read_bio_X509`, `d2i_X509_bio`, `PEM_read_bio_X509_CRL`, `d2i_X509_CRL_bio`, `ERR_clear_error`, `BIO_free`.

**Fluxo**: tenta PEM primeiro -> se falhar, `ERR_clear_error()` + DER fallback. BIO sempre liberado.

### 7.9 `utils/x509_name_builder.dart`

```dart
const X509NameBuilder(OpenSslBindings _b)
X509_NAME X509NameBuilder.build(DistinguishedName dn)
```

**Funcoes C**: `X509_NAME_new()`, `X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, bytes, len, -1, 0)`, `X509_NAME_free`.

**Fluxo**: `dn.validate()` -> `X509_NAME_new()` -> para cada entry (C, ST, L, O, OU, CN): `X509_NAME_add_entry_by_txt`. Lanca `StateError` em falhas.

---

## 8. Tabela Cruzada OpenSSL

### Funcoes C por Frequencia de Uso nos Fluxos

| Frequencia | Funcoes C |
|------------|-----------|
| **Extremamente Alta** (>=15 arquivos) | `ERR_clear_error`, `BIO_new`, `BIO_free`, `BIO_s_mem`, `X509_free`, `EVP_PKEY_free` |
| **Alta** (8-14 arquivos) | `X509_STORE_new/free`, `X509_STORE_add_cert`, `PEM_read_bio_PrivateKey`, `PEM_read_bio_X509`, `X509_new`, `EVP_sha256`, `X509_get_serialNumber`, `X509_get_subject_name` |
| **Media** (4-7 arquivos) | `X509_verify_cert`, `X509_STORE_CTX_init`, `X509_sign`, `X509_set_pubkey`, `EVP_PKEY_keygen`, `EVP_MD_CTX_new/free`, `EVP_DigestSignInit`, `EVP_DigestSign`, `d2i_X509_bio`, `i2d_X509_bio`, `OPENSSL_sk_new_null/push/free`, `X509_NAME_oneline`, `CRYPTO_free` |

### Funcoes C Exclusivas por Dominio

| Dominio | Funcoes |
|---------|---------|
| **AES** | `EVP_CIPHER_CTX_new/free`, `EVP_EncryptInit_ex/Update/Final_ex`, `EVP_DecryptInit_ex/Update/Final_ex`, `EVP_CIPHER_CTX_ctrl` |
| **Digest** | `EVP_MD_CTX_new/free`, `EVP_DigestInit_ex/Update/Final_ex`, `EVP_sha256/sha512/sha384/sha3_256/sha3_512` |
| **PKEY** | `EVP_PKEY_new/free/get_size`, `EVP_PKEY_CTX_new/new_id/free`, `EVP_PKEY_keygen_init/keygen`, `EVP_PKEY_encrypt/decrypt_init`, `EVP_PKEY_encrypt/decrypt`, `EVP_PKEY_encapsulate/decapsulate_init`, `EVP_PKEY_encapsulate/decapsulate` |
| **Sign/Verify** | `EVP_DigestSignInit/Update`, `EVP_DigestSign`, `EVP_DigestVerifyInit`, `EVP_DigestVerify` |
| **X509** | `X509_new/free`, `X509_get/set_*`, `i2d_X509_bio`, `d2i_X509_bio`, `X509_sign`, `X509_verify_cert` |
| **X509_STORE** | `X509_STORE_new/free/add_cert`, `X509_STORE_CTX_new/free/init`, `X509_STORE_CTX_get_error/get_error_depth`, `X509_VERIFY_PARAM_set_time` |
| **X509_CRL** | `X509_CRL_new/free`, `d2i_X509_CRL_bio`, `X509_CRL_verify`, `X509_CRL_get0_*`, `X509_CRL_get_REVOKED` |
| **X509_REQ** | `X509_REQ_new/free`, `X509_REQ_set/get_*`, `X509_REQ_sign`, `X509_REQ_add_extensions`, `i2d_X509_REQ_bio` |
| **CMS** | `CMS_sign/verify/encrypt/decrypt`, `CMS_ContentInfo_free`, `CMS_get0_signers`, `CMS_signed_add1_attr_by_txt` |
| **OCSP** | `OCSP_REQUEST_new/free`, `OCSP_request_add0_id`, `OCSP_cert_id_new/free`, `OCSP_RESPONSE_free`, `OCSP_response_status/get1_basic`, `OCSP_basic_verify`, `OCSP_resp_count/get0`, `OCSP_single_get0_status`, `OCSP_check_validity` |
| **Stack** | `OPENSSL_sk_new_null/push/free/num/value` |
| **OBJ** | `OBJ_sn2nid/nid2sn`, `OBJ_txt2nid/obj2txt` |
| **ASN1** | `ASN1_TIME_print/set`, `ASN1_STRING_get0_data/length`, `ASN1_TYPE_free/get`, `ASN1_tag2str`, `d2i_ASN1_TYPE_bio` |
| **BN** | `BN_new/free`, `BN_bn2bin/bin2bn` |
| **ERR** | `ERR_get_error/clear_error`, `ERR_error_string_n` |

### Padrao de Tratamento de Erro por Camada

| Camada | Padrao |
|--------|--------|
| **ffi/** | Nenhum (bindings puros) |
| **crypto/ (operacoes diretas)** | `_check1`/`_fail`: `StateError` com `getOpenSslError()` + `errClearError()`. `try/finally` para liberacao de memoria nativa. `AesGcmAuthFailure` para falha de autenticacao GCM |
| **crypto/ (fluxos)** | `CryptoResult<T>` / `CryptoFailure(CryptoError)`. `_fail<T>()` helpers que limpam fila de erro. `try/finally` aninhados. Fallback ML-DSA em `sign`/`verify` |
| **models/** | `ArgumentError` em validators. `CryptoError` sealed hierarchy com `message` getter |
| **metrics/** | `catch(_)` retorna defaults/zeros. `synthetic: true` flag em resultados fallback |
| **utils/** | Retorna `null` em falhas de parsing. `StateError` em builders. `CryptoResult` em serializers |

---

> **Total**: 74 arquivos documentados. ~120 funcoes C OpenSSL mapeadas. 22 classes de modelo de metrica. 12 subclasses de erro tipadas. 6 criadores de chave (RSA, EC, ML-KEM, ML-DSA via factory). 8 fluxos de alto nivel (ASN1, Certificate Chain, Certificate Creation, CSR, File Signing, Key Creation, Revocation, Timestamp).

---

## 9. Tabela-Resumo: Contagem de Linhas por Arquivo

| # | Arquivo | Linhas |
|---|---------|--------|
| | **ffi/** | |
| 1 | `ffi/openssl_bindings.dart` | 1895 |
| 2 | `ffi/native_loader.dart` | 76 |
| | **crypto/** | |
| 3 | `crypto/crypto_operations.dart` | 78 |
| 4 | `crypto/aes_operations.dart` | 394 |
| 5 | `crypto/asymmetric_operations.dart` | 444 |
| 6 | `crypto/cms_operations.dart` | 346 |
| 7 | `crypto/crypto_api.dart` | 303 |
| 8 | `crypto/crypto_context.dart` | 62 |
| 9 | `crypto/plugin_crypto_context.dart` | 20 |
| 10 | `crypto/plugin_crypto_operations.dart` | 255 |
| 11 | `crypto/x509_operations.dart` | 171 |
| 12 | `crypto/crl_operations.dart` | 27 |
| 13 | `crypto/csr_operations.dart` | 18 |
| 14 | `crypto/ocsp_operations.dart` | 26 |
| 15 | `crypto/timestamp_operations.dart` | 35 |
| 16 | `crypto/crypto_data.dart` | 42 |
| 17 | `crypto/constants.dart` | 20 |
| 18 | `crypto/extensions/key_pair_extensions.dart` | 25 |
| | **crypto/models/** | |
| 19 | `crypto/models/asn1_data.dart` | 142 |
| 20 | `crypto/models/certificate_data.dart` | 94 |
| 21 | `crypto/models/crl_data.dart` | 63 |
| 22 | `crypto/models/crypto_error.dart` | 190 |
| 23 | `crypto/models/crypto_result.dart` | 22 |
| 24 | `crypto/models/csr_data.dart` | 66 |
| 25 | `crypto/models/distinguished_name.dart` | 54 |
| 26 | `crypto/models/key_types.dart` | 91 |
| 27 | `crypto/models/ocsp_data.dart` | 36 |
| 28 | `crypto/models/signing_algorithm.dart` | 69 |
| 29 | `crypto/models/ts_data.dart` | 148 |
| | **crypto/flows/** | |
| 30 | `crypto/flows/asn1/asn1_parser.dart` | 10 |
| 31 | `crypto/flows/asn1/openssl_asn1_parser.dart` | 216 |
| 32 | `crypto/flows/certificate_chain/chain_verification_request.dart` | 41 |
| 33 | `crypto/flows/certificate_chain/chain_verifier.dart` | 30 |
| 34 | `crypto/flows/certificate_chain/openssl_chain_verifier.dart` | 190 |
| 35 | `crypto/flows/certificate_chain/x509_store_factory.dart` | 60 |
| 36 | `crypto/flows/certificate_creation/certificate_creator.dart` | 9 |
| 37 | `crypto/flows/certificate_creation/certificate_request.dart` | 73 |
| 38 | `crypto/flows/certificate_creation/certificate_builder.dart` | 543 |
| 39 | `crypto/flows/certificate_creation/self_signed_cert_creator.dart` | 244 |
| 40 | `crypto/flows/csr/csr_generator.dart` | 8 |
| 41 | `crypto/flows/csr/openssl_csr_generator.dart` | 274 |
| 42 | `crypto/flows/file_signing/file_signer.dart` | 13 |
| 43 | `crypto/flows/file_signing/file_signing_request.dart` | 63 |
| 44 | `crypto/flows/file_signing/streaming_file_signer.dart` | 232 |
| 45 | `crypto/flows/key_creation/key_creator.dart` | 11 |
| 46 | `crypto/flows/key_creation/key_creator_factory.dart` | 54 |
| 47 | `crypto/flows/key_creation/rsa_key_creator.dart` | 114 |
| 48 | `crypto/flows/key_creation/ec_key_creator.dart` | 124 |
| 49 | `crypto/flows/key_creation/ml_dsa_key_creator.dart` | 96 |
| 50 | `crypto/flows/key_creation/ml_kem_key_creator.dart` | 96 |
| 51 | `crypto/flows/revocation/revocation_verifier.dart` | 36 |
| 52 | `crypto/flows/revocation/crl_verifier.dart` | 262 |
| 53 | `crypto/flows/revocation/ocsp_verifier.dart` | 366 |
| 54 | `crypto/flows/timestamp/timestamp_client.dart` | 21 |
| 55 | `crypto/flows/timestamp/openssl_timestamp_client.dart` | 424 |
| | **metrics/** | |
| 56 | `metrics/concurrency.dart` | 215 |
| 57 | `metrics/constant_time.dart` | 82 |
| 58 | `metrics/coverage_parser.dart` | 141 |
| 59 | `metrics/memory_tracker.dart` | 82 |
| 60 | `metrics/metrics_collector.dart` | 476 |
| 61 | `metrics/metrics_models.dart` | 1488 |
| 62 | `metrics/safe_curves.dart` | 153 |
| 63 | `metrics/security_benchmark.dart` | 841 |
| 64 | `metrics/security_metrics.dart` | 86 |
| 65 | `metrics/throughput.dart` | 82 |
| 66 | `metrics/timing.dart` | 387 |
| 67 | `metrics/zeroization.dart` | 65 |
| | **crypto/utils/** | |
| 68 | `crypto/utils/asn1_time.dart` | 66 |
| 69 | `crypto/utils/bio_utils.dart` | 64 |
| 70 | `crypto/utils/certificate_serializer.dart` | 64 |
| 71 | `crypto/utils/hex_utils.dart` | 27 |
| 72 | `crypto/utils/key_pair_serializer.dart` | 75 |
| 73 | `crypto/utils/openssl_error.dart` | 29 |
| 74 | `crypto/utils/x509_ext_parser.dart` | 185 |
| 75 | `crypto/utils/x509_loader.dart` | 39 |
| 76 | `crypto/utils/x509_name_builder.dart` | 53 |

> **Total de linhas de codigo**: 11.212 (74 arquivos, media de ~152 linhas/arquivo)
