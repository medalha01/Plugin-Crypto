# Arquitetura do PluginCrypto

> Documentação técnica de arquitetura interna do PluginCrypto. Cobre as 3 camadas
> com todas as subcamadas e direção de fluxo de dados, inicialização FFI (late-final
> lazy), dispatch de plataforma no native loader, providers OpenSSL com algoritmos
> registrados por cada um, segurança de thread (síncrono, estruturas não
> compartilhadas), modelo de memória (calloc vs GC Dart com try/finally aninhado),
> rastreamento completo fim-a-fim de `aes128GcmEncrypt`, comparação Android JNI vs
> Linux dlopen, e build de ambas as plataformas.

---

## 1. Visão Geral em 3 Camadas (Diagrama Expandido)

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                     PUBLIC API  (Dart  package:tcc_plugin_crypto)           │
 │                                                                              │
 │  plugin_crypto.dart                                                          │
 │  └─ PluginCryptoAPI.instance  ──  singleton lazy, inicializa FFI            │
 │                                                                              │
 │  ┌──────────────┬──────────────┬──────────────┬──────────────┬─────────────┐ │
 │  │   Hash       │    AES       │   RSA / EC   │  ML-KEM/DSA  │  X.509      │ │
 │  │ sha256       │ aes128Cbc    │ sign/verify  │ encapsulate  │ parse       │ │
 │  │ sha512       │ aes256Cbc    │ encrypt/dec  │ decapsulate  │ verify      │ │
 │  │ sha3_256     │ aes128Gcm    │ keygen       │ mlKemEncap   │ chain       │ │
 │  │ sha3_512     │ aes256Gcm    │              │ mlKemDecap   │ extensions  │ │
 │  └──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘ │
 │  ┌──────────────┬──────────────┬──────────────┬──────────────┬─────────────┐ │
 │  │  CMS/PKCS#7  │  CRL         │    OCSP      │    CSR       │ Timestamp   │ │
 │  │ cmsSign      │ parseCrl     │ buildReq     │ generateCsr  │ createReq   │ │
 │  │ cmsVerify    │ verifySig    │ verifyResp   │              │ verifyResp  │ │
 │  │ cmsEncrypt   │ checkRevoked │              │              │ verify      │ │
 │  │ cmsDecrypt   │              │              │              │             │ │
 │  │ cmsSignCades │              │              │              │             │ │
 │  └──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘ │
 │                                                                              │
 │  43 métodos públicos síncronos  todos delegam para a Core Layer            │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │                     CORE LAYER  (Dart  lib/src/crypto/)                     │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ crypto/  ── Operações Atômicas via FFI  (8 arquivos)                 │   │
 │  │                                                                       │   │
 │  │  crypto_operations.dart   (78 linhas)                                 │   │
 │  │    randomBytes / sha256 / sha512 / sha3_256 / sha3_512               │   │
 │  │                                                                       │   │
 │  │  aes_operations.dart      (394 linhas)                                │   │
 │  │    aes128CbcEncrypt  / aes128CbcDecrypt                               │   │
 │  │    aes256CbcEncrypt  / aes256CbcDecrypt                               │   │
 │  │    aes128GcmEncrypt  / aes128GcmDecrypt                               │   │
 │  │    aes256GcmEncrypt  / aes256GcmDecrypt                               │   │
 │  │                                                                       │   │
 │  │  asymmetric_operations.dart   (444 linhas)                            │   │
 │  │    generateRsaKeyPair  /  generateEcKeyPair                           │   │
 │  │    sign  /  verify  /  rsaEncrypt  /  rsaDecrypt                      │   │
 │  │    mlKemEncapsulate  /  mlKemDecapsulate                              │   │
 │  │                                                                       │   │
 │  │  x509_operations.dart       (171 linhas)                              │   │
 │  │    parseX509Certificate  /  verifyX509Certificate                     │   │
 │  │                                                                       │   │
 │  │  cms_operations.dart        (346 linhas)                              │   │
 │  │    cmsSign / cmsVerify / cmsEncrypt / cmsDecrypt / cmsSignCades       │   │
 │  │                                                                       │   │
 │  │  crl_operations.dart        (27 linhas)                               │   │
 │  │    parseCrl / verifyCrlSignature / checkRevocation                    │   │
 │  │                                                                       │   │
 │  │  ocsp_operations.dart       (26 linhas)                               │   │
 │  │    buildOcspRequest / verifyOcspResponse                              │   │
 │  │                                                                       │   │
 │  │  csr_operations.dart        (18 linhas)                               │   │
 │  │    generateCsr                                                        │   │
 │  │                                                                       │   │
 │  │  timestamp_operations.dart  (35 linhas)                               │   │
 │  │    createRequest / verifyResponse / verify                            │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ flows/  ── Workflows Completos  (8 diretórios, 24 arquivos)          │   │
 │  │                                                                       │   │
 │  │  key_creation/       KeyCreator interface + 4 implementações          │   │
 │  │    RsaKeyCreator  / EcKeyCreator / MlKemKeyCreator / MlDsaKeyCreator  │   │
 │  │                                                                       │   │
 │  │  certificate_creation/  SelfSignedCertCreator + CertificateBuilder    │   │
 │  │    (CertificateBuilder: fluent API com 543 linhas)                    │   │
 │  │                                                                       │   │
 │  │  certificate_chain/   OpensslChainVerifier                            │   │
 │  │    X509_STORE_CTX_init → X509_verify_cert                            │   │
 │  │                                                                       │   │
 │  │  file_signing/        StreamingFileSigner                             │   │
 │  │    BIO_new_file → streaming EVP_DigestSign                            │   │
 │  │                                                                       │   │
 │  │  csr/                 OpensslCsrGenerator                             │   │
 │  │    X509_REQ_new → X509_REQ_sign                                      │   │
 │  │                                                                       │   │
 │  │  revocation/          OpenSslCrlVerifier + OpenSslOcspVerifier        │   │
 │  │    X509_CRL_verify / OCSP_basic_verify                                │   │
 │  │                                                                       │   │
 │  │  timestamp/           OpenSslTimestampClient (DER manual, 424 linhas) │   │
 │  │    parser DER puro para RFC 3161                                     │   │
 │  │                                                                       │   │
 │  │  asn1/                OpenSslAsn1Parser (DER manual, 216 linhas)      │   │
 │  │    parser DER puro com árvore hierárquica                             │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ models/  ── Modelos Puros Dart  (11 arquivos, 39 classes, 6 enums)   │   │
 │  │                                                                       │   │
 │  │  key_types.dart           KeySpec (sealed) + 4 subtipos               │   │
 │  │  crypto_error.dart        CryptoError (sealed) + 13 subtipos          │   │
 │  │  crypto_result.dart       CryptoResult<T> (sealed: Success/Failure)   │   │
 │  │  certificate_data.dart    CertificateData, X509Extension              │   │
 │  │  signing_algorithm.dart   SigningAlgorithm, HashAlgorithm             │   │
 │  │  distinguished_name.dart  DistinguishedName (validação CN, C, etc.)   │   │
 │  │  csr_data.dart            CsrRequest, CsrData                        │   │
 │  │  crl_data.dart            CrlInfo, RevokedEntry, RevocationStatus     │   │
 │  │  ocsp_data.dart           OcspResponse, CertificateStatus             │   │
 │  │  asn1_data.dart           Asn1Node (árvore hierárquica ASN.1)         │   │
 │  │  ts_data.dart             TimestampResponse, TimestampAccuracy        │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ utils/  ── Serializadores, Parsers, Builders  (9 arquivos)           │   │
 │  │                                                                       │   │
 │  │  openssl_error.dart          ERR_get_error → String formatada         │   │
 │  │  bio_utils.dart              BIO_new_mem_buf / BIO_read / BIO_free    │   │
 │  │  x509_loader.dart            PEM_read_bio_X509 / d2i_X509_bio         │   │
 │  │  x509_ext_parser.dart        Extensões X.509 v3 (SAN, BC, KU, EKU)   │   │
 │  │  x509_name_builder.dart      DistinguishedName → X509_NAME            │   │
 │  │  certificate_serializer.dart i2d_X509 + PEM_write_bio_X509            │   │
 │  │  key_pair_serializer.dart    EVP_PKEY → KeyPair (PEM), 228 linhas     │   │
 │  │  asn1_time.dart              ASN1_TIME ↔ DateTime                   │   │
 │  │  hex_utils.dart              Uint8List ↔ hex String                  │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ metrics/  ── Coleta de Métricas Independente  (12 arquivos)          │   │
 │  │                                                                       │   │
 │  │  metrics_collector.dart      Orquestrador central (476 linhas)        │   │
 │  │  metrics_models.dart         Modelos JSON schema v1.2.0 (1488 linhas) │   │
 │  │  timing.dart                 Latência: média, mediana, σ, CV, p99     │   │
 │  │  throughput.dart             Vazão em bytes/segundo (82 linhas)       │   │
 │  │  security_benchmark.dart     ops/s por algoritmo (841 linhas)         │   │
 │  │  security_metrics.dart       Bits de segurança por algoritmo          │   │
 │  │  safe_curves.dart            Validação SafeCurves (153 linhas)        │   │
 │  │  constant_time.dart          Análise de tempo constante (82 linhas)   │   │
 │  │  concurrency.dart            Throughput com Isolates (215 linhas)     │   │
 │  │  memory_tracker.dart         RSS via ProcessInfo.currentRss (82 lns)  │   │
 │  │  coverage_parser.dart        Análise de lcov.info (141 linhas)        │   │
 │  │  zeroization.dart            Verificação de zeroização pós-uso        │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │                   FFI LAYER  (dart:ffi)                                       │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ openssl_bindings.dart  ── 1.895 linhas de bindings C                 │   │
 │  │                                                                       │   │
 │  │  class OpenSslBindings {                                              │   │
 │  │    final DynamicLibrary _crypto;  // libcrypto.so (167 late-finals)   │   │
 │  │    final DynamicLibrary _ssl;     // libssl.so    (reserva)           │   │
 │  │                                                                       │   │
 │  │    late final EVP_DigestInit_exDart  evpDigestInitEx;                 │   │
 │  │    late final EVP_EncryptInit_exDart evpEncryptInitEx;                │   │
 │  │    late final EVP_aes_128_gcmDart    evpAes128Gcm;                    │   │
 │  │    ... (167 late-finals, cada = .lookup + .asFunction)                │   │
 │  │  }                                                                    │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │  ┌──────────────────────────────────────────────────────────────────────┐   │
 │  │ native_loader.dart  ── 76 linhas  dispatch por plataforma           │   │
 │  │                                                                       │   │
 │  │  DynamicLibrary loadCrypto() {                                        │   │
 │  │    if (Platform.isAndroid) return DynamicLibrary.open('libcrypto.so') │   │
 │  │    if (Platform.isLinux) {                                            │   │
 │  │      resolve native dir → DynamicLibrary.open('libcrypto.so.4')       │   │
 │  │    }                                                                  │   │
 │  │  }                                                                    │   │
 │  │  DynamicLibrary loadSsl() { ... idem para libssl.so ... }             │   │
 │  └──────────────────────────────────────────────────────────────────────┘   │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │                   NATIVE LAYER  (C/C++ pré-compilado, OpenSSL 4.0.0)         │
 │                                                                              │
 │  ┌──────────────────────────────────┬────────────────────────────────────┐  │
 │  │  LINUX x86_64                    │  ANDROID (3 ABIs  via jniLibs)    │  │
 │  │                                  │                                    │  │
 │  │  native/linux/x86_64/            │  android/src/main/jniLibs/         │  │
 │  │  ├── libcrypto.so.4    (7.0 MB)  │  ├── arm64-v8a/                    │  │
 │  │  ├── libssl.so.4       (964 KB)  │  │   ├── libcrypto.so   (~7 MB)    │  │
 │  │  └── providers/                  │  │   └── libssl.so      (~964 KB)  │  │
 │  │      ├── default.so             │  ├── armeabi-v7a/                   │  │
 │  │      ├── fips.so                │  │   ├── libcrypto.so               │  │
 │  │      ├── legacy.so              │  │   └── libssl.so                  │  │
 │  │      └── oqsprovider.so         │  └── x86_64/                        │  │
 │  │                                  │      ├── libcrypto.so               │  │
 │  │  Build: CMakeLists.txt           │      └── libssl.so                  │  │
 │  │  (99 linhas, C++ com GTK)        │                                    │  │
 │  │                                  │  Build: build.gradle.kts            │  │
 │  │                                  │  (79 linhas, Kotlin + NDK)          │  │
 │  └──────────────────────────────────┴────────────────────────────────────┘  │
 │                                                                              │
 │                        ▸ FLUXO DE DADOS (TOP-DOWN) ◂                         │
 │                                                                              │
 │  App Dart                                                                   │
 │    │  chama PluginCryptoAPI.instance.aes128GcmEncrypt(key, iv, plaintext)    │
 │    ▼                                                                         │
 │  PUBLIC API  (crypto_api.dart:113-118)                                       │
 │    │  valida key.length == 16                                                │
 │    │  delega para _aes.aes128GcmEncrypt(key, iv, plaintext, aad: aad)        │
 │    ▼                                                                         │
 │  CORE LAYER  (aes_operations.dart:53-61)                                     │
 │    │  _validateAesKeyLength(key, 16)                                         │
 │    │  chama _gcmCipherOp(key, iv, plaintext, _b.evpAes128Gcm(), true)        │
 │    ▼                                                                         │
 │  FFI LAYER  (openssl_bindings.dart:1311-1313)                                │
 │    │  _b.evpAes128Gcm  ──  late final resolvido em 1º acesso                │
 │    │  _b.evpCipherCtxNew / _b.evpEncryptInitEx / _b.evpEncryptUpdate         │
 │    │  _b.evpEncryptFinalEx / _b.evpCipherCtxCtrl                             │
 │    ▼                                                                         │
 │  NATIVE LAYER  (libcrypto.so.4 / libcrypto.so)                               │
 │    │  EVP_CIPHER_CTX_new   →  aloca contexto no heap C                      │
 │    │  EVP_EncryptInit_ex   →  seleciona cipher AES-128-GCM                   │
 │    │  EVP_EncryptUpdate    →  criptografa blocos, gera keystream GCM         │
 │    │  EVP_EncryptFinal_ex  →  finaliza, gera tag GHASH                      │
 │    │  EVP_CIPHER_CTX_ctrl  →  GET_TAG: extrai 16 bytes de authentication tag │
 │    │  EVP_CIPHER_CTX_free  →  libera contexto                               │
 │    ▼                                                                         │
 │  Resultado retorna: AesGcmResult(ciphertext: Uint8List, tag: Uint8List(16)) │
 └─────────────────────────────────────────────────────────────────────────────┘
```

## 2. Inicialização das Bindings FFI e Padrão `late final` Lazy

### 2.1 Motivação

O pacote `dart:ffi` exige que cada símbolo C seja resolvido individualmente via
`DynamicLibrary.lookup<NativeFunction<T>>('nome_do_símbolo')`. São 167 símbolos
distribuídos entre `libcrypto.so` e `libssl.so`. Resolver todos no construtor
causaria:

- **Custo de inicialização proibitivo**: 167 chamadas a `lookup()` + `asFunction()`
  antes que qualquer operação criptográfica pudesse ser executada.
- **Overhead em código que nunca usa todos os símbolos**: uma aplicação que só faz
  hash SHA-256 pagaria o custo de resolver símbolos de CMS, OCSP, CRL, etc.

### 2.2 Implementação

Cada binding é declarado como um campo `late final` na classe `OpenSslBindings`:

```dart
// openssl_bindings.dart:1213-1218
late final OpenSSLVersionDart openSSLVersion = _crypto
    .lookup<OpenSSLVersionNative>('OpenSSL_version')
    .asFunction<OpenSSLVersionDart>();
late final OSSL_PROVIDER_loadDart osslProviderLoad = _crypto
    .lookup<OSSL_PROVIDER_loadNative>('OSSL_PROVIDER_load')
    .asFunction<OSSL_PROVIDER_loadDart>();
```

O ciclo de vida de cada `late final`:

| Estágio | O que acontece |
|---------|---------------|
| **Declaração** | Nenhum código é executado. O compilador Dart aloca um slot no objeto `OpenSslBindings` com um bit `_initialized = false`. |
| **Primeiro acesso** | O getter implícito verifica `_initialized`. Se `false`, executa a expressão de inicialização: `DynamicLibrary.lookup()` → `NativeFunction` → `.asFunction()` → armazena o `Dart Function` no slot. |
| **Acessos subsequentes** | O getter retorna o valor já armazenado diretamente  zero overhead (um load de campo). |

### 2.3 Fluxo Completo de Inicialização

```
PluginCryptoAPI.instance          ← primeiro acesso ao singleton
  │
  ├─ _instance ??= PluginCryptoAPI._()
  │     │
  │     ├─ loadCrypto()           ← dispatcher de plataforma
  │     │     └─ DynamicLibrary.open('libcrypto.so.4')
  │     │         └─ dlopen("libcrypto.so.4", RTLD_LAZY)   ← syscall Linux
  │     │             └─ retorna DynamicLibrary handle
  │     │
  │     ├─ loadSsl()              ← dispatcher de plataforma
  │     │     └─ DynamicLibrary.open('libssl.so.4')
  │     │
  │     └─ OpenSslBindings.create(libcrypto, libssl)
  │           └─ armazena _crypto e _ssl (167 late finals NÃO executados)
  │
  └─ retorna _instance
```

No primeiro acesso a qualquer binding (ex.: `_b.evpSha256`), o getter implícito
executa `lookup` → `asFunction`. Isso distribui o custo de resolução de símbolos
pelo tempo de execução, sob demanda. Um método que usa 5 bindings paga o custo
de resolver apenas 5 símbolos.

### 2.4 Tipos de Bindings

Cada binding segue o padrão de duas definições de tipo:

```dart
// Tipo nativo (assinatura C exata)
typedef EVP_aes_128_gcmNative = NativeFunction<EVP_CIPHER Function()>;

// Tipo Dart (após .asFunction())
typedef EVP_aes_128_gcmDart = EVP_CIPHER Function();
```

O `NativeFunction` mapeia o ABI da arquitetura alvo (calling convention, tamanhos
de registradores). O tipo Dart é o que o código cliente usa, totalmente tipado,
com `Pointer<Void>` mapeado para os typedefs do topo do arquivo (`EVP_CIPHER`,
`EVP_MD_CTX`, etc.).

### 2.5 Domínios de Símbolos

| Domínio | Quantidade | Exemplos |
|---------|-----------|----------|
| Hash / Digest | 10 | `EVP_sha256`, `EVP_MD_CTX_new`, `EVP_DigestInit_ex` |
| Cifra Simétrica / AEAD | 14 | `EVP_aes_128_gcm`, `EVP_EncryptUpdate`, `EVP_CIPHER_CTX_ctrl` |
| Chave Assimétrica | 32 | `EVP_PKEY_keygen`, `EVP_DigestSign`, `EVP_PKEY_encapsulate` |
| X.509 | 30 | `X509_new`, `X509_sign`, `X509_get_ext_count` |
| BIO (I/O) | 8 | `BIO_new_mem_buf`, `BIO_read`, `BIO_new_file` |
| CMS/PKCS#7 | 14 | `CMS_sign`, `CMS_encrypt`, `CMS_SignerInfo_get0_signer_id` |
| CRL | 10 | `X509_CRL_verify`, `d2i_X509_CRL_bio` |
| OCSP | 17 | `OCSP_request_new`, `OCSP_basic_verify`, `OCSP_resp_find_status` |
| CSR | 10 | `X509_REQ_new`, `X509_REQ_sign` |
| Stack / ASN.1 / Util | 20 | `OPENSSL_sk_push`, `d2i_ASN1_TYPE_bio`, `OBJ_sn2nid` |
| Erro | 3 | `ERR_get_error`, `ERR_clear_error`, `ERR_error_string_n` |
| Random | 2 | `RAND_bytes`, `RAND_priv_bytes` |
| **Total** | **167** | |

---

## 3. Native Loader com Dispatch por Plataforma

### 3.1 Algoritmo de Resolução de Diretório Nativo (`_resolveNativeDir`)

```
_resolveNativeDir()
  │
  ├─ 1. PLUGIN_CRYPTO_NATIVE_DIR (variável de ambiente)
  │     └─ Se definida E o diretório existe → retorna
  │
  ├─ 2. {cwd}/native/linux/x86_64
  │     └─ Se existe → retorna
  │
  └─ 3. null
        └─ fallback para paths de sistema (etapa final do loader)
```

### 3.2 `loadCrypto()`: Caminhos por Plataforma

```
loadCrypto()
  │
  ├─ Platform.isAndroid ─────────────────────┐
  │   └─ DynamicLibrary.open('libcrypto.so') │  ← nome curto, Android resolve
  │      por libcrypto.so no jniLibs da ABI  │     via linker do Android (APK)
  │                                          │
  ├─ Platform.isIOS ─────────────────────────┤
  │   └─ DynamicLibrary.process()            │  ← símbolos linkados estaticamente
  │      no processo                         │     no binário do app iOS
  │                                          │
  └─ Platform.isLinux ───────────────────────┤
      │                                       │
      ├─ nativeDir = _resolveNativeDir()      │
      │   ├─ Se definido:                     │
      │   │   ├─ tenta libcrypto.so.4         │  ← OpenSSL 4.0.0 (preferencial)
      │   │   └─ fallback: libcrypto.so       │  ← versão sem sufixo
      │   │                                    │
      │   └─ Se null (fallback sistema):       │
      │       ├─ tenta libcrypto.so.4         │  ← busca nos ld paths
      │       ├─ fallback: libcrypto.so       │  ← /usr/lib, /usr/local/lib
      │       └─ fallback: libcrypto.so.3     │  ← OpenSSL 3.x (sistema)
      │                                        │
      └─ Se todas falharem:                    │
          └─ throw UnsupportedError            │
```

### 3.3 `loadSsl()`: Estrutura Análoga

Mesmo algoritmo de `loadCrypto()`, porém buscando `libssl.so` / `libssl.so.4` /
`libssl.so.3`. A prioridade e fallback são idênticos.

### 3.4 Diferença Fundamental: Android JNI vs Linux dlopen

| Aspecto | Linux (`dlopen`) | Android (JNI via `System.loadLibrary`) |
|---------|-----------------|----------------------------------------|
| **Mecanismo** | `DynamicLibrary.open(path)` → `dlopen(path, RTLD_LAZY)` | `DynamicLibrary.open('libcrypto.so')` → delegate ao linker do Android Runtime (ART) |
| **Resolução de caminho** | Caminho absoluto ou relativo ao CWD; busca em `LD_LIBRARY_PATH` e `/etc/ld.so.conf` | Busca automática no `jniLibs/` da ABI correta; sem caminho explícito |
| **Sufixo de versão** | `libcrypto.so.4`  necessário porque Linux permite múltiplas versões coexistentes | `libcrypto.so`  sem sufixo; o APK contém exatamente uma versão por ABI |
| **Providers** | Carregados do diretório `providers/` relativo ao `.so` | Providers embutidos no `libcrypto.so` (compilação monolítica) ou não disponíveis |
| **Threading** | pthreads (nativo do Linux) | Bionic libc threads (Android)  compatível, mesma API POSIX |
| **Build** | GCC/Clang com CMake, target x86_64-linux-gnu | NDK cross-compiler, targets: aarch64-linux-android, armv7a-linux-androideabi, x86_64-linux-android |

## 4. Providers OpenSSL 4.0.0

### 4.1 Arquitetura de Providers

O OpenSSL 4.0.0 implementa uma arquitetura de providers plugáveis. Cada provider
é um `.so` que registra conjuntos de algoritmos (ciphers, digests, signatures,
KEMs, keymgmt, KDFs, MACs, RNGs) em um `OSSL_LIB_CTX`. O dispatch de operações
criptográficas é roteado para o provider que registrou o algoritmo solicitado.

### 4.2 Tabela de Providers

| Provider | Arquivo | Carregamento | Algoritmos Registrados |
|----------|---------|-------------|----------------------|
| **default** | `providers/default.so` | **Sempre carregado** (built-in ao init do OpenSSL) | **Cifras simétricas:** AES-128/192/256 (ECB, CBC, CTR, OFB, CFB, XTS, GCM, CCM, OCB, WRAP), Camellia, SM4. **Digests:** SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512, SHAKE128/256. **MAC:** HMAC (todos SHA), CMAC (AES), GMAC (AES-GCM). **Assinatura:** RSA (PKCS#1 v1.5, PSS, X9.31), DSA, ECDSA (P-256/384/521), Ed25519, Ed448. **Troca de chaves:** DH, ECDH, X25519, X448. **KDF:** HKDF, PBKDF2, SSKDF, TLS1-PRF, KBKDF. **KEM:** RSA. **RNG:** CTR-DRBG, Hash-DRBG, HMAC-DRBG. **Keymgmt:** RSA, DSA, DH, EC, ECX (X25519/X448/Ed25519/Ed448). |
| **fips** | `providers/fips.so` | **Condicional** (se o arquivo existir no diretório de providers) | **Subconjunto certificado FIPS 140-3** dos algoritmos acima: AES (ECB, CBC, CTR, GCM, CCM, XTS  FIPS), SHA-2, SHA-3, HMAC, CMAC, GMAC, RSA (assinatura e KEM, chaves >= 2048 bits), ECDSA (curvas aprovadas pelo NIST: P-256, P-384, P-521), DH, ECDH, HKDF, PBKDF2, DRBGs. Inclui **self-tests (KAT)** obrigatórios executados no carregamento: AES (encrypt/decrypt conhecidos), SHA (vetores de teste), RSA (sign/verify), ECDSA, DRBG. Estes KATs são executados via `fips_self_test.c` e falham o carregamento se qualquer teste falhar. |
| **legacy** | `providers/legacy.so` | **Condicional** (se o arquivo existir) | **Algoritmos depreciados e inseguros:** DES (ECB, CBC, CFB, OFB), 3DES (TDES), RC4, RC5, Blowfish, CAST5, IDEA, SEED. **Digests:** MD4, MD5, MDC2, RIPEMD160, Whirlpool. **MAC:** HMAC-MD5. |
| **oqsprovider** | `providers/oqsprovider.so` | **Condicional** (se o arquivo existir; pós-quântico) | **KEM pós-quântico:** ML-KEM-512 (Kyber-512), ML-KEM-768 (Kyber-768), ML-KEM-1024 (Kyber-1024). **Assinatura pós-quântica:** ML-DSA-44 (Dilithium-2), ML-DSA-65 (Dilithium-3), ML-DSA-87 (Dilithium-5), SLH-DSA (SPHINCS+ nos parâmetros NIST). **Keymgmt:** ML-KEM, ML-DSA, SLH-DSA. |

### 4.3 Inicialização dos Providers

```dart
// O carregamento de providers é feito via OSSL_PROVIDER_load
// Chamado no contexto do primeiro uso de operações que exigem providers

// Provider default, built-in, sempre disponível:
//   OSSL_PROVIDER_load(nullptr, "default")

// Provider fips:
//   OSSL_PROVIDER_load(nullptr, "fips")
//   → carrega providers/fips.so
//   → executa self-tests (KATs)
//   → se falhar, retorna nullptr

// Provider legacy:
//   OSSL_PROVIDER_load(nullptr, "legacy")
//   → carrega providers/legacy.so

// Provider oqsprovider:
//   OSSL_PROVIDER_load(nullptr, "oqsprovider")
//   → carrega providers/oqsprovider.so
//   → registra algoritmos ML-KEM e ML-DSA
```

### 4.4 Carregamento Condicional

O `oqsprovider` e `legacy` são carregados condicionalmente, se o arquivo `.so`
não existir no diretório de providers, `OSSL_PROVIDER_load` retorna `nullptr`. O
código Dart trata isso de forma transparente: as operações que dependem desses
providers (ML-KEM, ML-DSA, DES, MD5) retornam erro se chamadas sem o provider.

---

## 5. Segurança de Thread

### 5.1 Modelo: Totalmente Síncrono

**Todas as operações da API pública de PluginCrypto são síncronas.** Nenhuma
operação retorna `Future`, `Stream`, ou dispara callbacks assíncronos. Não há
fila de eventos, event loop, ou I/O não bloqueante envolvido nas operações
criptográficas.

```dart
// Toda chamada é bloqueante (síncrona):
Uint8List hash = PluginCryptoAPI.instance.sha256(data);
KeyPair kp = PluginCryptoAPI.instance.generateRsaKeyPair(2048);
bool ok = PluginCryptoAPI.instance.verify(data, pubKey, sig);
```

### 5.2 Estruturas Não Compartilhadas Entre Threads

Cada chamada cria seu próprio contexto OpenSSL descartável:

- `EVP_MD_CTX`, contexto de hash, criado em `_digest()` e liberado no `finally`
- `EVP_CIPHER_CTX`, contexto de cifra, criado em `_cipherOp()` / `_gcmCipherOp()`
- `EVP_PKEY_CTX`, contexto de chave assimétrica, criado em cada `KeyCreator.create()`
- `X509_STORE_CTX`, contexto de validação de cadeia, criado em cada `verifyX509Certificate()`

**Nenhuma dessas estruturas é preservada entre chamadas**, são alocadas em cada
invocação e liberadas antes do retorno. Isso elimina completamente a possibilidade
de data races.

### 5.3 Thread Safety do OpenSSL

O OpenSSL internamente é thread-safe quando inicializado corretamente:

- **CRYPTO_THREAD_init**: O OpenSSL 4.0.0 usa `pthreads` (Linux) ou `Bionic libc`
  (Android) para locking interno de estruturas globais (tabela de algoritmos,
  cache de erro, alocadores).
- **ERR_get_error / ERR_clear_error**: A fila de erros é thread-local (armazenada
  em TLS (Thread-Local Storage). Cada thread tem sua própria fila de erro OpenSSL,
  eliminando a necessidade de locks na leitura/limpeza de erros.
- **RAND_bytes**: O DRBG (Deterministic Random Bit Generator) global usa lock
  interno para acesso concorrente.
- **OSSL_LIB_CTX**: Pode ser compartilhado entre threads com segurança interna
  via RCU (Read-Copy-Update) no OpenSSL 4.0.0.

### 5.4 Uso com Dart Isolates

Se o usuário desejar paralelismo (ex.: criptografar múltiplos arquivos
simultaneamente), o padrão recomendado é usar `Isolate`:

```dart
// Cada Isolate carrega sua própria cópia das bibliotecas nativas
final result = await Isolate.run(() {
  return PluginCryptoAPI.instance.aes256GcmEncrypt(key, iv, data);
});
```

**Restrição:** `DynamicLibrary.open()` precisa ser chamado em cada Isolate
separadamente. A implementação atual do singleton `PluginCryptoAPI.instance`
usa `static`, portanto, em múltiplos Isolates, cada Isolate terá sua própria
instância independente de `PluginCryptoAPI`, com seu próprio `OpenSslBindings`
e seus próprios handles `DynamicLibrary`.

## 6. Modelo de Memória: `calloc` vs GC Dart

### 6.1 Dois Universos de Memória

O PluginCrypto opera em dois universos de memória radicalmente diferentes:

| Memória | Gerenciador | Alocação | Liberação | Tipo de Dados |
|---------|------------|----------|-----------|---------------|
| **Dart Heap** | GC Dart (tracing generational) | Automática (`Uint8List`, `String`) | Automática (GC) | Dados gerenciados: resultados, argumentos |
| **C Heap** | `malloc`/`calloc` do libc | Manual via `package:ffi` (`calloc<T>()`) | Manual via `calloc.free()` ou `*_free()` OpenSSL | Ponteiros nativos: buffers temporários, contexts OpenSSL |

### 6.2 O Problema: Ponteiro Nativo em Try/Catch Dart

Se uma exceção Dart for lançada após `calloc<Uint8>(n)` mas antes de
`calloc.free(ptr)`, a memória nativa vaza **permanentemente**, o GC Dart
não tem conhecimento de alocações fora do heap gerenciado.

```dart
// PERIGO, vazamento se houver exceção:
final buf = calloc<Uint8>(1024);  // alocado no C heap
doSomethingThatMightThrow(buf);   // se lançar exceção...
calloc.free(buf);                 // ...esta linha nunca executa
```

### 6.3 Solução: Padrão `try/finally` Aninhado

**TODA alocação nativa é envolvida em `try/finally`.** A ordem de aninhamento
garante liberação na ordem inversa da alocação (LIFO):

```dart
// aes_operations.dart:236-373, exemplo real de _gcmCipherOp
final ctx = _b.evpCipherCtxNew();              // Nível 1: contexto EVP
if (ctx == nullptr) _fail('EVP_CIPHER_CTX_new');
try {
  final kp = calloc<Uint8>(key.length);        // Nível 2: chave
  final ivp = calloc<Uint8>(iv.length);         // Nível 2: IV
  kp.asTypedList(key.length).setAll(0, key);
  ivp.asTypedList(iv.length).setAll(0, iv);
  try {
    // ... init cipher ...

    if (aad != null && aad.isNotEmpty) {
      final aadP = calloc<Uint8>(aad.length);  // Nível 3: AAD
      try {
        aadP.asTypedList(aad.length).setAll(0, aad);
        final aadWritten = calloc<Int>();       // Nível 4: aadWritten
        try {
          _b.evpEncryptUpdate(ctx, nullptr, aadWritten, aadP, aad.length);
        } finally {
          calloc.free(aadWritten);              // Libera Nível 4
        }
      } finally {
        calloc.free(aadP);                      // Libera Nível 3
      }
    }

    final out = calloc<Uint8>(outLen);           // Nível 3: buffer saída
    final written = calloc<Int>();               // Nível 3: contador
    try {
      final dp = calloc<Uint8>(data.length);    // Nível 4: dados entrada
      try {
        // ... evpEncryptUpdate, evpEncryptFinalEx ...
        final finalWritten = calloc<Int>();      // Nível 5: finalWritten
        try {
          // ... evpEncryptFinalEx, extrai tag ...
        } finally {
          calloc.free(finalWritten);             // Libera Nível 5
        }
      } finally {
        calloc.free(dp);                         // Libera Nível 4
      }
    } finally {
      calloc.free(out);                          // Libera Nível 3
      calloc.free(written);
    }
  } finally {
    calloc.free(kp);                             // Libera Nível 2
    calloc.free(ivp);
  }
} finally {
  _b.evpCipherCtxFree(ctx);                     // Libera Nível 1
}
```

### 6.4 Analogia Visual do Aninhamento

```
ctx = EVP_CIPHER_CTX_new()          ───────────────────────── +1 ─┐
try {                                                              │
    kp = calloc(key.len)            ──────────────────── +1 ─┐    │
    ivp = calloc(iv.len)            ──────────────────── +1 ┤    │
    try {                                                     │    │
        out = calloc(outLen)        ─────────────── +1 ─┐    │    │
        written = calloc(Int)       ─────────────── +1 ┤    │    │
        try {                                           │    │    │
            dp = calloc(data.len)   ────────── +1 ─┐   │    │    │
            try {                                   │   │    │    │
                finalWritten=calloc ────── +1 ─┐   │   │    │    │
                try { USE(a,b,c,d,e,f) }       │   │   │    │    │
                finally { free(f) }   ── -1 ──┘   │   │    │    │
            } finally { free(dp) }    ── -1 ──────┘   │    │    │
        } finally { free(out)        ── -1 ───────────┤    │    │
                     free(written)   ── -1 ───────────┘    │    │
    } finally { free(kp)            ── -1 ────────────────┤    │
                 free(ivp)          ── -1 ────────────────┘    │
} finally { EVP_CIPHER_CTX_free(ctx) ── -1 ───────────────────┘

Se exceção lançada em USE(a,b,c,d,e,f):
  1. finally { free(f) }           ← executado
  2. finally { free(dp) }           ← executado
  3. finally { free(out, written) } ← executado
  4. finally { free(kp, ivp) }      ← executado
  5. finally { EVP_CIPHER_CTX_free }← executado
  → Zero vazamento de memória nativa, independentemente de onde a exceção ocorreu
```

### 6.5 `calloc` vs `malloc`

`package:ffi` provê `calloc<T>()` que chama `calloc(count, sizeof(T))` do libc:

- **calloc** = `malloc(count * size)` + `memset(ptr, 0, count * size)`
  Garante que a memória está zerada, importante para segurança (evita leak de
  dados residuais do heap entre operações criptográficas).
- Ponteiros não inicializados são setados para `null` (em plataformas onde
  ponteiro nulo == 0), eliminando uma classe de bugs.

### 6.6 Contextos OpenSSL (Não Gerenciados por `calloc`)

Contextos OpenSSL (`EVP_MD_CTX`, `EVP_CIPHER_CTX`, `EVP_PKEY`, `BIO`, `X509`,
etc.) são alocados internamente pelo OpenSSL via `OPENSSL_malloc()` e devem ser
liberados com suas funções `_free()` específicas. O padrão `try/finally` se aplica
igualmente a eles:

```dart
final ctx = _b.evpMdCtxNew();     // alocado via OPENSSL_malloc()
try {
  _b.evpDigestInitEx(ctx, md, nullptr);
  // ...
} finally {
  _b.evpMdCtxFree(ctx);           // liberado via OPENSSL_free()
}
```

### 6.7 Fila de Erro OpenSSL

Após cada falha, `ERR_clear_error()` é chamado para limpar a fila de erros
thread-local:

```dart
// aes_operations.dart:375-393
void _check1(int result, String op) {
  if (result != 1) {
    final err = getOpenSslError(_b);  // consome o erro da fila
    _b.errClearError();               // limpa erros residuais
    throw StateError('$op failed${err != null ? ': $err' : ''}');
  }
}
```

O padrão `getOpenSslError` + `errClearError` é executado em todos os mais de 50
pontos de verificação de erro no código. Isso evita que erros de uma operação
"contaminem" o diagnóstico da operação seguinte.

---

## 7. Rastreamento Completo Fim-a-Fim: `aes128GcmEncrypt`

### 7.1 Stack de Chamada (Top-Down)

```
[Nível 7  App Dart]
  │
  │ var result = PluginCryptoAPI.instance.aes128GcmEncrypt(
  │   key,       // Uint8List(16)  128 bits
  │   iv,        // Uint8List(12)  96 bits (recomendado pelo NIST)
  │   plaintext, // Uint8List(N)  dados a criptografar
  │   aad: aad,  // Uint8List?  authenticated additional data
  │ );
  │
  ▼
[Nível 6  Public API: crypto_api.dart:113-118]
  │
  │ AesGcmResult aes128GcmEncrypt(
  │   Uint8List key, Uint8List iv, Uint8List plaintext,
  │   {Uint8List? aad}
  │ ) => _aes.aes128GcmEncrypt(key, iv, plaintext, aad: aad);
  │
  ▼
[Nível 5  Core AES: aes_operations.dart:53-61]
  │
  │ AesGcmResult aes128GcmEncrypt(...) {
  │   _validateAesKeyLength(key, 16);    // key.length == 16?
  │   return _gcmCipherOp(
  │     key, iv, plaintext,
  │     _b.evpAes128Gcm(),              // ← late final resolvido aqui (1º acesso)
  │     true,                            // encrypt=true
  │     aad: aad,
  │   );
  │ }
  │
  ▼
[Nível 4  Core AES: aes_operations.dart:227-373  _gcmCipherOp]
  │
  │ Passo 1: EVP_CIPHER_CTX_new()          ← aloca contexto limpo
  │ Passo 2: calloc key, iv buffers        ← copia key/iv para C heap
  │ Passo 3: EVP_EncryptInit_ex(ctx, cipher=EVP_aes_128_gcm(),
  │                               engine=null, key, iv)
  │          └─ seleciona algoritmo AES-128-GCM
  │          └─ configura key schedule (AES key expansion: 10 rounds p/ 128-bit)
  │          └─ armazena IV para inicialização do contador GCM
  │ Passo 4: (Opcional) Se AAD fornecido:
  │            EVP_EncryptUpdate(ctx, out=null, &written, aad, aad.len)
  │            └─ alimenta AAD ao GHASH (autentica mas não criptografa)
  │ Passo 5: calloc(data.len) buffer       ← copia plaintext para C heap
  │ Passo 6: EVP_EncryptUpdate(ctx, out, &written, plaintext, plaintext.len)
  │          └─ para cada bloco de 16 bytes do plaintext:
  │              - incrementa contador GCM (32-bit counter)
  │              - AES_encrypt(counter_block) → keystream_block
  │              - ciphertext_block = plaintext_block XOR keystream_block
  │              - GHASH.update(ciphertext_block)
  │ Passo 7: EVP_EncryptFinal_ex(ctx, out+written, &finalWritten)
  │          └─ finaliza GHASH:
  │              - padding final (zero-padding ao bloco de 16 bytes)
  │              - GHASH.final(len(AAD) || len(ciphertext)) → tag parcial
  │              - AES_encrypt(IV || counter=0) XOR tag_parcial → tag final
  │ Passo 8: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GET_TAG, 16, tagBuf)
  │          └─ extrai os 16 bytes da authentication tag
  │ Passo 9: retorna AesGcmResult(
  │            ciphertext = Uint8List.fromList(out[0..resultLen]),
  │            tag        = Uint8List.fromList(tagBuf[0..16]),
  │          )
  │ Passo 10: calloc.free de todos os buffers no finally
  │ Passo 11: EVP_CIPHER_CTX_free(ctx)     ← libera contexto nativo
  │
  ▼
[Nível 3  FFI: openssl_bindings.dart  late finals resolvidos sob demanda]
  │
  │ _b.evpAes128Gcm          → Dart function que chama EVP_aes_128_gcm()
  │ _b.evpCipherCtxNew       → Dart function que chama EVP_CIPHER_CTX_new()
  │ _b.evpEncryptInitEx      → Dart function que chama EVP_EncryptInit_ex()
  │ _b.evpEncryptUpdate      → Dart function que chama EVP_EncryptUpdate()
  │ _b.evpEncryptFinalEx     → Dart function que chama EVP_EncryptFinal_ex()
  │ _b.evpCipherCtxCtrl      → Dart function que chama EVP_CIPHER_CTX_ctrl()
  │ _b.evpCipherCtxFree      → Dart function que chama EVP_CIPHER_CTX_free()
  │
  ▼
[Nível 2  dart:ffi trampoline]
  │
  │ Conversão de tipos Dart → C:
  │   Uint8List → Pointer<Uint8> (calloc + cópia manual)
  │   int → Int (compatível com C int de 32 bits)
  │   Pointer<Void> → passagem direta (mesmo endereço de memória)
  │
  │ Cada chamada FFI transita:
  │   Dart stack → FFI trampoline → C calling convention → C stack
  │   (preservação de registradores conforme ABI da plataforma)
  │
  ▼
[Nível 1  Native: libcrypto.so]
  │
  │ EVP_aes_128_gcm()                       ← retorna EVP_CIPHER* (estático)
  │ EVP_CIPHER_CTX_new()                    ← OPENSSL_zalloc(sizeof(EVP_CIPHER_CTX))
  │ EVP_EncryptInit_ex(ctx, cipher, ...)    ← dispatch para provider "default"
  │   └─ provider default → cipher_aes_gcm.c
  │       └─ AES_set_encrypt_key(key, 128)  ← key schedule (AES-NI se disponível)
  │       └─ CRYPTO_gcm128_init(&ctx->gcm, ...)
  │ EVP_EncryptUpdate(ctx, out, ...)        ← cipher_aes_gcm_hw.c
  │   └─ se CPU tem AES-NI:
  │       └─ aesni_gcm_encrypt() ← instruções AES-NI + PCLMULQDQ (GHASH)
  │   └─ senão:
  │       └─ aes_gcm_encrypt()  ← implementação software (constante-time)
  │ EVP_EncryptFinal_ex(ctx, ...)          ← finaliza GHASH, gera tag
  │ EVP_CIPHER_CTX_ctrl(ctx, GET_TAG, ...) ← cópia tag do contexto
  │ EVP_CIPHER_CTX_free(ctx)               ← OPENSSL_clear_free (zeroização)
  │
  ▼
[Nível 0  CPU]
  │
  │ x86_64 (Linux) ou ARMv8 (Android):
  │   - AES-NI: aesenc, aesenclast (10 rounds para AES-128)
  │   - PCLMULQDQ: multiplicação em GF(2^128) para GHASH
  │   - ou NEON (ARM): instruções AES + PMULL para GHASH
  │   - ou software: tabelas de lookup constant-time
  │
  └─ Resultado retorna ao longo da stack para o Dart → App Dart
```

### 7.2 Tratamento de Erro no Caminho

Se `EVP_EncryptFinal_ex` falhar (ex.: tag corrompida na descriptografia):

```
EVP_DecryptFinal_ex retorna 0
  └─ _check1(0, 'EVP_DecryptFinal_ex(GCM)')   ← aes_operations.dart:379-384
      └─ _b.errGetError()                     ← lê código de erro da TLS
      └─ _b.errClearError()                   ← limpa fila de erro
      └─ throw AesGcmAuthFailure(reason: ...)  ← exceção tipada Dart
```

O `finally` mais externo garante que `EVP_CIPHER_CTX_free` seja chamado mesmo
após o throw, liberando a memória do contexto.

### 7.3 Cópia de Dados Dart → C → Dart

```
plaintext (Uint8List no Dart Heap, gerenciado pelo GC)
    │
    │ calloc<Uint8>(data.length)          ← aloca no C heap
    │ dp.asTypedList(N).setAll(0, data)   ← CÓPIA (N bytes)
    ▼
Pointer<Uint8> dp (C heap)
    │
    │ EVP_EncryptUpdate(ctx, out, written, dp, N)
    │   └─ OpenSSL lê de dp (C heap)
    │   └─ escreve ciphertext em out (C heap)
    ▼
out.asTypedList(resultLen)               ← cria TypedListView
    │
    │ Uint8List.fromList(view)            ← CÓPIA (resultLen bytes)
    ▼
Uint8List result (Dart Heap, gerenciado pelo GC)
    │
    │ calloc.free(dp)                     ← libera C heap
    │ calloc.free(out)                    ← libera C heap
    ▼
result retornado ao caller Dart
```

**Total de cópias de dados:** 2 (Dart → C na entrada, C → Dart na saída). O
overhead é dominado pelo tempo da operação criptográfica em si (AES + GHASH),
não pelas cópias.

## 8. Comparação Detalhada: Android JNI vs Linux dlopen

### 8.1 Mecanismo de Carga

| | Linux | Android |
|---|-------|---------|
| **API Flutter** | `DynamicLibrary.open(path)` | `DynamicLibrary.open('libcrypto.so')` |
| **Syscall subjacente** | `dlopen(path, RTLD_LAZY)` | ART interno  mapeia para `android_dlopen_ext()` |
| **Resolução de caminho** | Caminho absoluto calculado em runtime relativo ao CWD ou diretório do plugin | Nome curto  o Android Runtime localiza nos diretórios `jniLibs/<abi>/` do APK |
| **Fallback** | Tenta `libcrypto.so.4` → `libcrypto.so` → `libcrypto.so.3` nos paths do sistema (`LD_LIBRARY_PATH`, `/usr/lib`, `/etc/ld.so.conf`) | Sem fallback  o APK contém a versão exata necessária |
| **Sufixo de versão** | `libcrypto.so.4` (SONAME versionado, múltiplas versões podem coexistir) | `libcrypto.so` (sem sufixo, Android não usa versionamento de SO tradicional) |

### 8.2 Empacotamento e Distribuição

| | Linux | Android |
|---|-------|---------|
| **Localização dos .so** | `native/linux/x86_64/` no diretório do plugin | `android/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/` |
| **Mecanismo de empacotamento** | `CMakeLists.txt` → `PLUGIN_BUNDLED_LIBRARIES` → copiados para o bundle do app Flutter | `build.gradle.kts` → `jniLibs.srcDirs(...)` → Gradle empacota automaticamente no APK |
| **ABIs suportadas** | Apenas x86_64 (Linux desktop) | 3 ABIs: arm64-v8a (64-bit), armeabi-v7a (32-bit), x86_64 (emulador) |
| **Providers** | Arquivos `.so` separados no diretório `providers/` | Providers podem ser embutidos na build do `libcrypto.so` (configuração de compilação cruzada) |
| **Build toolchain** | Clang/GCC nativo via CMake | NDK cross-compiler (Android NDK 27.1.12297006) |
| **Target triple** | `x86_64-linux-gnu` | `aarch64-linux-android`, `armv7a-linux-androideabi`, `x86_64-linux-android` |

### 8.3 Plugin MethodChannel com Presença Mínima

O plugin Android (`PluginCryptoPlugin.kt`, 38 linhas) existe **apenas** para
registro no Flutter Engine. A comunicação real é FFI direta Dart→C, sem passar
pelo MethodChannel:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Fluxo de Comunicação                          │
│                                                                  │
│  Dart App                                                        │
│    │                                                             │
│    ├──▶ PluginCryptoAPI.instance.aes128GcmEncrypt(...)            │
│    │       │                                                     │
│    │       ▼                                                     │
│    │    dart:ffi → libcrypto.so (direto, sem MethodChannel)      │
│    │                                                             │
│    └──▶ (apenas) MethodChannel("plugin_crypto")                  │
│              │                                                   │
│              ▼                                                   │
│           PluginCryptoPlugin.kt                                  │
│              │                                                   │
│              └── "getPlatformVersion" → "Android 14"             │
│                                                                  │
│  99.9% das chamadas: FFI direto                                  │
│  0.1% das chamadas:  MethodChannel (getPlatformVersion)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Build Linux com CMakeLists.txt (99 linhas)

### 9.1 Estrutura do Build

```cmake
# Alvo: plugin_crypto_plugin (shared library para Flutter Linux)
add_library(plugin_crypto_plugin SHARED "plugin_crypto_plugin.cc")

# Dependências
target_link_libraries(plugin_crypto_plugin PRIVATE flutter)     # Flutter embedding
target_link_libraries(plugin_crypto_plugin PRIVATE PkgConfig::GTK)  # GTK para janela

# Bundling das bibliotecas OpenSSL
set(PLUGIN_BUNDLED_LIBRARIES
  "${OPENSSL_NATIVE_DIR}/libcrypto.so.4"
  "${OPENSSL_NATIVE_DIR}/libssl.so.4"
  PARENT_SCOPE
)
```

### 9.2 Configurações de Compilação

| Configuração | Valor | Propósito |
|-------------|-------|-----------|
| `CXX_VISIBILITY_PRESET` | `hidden` | Símbolos C++ ocultos por padrão  apenas marcados com `FLUTTER_PLUGIN_EXPORT` são exportados. Evita conflitos de símbolos entre plugins. |
| `FLUTTER_PLUGIN_IMPL` | Definido | Macro de pré-processador que expande para `__attribute__((visibility("default")))` nos símbolos que o Flutter Engine precisa encontrar. |
| `CMAKE_MINIMUM_REQUIRED` | 3.10 | Compatibilidade com versões antigas de CMake em distros LTS. |
| Google Test | 1.11.0 via `FetchContent` | Testes unitários C++ compilados apenas quando `include_plugin_crypto_tests=true`. |

### 9.3 Testes C++

Os testes unitários nativos são compilados como um executável separado
(`plugin_crypto_test`) linkando `gtest_main` + `gmock`. Só são compilados
quando o app de exemplo define `include_plugin_crypto_tests`.

## 10. Build Android com build.gradle.kts (79 linhas)

### 10.1 Configurações Chave

| Configuração | Valor | Propósito |
|-------------|-------|-----------|
| `compileSdk` | 36 | API level de compilação (Android 15) |
| `minSdk` | 29 | API mínima (Android 10+)  exigido pelo OpenSSL 4.0.0 |
| `ndkVersion` | 27.1.12297006 | NDK usado para compilação cruzada das `.so` |
| `jniLibs.srcDirs` | `src/main/jniLibs` | Diretório de onde as `.so` pré-compiladas são empacotadas no APK |
| `sourceCompatibility` | Java 17 | Bytecode target Java 17 |
| Kotlin | 2.2.20 | Versão do compilador Kotlin |

### 10.2 Testes Kotlin

Testes unitários com JUnit Platform + Mockito 5.0.0:

```kotlin
testOptions {
    unitTests {
        all { it.useJUnitPlatform() }
        testLogging {
            events("passed", "skipped", "failed", "standardOut", "standardError")
        }
    }
}
```

---

## 11. Camada Core: Operações Atômicas

### 11.1 `crypto_operations.dart` (78 linhas)

Responsável por hash e números aleatórios stateless. Cada chamada aloca e libera seu próprio
`EVP_MD_CTX`:

- **`randomBytes(length)`**: `RAND_bytes(buf, length)` → `Uint8List.fromList()`
  + `calloc.free()`. O buffer é alocado via `calloc<Uint8>(length)` para receber
  os bytes do DRBG.
- **`_digest(data, md, digestLen)`**: `EVP_MD_CTX_new` → `EVP_DigestInit_ex` →
  `EVP_DigestUpdate` → `EVP_DigestFinal_ex` → `EVP_MD_CTX_free`. O buffer de
  dados de entrada é copiado para C heap via `calloc` + `asTypedList().setAll()`.

### 11.2 `aes_operations.dart` (394 linhas)

Gerencia AES-128/256 nos modos CBC e GCM. Duas funções core internas:

- **`_cipherOp()`** (CBC): Algoritmo simétrico, Init, Update, Final. Padding
  PKCS#7 automático do OpenSSL.
- **`_gcmCipherOp()`** (GCM): Modo AEAD, adicionalmente gerencia AAD (opcional)
  e authentication tag (GET_TAG na encriptação, SET_TAG na decriptação).

Validações:
- `key.length` igual a 16 (AES-128) ou 32 (AES-256)
- `iv.length` == 16 para CBC; GCM aceita IV de tamanho variável (recomendado 12 bytes)
- `tag.length` == 16 para GCM decrypt (rejeita tags < 16 bytes)

### 11.3 `asymmetric_operations.dart` (444 linhas)

Encapsula a pipeline completa de chaves assimétricas, geração, assinatura, encriptação e algoritmos pós-quânticos:

| Operação | Pipeline OpenSSL |
|----------|-----------------|
| `generateRsaKeyPair(bits)` | `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA)` → `EVP_PKEY_keygen_init` → `EVP_PKEY_CTX_set_rsa_keygen_bits` → `EVP_PKEY_keygen` → `KeyPairSerializer.extract()` |
| `generateEcKeyPair(curveName)` | `OBJ_sn2nid(curveName)` → `EVP_PKEY_CTX_new_id(EVP_PKEY_EC)` → `EVP_PKEY_CTX_set_ec_paramgen_curve_nid` → `EVP_PKEY_keygen` → serialização PEM |
| `sign(data, privKey)` | `BIO_new_mem_buf(privKey)` → `PEM_read_bio_PrivateKey` → `EVP_MD_CTX_new` → `EVP_DigestSignInit` → `EVP_DigestSign` |
| `verify(data, pubKey, sig)` | `BIO_new_mem_buf(pubKey)` → `PEM_read_bio_PUBKEY` → `EVP_MD_CTX_new` → `EVP_DigestVerifyInit` → `EVP_DigestVerify` |
| `rsaEncrypt(pubKey, plaintext)` | `PEM_read_bio_PUBKEY` → `EVP_PKEY_CTX_new` → `EVP_PKEY_encrypt_init` → `EVP_PKEY_encrypt` (OAEP-SHA256) |
| `rsaDecrypt(privKey, ciphertext)` | `PEM_read_bio_PrivateKey` → `EVP_PKEY_CTX_new` → `EVP_PKEY_decrypt_init` → `EVP_PKEY_decrypt` (OAEP-SHA256) |
| `mlKemEncapsulate(pubKey)` | `PEM_read_bio_PUBKEY` → `EVP_PKEY_CTX_new` → `EVP_PKEY_encapsulate_init` → `EVP_PKEY_encapsulate` → retorna `(ciphertext, sharedSecret)` |
| `mlKemDecapsulate(privKey, ct)` | `PEM_read_bio_PrivateKey` → `EVP_PKEY_CTX_new` → `EVP_PKEY_decapsulate_init` → `EVP_PKEY_decapsulate` → retorna `sharedSecret` 32 bytes |

### 11.4 `x509_operations.dart` (171 linhas)

- **`parseX509Certificate()`**: Tenta `PEM_read_bio_X509` primeiro; se falhar,
  fallback para `d2i_X509_bio` (DER). Extrai subject, issuer, serialNumber,
  notBefore, notAfter, public key, e extensões X.509 v3 (opcionais).
- **`verifyX509Certificate()`**: `X509_STORE_new` → `X509_STORE_add_cert(caCert)`
  → `X509_STORE_CTX_new` → `X509_STORE_CTX_init` → `X509_verify_cert`.

### 11.5 `cms_operations.dart` (346 linhas)

Provê assinatura e envelope CMS/PKCS#7 com suporte a CAdES-BES:

- **`cmsSign()`**: `BIO_new_mem_buf(data)` / `BIO_new_file(path)` →
  `CMS_sign(cert, pkey, null, dataBio, CMS_DETACHED|CMS_STREAM)` →
  `i2d_CMS_bio` → DER bytes
- **`cmsVerify()`**: `d2i_CMS_bio` → `CMS_verify(cms, certs, store, dataBio, null, flags)`
- **`cmsEncrypt()`**: `BIO_new_mem_buf(data)` →
  `CMS_encrypt(certs, dataBio, cipher, flags)` → DER bytes
- **`cmsDecrypt()`**: `d2i_CMS_bio` → `CMS_decrypt(cms, pkey, cert, null, outBio, flags)`
- **`cmsSignCades()`**: Extensão CAdES-BES, adiciona atributos assinados
  (`signing-time`, `message-digest`, `certificate` opcional, cadeia de
  certificados) via `CMS_signed_add1_attr_by_txt` e `CMS_add0_cert`.

## 12. Camada Core: Modelos

### 12.1 `CryptoError` (sealed class, 13 subtipos)

```
CryptoError (sealed)
├── KeygenError           falha na geração de chave (keyType, reason, openSslError)
├── CertificateError      falha na criação de certificado (reason, openSslError)
├── FileSigningError      falha na assinatura de arquivo (filePath, reason, openSslError)
├── ValidationError       erro de validação de input (field, reason)
├── ChainValidationError  falha na validação de cadeia (chainDetail, errorDepth, openSslError)
├── CrlError              erro em operação CRL (reason, openSslError)
├── X509ExtensionError    erro ao parsear extensão X.509 (oid, reason, openSslError)
├── OcspError             erro em operação OCSP (reason, openSslError)
├── Asn1Error             erro de parsing ASN.1 (reason, openSslError)
├── AesGcmAuthFailure     falha de autenticação GCM (reason, openSslError)
├── CsrError              erro na geração de CSR (reason, openSslError)
└── TimestampError        erro em operação de timestamp (reason, openSslError)
```

### 12.2 `CryptoResult<T>` (sealed class: Result Monad)

```dart
sealed class CryptoResult<T> {}

class CryptoSuccess<T> extends CryptoResult<T> {
  final T value;
}

class CryptoFailure<T> extends CryptoResult<T> {
  final CryptoError error;
}
```

Usado em 9 operações (CRL, OCSP, CSR, Timestamp, ASN.1) que podem falhar por
razões esperadas (não excepcionais). A API de hash/AES/RSA usa exceções; a API
de parsing/validação usa `CryptoResult`.

### 12.3 `KeySpec` (sealed class, 4 subtipos)

```
KeySpec (sealed)
├── RsaKeySpec(bits: int)             1024..16384, múltiplo de 1024
├── EcKeySpec(curveName: String)      "prime256v1", "secp384r1", "secp521r1"
├── MlKemKeySpec(securityLevel: int)  512, 768, 1024
└── MlDsaKeySpec(securityLevel: int)  44, 65, 87
```

## 13. Camada de Métricas Independente

Os 12 arquivos em `metrics/` (~4200 linhas) operam exclusivamente sobre a API pública. Cada métrica é obtida invocando os 43 métodos expostos por `PluginCryptoAPI` e medindo latência, vazão, bits de segurança e características de implementação. Nenhum acesso direto a FFI ou estruturas internas.

| Arquivo | Função | Métricas Coletadas |
|---------|--------|-------------------|
| `metrics_collector.dart` | Orquestrador | Coordena a coleta e gera relatório JSON (schema v1.2.0) |
| `timing.dart` | Latência | Média, mediana, desvio padrão, CV, p99 para cada operação |
| `throughput.dart` | Vazão | bytes/segundo por algoritmo e tamanho de entrada |
| `security_benchmark.dart` | Benchmark | Operações/segundo para RSA (2048/4096), EC (P-256/P-384), ML-KEM, ML-DSA |
| `security_metrics.dart` | Segurança | Bits de segurança clássica e pós-quântica (NIST categories 1-5) |
| `safe_curves.dart` | Curvas Seguras | Validação SafeCurves (rigidez, twisted security, etc.) |
| `constant_time.dart` | Side-channel | Análise estatística de tempo de execução constante |
| `concurrency.dart` | Concorrência | Throughput com N Isolates paralelos |
| `memory_tracker.dart` | Memória | RSS via `ProcessInfo.currentRss` |
| `coverage_parser.dart` | Cobertura | Parsing de `lcov.info` |
| `zeroization.dart` | Zeroização | Verificação de que buffers são zerados após uso |

---

## 14. Padrões de Projeto

| Padrão | Onde | Detalhe |
|--------|------|---------|
| **Singleton Lazy** | `PluginCryptoAPI.instance` (`crypto_api.dart:62-65`) | `_instance ??= PluginCryptoAPI._()`  thread-safe no Dart (single-threaded por Isolate), inicialização sob demanda |
| **Factory Method** | `KeyCreatorFactory` (`key_creator_factory.dart`) | Seleciona `KeyCreator` por `KeySpec.runtimeType`: `RsaKeyCreator`, `EcKeyCreator`, `MlKemKeyCreator`, `MlDsaKeyCreator` |
| **Builder (Fluent API)** | `CertificateBuilder` (`certificate_builder.dart`, 543 linhas) | Encadeamento de métodos para configurar certificado X.509: `.subject(...)` → `.issuer(...)` → `.addExtension(...)` → `.build(keySpec)` |
| **Strategy** | `KeyCreator`, `ChainVerifier`, `FileSigner` | Interfaces com múltiplas implementações intercambiáveis via injeção de dependência |
| **Result Monad** | `CryptoResult<T>` (`crypto_result.dart`) | `CryptoSuccess(value)` ou `CryptoFailure(error)`  sem exceções para falhas esperadas (9 operações) |
| **Sealed Class Hierarchy** | `CryptoError` (13 subtipos), `KeySpec` (4 subtipos) | Pattern matching exaustivo no `switch`  compilador obriga tratar todos os casos |
| **RAII via try/finally** | Todos os arquivos em `crypto/` e `flows/` | Gerenciamento determinístico de recursos nativos  alocação e liberação no mesmo escopo léxico |

## 15. Utilitários (`utils/`, 9 arquivos, 599 linhas)

| Arquivo | Linhas | Propósito |
|---------|--------|-----------|
| `openssl_error.dart` | 29 | `ERR_get_error()` → `ERR_error_string_n()` → `String` formatada; aloca buffer temporário de 256 bytes via `calloc<Uint8>(256)` |
| `bio_utils.dart` | 42 | Wrappers para `BIO_new_mem_buf(data, len)` e `BIO_read(bio, buf, len)` com `try/finally` |
| `x509_loader.dart` | 48 | Carrega X.509 de PEM ou DER com fallback automático: `PEM_read_bio_X509` → se falhar → `d2i_X509_bio` |
| `x509_ext_parser.dart` | 128 | Parseia extensões X.509 v3: SubjectAlternativeName (SAN), BasicConstraints, KeyUsage, ExtendedKeyUsage, CRL Distribution Points, AuthorityKeyIdentifier |
| `x509_name_builder.dart` | 93 | Converte `DistinguishedName` (modelo Dart) → `X509_NAME*` (OpenSSL) com `X509_NAME_add_entry_by_txt` para cada campo (CN, O, OU, C, ST, L) |
| `certificate_serializer.dart` | 42 | Serializa X.509 para DER (`i2d_X509`) e PEM (`PEM_write_bio_X509`) |
| `key_pair_serializer.dart` | 228 | Extrai `EVP_PKEY` para `KeyPair` (PEM público + PEM privado); elimina 228 linhas duplicadas que existiam em RsaKeyCreator e EcKeyCreator |
| `asn1_time.dart` | 41 | Converte `ASN1_TIME` (estrutura C) para `DateTime` (Dart) e vice-versa |
| `hex_utils.dart` | 18 | Conversão `Uint8List` ↔ hex `String` (uppercase, sem separadores) |

---

## 16. Estatísticas do Código-Fonte

| Camada | Arquivos | Linhas (aprox.) | Domínio |
|--------|----------|-----------------|---------|
| FFI Layer | 2 | 1.971 | `openssl_bindings.dart` (1895) + `native_loader.dart` (76) |
| Core Operations | 9 | 1.465 | AES (394), Asymmetric (444), X.509 (171), CMS (346), CRL (27), OCSP (26), CSR (18), Timestamp (35), Crypto (78) |
| Flows | 24 | 4.426 | KeyCreation, CertificateCreation, CertificateChain, FileSigning, CSR, Revocation, Timestamp, ASN.1 |
| Models | 11 | 953 | Tipos de dados puros Dart  zero FFI |
| Metrics | 12 | 4.207 | Coleta independente de métricas |
| Utils | 9 | 599 | Serializadores, parsers, builders |
| Platform | 3 | 216 | CMakeLists.txt (99), build.gradle.kts (79), PluginCryptoPlugin.kt (38) |
| **Total** | **70** | **~13.837** | |

---

## 17. Resumo de Segurança

| Aspecto | Decisão |
|---------|---------|
| **Zeroização de memória** | `calloc` (zero-fill) para todos os buffers nativos; `OPENSSL_clear_free` nos contextos OpenSSL (versão do `EVP_*_free` que sobrescreve com zeros antes de liberar) |
| **Tempo constante** | AES-GCM usa implementação constante-time por padrão no OpenSSL 4.0.0 (sem branches dependentes de dados); GHASH via PCLMULQDQ também é constante-time |
| **Thread safety** | Operações síncronas, estruturas de contexto não compartilhadas entre invocações, fila de erro thread-local (TLS) |
| **Gerenciamento de recursos** | Padrão `try/finally` aninhado garante liberação mesmo em caminhos de exceção; zero vazamentos em operação normal e excepcional |
| **Fila de erro** | `ERR_clear_error()` após toda falha; evita contaminação entre operações consecutivas |
| **Providers** | FIPS 140-3 com self-tests (KAT) no carregamento; algoritmos depreciados isolados em `legacy.so`; pós-quântico isolado em `oqsprovider.so` (carregamento condicional) |
| **Validação de entrada** | Todas as fronteiras da Public API validam tamanhos de chave, IV, tag antes de delegar para a camada FFI |
