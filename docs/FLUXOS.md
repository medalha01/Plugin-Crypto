# Fluxos de Trabalho: PluginCrypto

> Documentação de altíssimo detalhamento de todos os 7 workflows da biblioteca PluginCrypto.
> Cada fluxo é dissecado com o código Dart real da implementação, a cadeia completa de
> funções C do OpenSSL invocadas via FFI, todo bloco `try`/`finally`, todos os ramos de
> erro com os tipos concretos (`ValidationError`, `KeygenError`, `CertificateError`, etc.),
> e os edge cases críticos (digest mismatch com ML-DSA, curva EC não suportada, parâmetros
> RSA inválidos, CRL com assinatura corrompida, OCSP com status desconhecido, etc.).
>
> **Arquivos de implementação de referência:**
>
> | Fluxo | Arquivo Principal |
> |---|---|
> | 1. Criação de Chaves | `lib/src/crypto/flows/key_creation/{rsa,ec,ml_kem,ml_dsa}_key_creator.dart` |
> | 2. Certificado Auto-Assinado | `lib/src/crypto/flows/certificate_creation/certificate_builder.dart` |
> | 3. Assinatura de Arquivos | `lib/src/crypto/flows/file_signing/streaming_file_signer.dart` |
> | 4. Verificação de Cadeia | `lib/src/crypto/flows/certificate_chain/openssl_chain_verifier.dart` |
> | 5. Geração de CSR | `lib/src/crypto/flows/csr/openssl_csr_generator.dart` |
> | 6. Revogação (CRL + OCSP) | `lib/src/crypto/flows/revocation/{crl_verifier,ocsp_verifier}.dart` |
> | Todos (FFI) | `lib/src/ffi/openssl_bindings.dart` (2015 linhas de bindings manuais) |

---

## Índice

1. [Fundação: Arquitetura FFI e Modelo de Erro](#1-fundacao-arquitetura-ffi-e-modelo-de-erro)
1. [Fundação: Arquitetura FFI e Modelo de Erro](#1-fundacao-arquitetura-ffi-e-modelo-de-erro)
2. [Fluxo 1: Criação de Chaves Assimétricas](#2-fluxo-1-criacao-de-chaves-assimetricas)
3. [Fluxo 2: Criação de Certificado Auto-Assinado X.509 v3](#3-fluxo-2-criacao-de-certificado-auto-assinado-x509-v3)
4. [Fluxo 3: Assinatura de Arquivos com Streaming](#4-fluxo-3-assinatura-de-arquivos-com-streaming)
5. [Fluxo 4: Verificação de Cadeia de Certificados](#5-fluxo-4-verificacao-de-cadeia-de-certificados)
6. [Fluxo 5: Geração de CSR (PKCS#10)](#6-fluxo-5-geracao-de-csr-pkcs10)
7. [Fluxo 6: Verificação de Revogação: CRL + OCSP](#7-fluxo-6-verificacao-de-revogacao--crl--ocsp)
8. [Fluxo 7: Padrão Universal de Tratamento de Erro e Liberação de Recursos](#8-fluxo-7-padrao-universal-de-tratamento-de-erro-e-liberacao-de-recursos)

---

## 1. Fundação: Arquitetura FFI e Modelo de Erro

### 1.1 O Contrato `CryptoResult<T>`

TODOS os fluxos retornam o tipo selado `CryptoResult<T>`, definido em
`lib/src/crypto/models/crypto_result.dart:19-35`. O compilador Dart força
pattern matching exaustivo. Não é possível ignorar o caso de erro:

```dart
// lib/src/crypto/models/crypto_result.dart:19-35
sealed class CryptoResult<T> {
  const CryptoResult._();
}

class CryptoSuccess<T> extends CryptoResult<T> {
  final T value;
  const CryptoSuccess(this.value) : super._();
}

class CryptoFailure<T> extends CryptoResult<T> {
  final CryptoError error;
  const CryptoFailure(this.error) : super._();
}
```

### 1.2 Hierarquia Selada de Erros

Todos os tipos de erro herdam de `CryptoError` (`lib/src/crypto/models/crypto_error.dart:10-15`).
A hierarquia completa é: `CryptoError (sealed) → KeygenError | CertificateError | FileSigningError | ValidationError | ChainValidationError | CrlError | OcspError | CsrError | X509ExtensionError | Asn1Error | AesGcmAuthFailure | TimestampError`.

Cada erro carrega campos estruturados (ex: `KeygenError.keyType`, `openSslError`) para diagnóstico
programático, não apenas exibição.

### 1.3 Loader da Biblioteca Nativa

As bindings são carregadas via `DynamicLibrary` e expostas através da classe `OpenSslBindings`
(`lib/src/ffi/openssl_bindings.dart:1277-1286`):

```dart
// lib/src/ffi/openssl_bindings.dart:1277-1286
class OpenSslBindings {
  final DynamicLibrary _crypto;
  final DynamicLibrary _ssl;

  OpenSslBindings._(this._crypto, this._ssl);

  factory OpenSslBindings.create(DynamicLibrary crypto, DynamicLibrary ssl) {
    return OpenSslBindings._(crypto, ssl);
  }
```

Cada função C é resolvida via `DynamicLibrary.lookup<NativeFunction>` e exposta como `late final`
campo de função Dart com a assinatura convertida. Exemplo:

```dart
// lib/src/ffi/openssl_bindings.dart:1423-1428
late final EVP_PKEY_keygen_initDart evpPkeyKeygenInit = _crypto
    .lookup<EVP_PKEY_keygen_initNative>('EVP_PKEY_keygen_init')
    .asFunction<EVP_PKEY_keygen_initDart>();
```

### 1.4 Tipos Opaques FFI

Todos os tipos nativos são declarados como `Pointer<Void>` alias (`lib/src/ffi/openssl_bindings.dart:26-67`),
garantindo type safety em tempo de compilação:

```dart
typedef EVP_PKEY = Pointer<Void>;
typedef EVP_PKEY_CTX = Pointer<Void>;
typedef X509 = Pointer<Void>;
typedef X509_STORE = Pointer<Void>;
typedef BIO = Pointer<Void>;
// ... mais 60+ tipos opacos
```

### 1.5 Injeção de Dependência (DIP)

Todos os fluxos recebem `OpenSslBindings` ou `CryptoContext` via construtor, nunca acessam
`PluginCryptoAPI.instance` internamente. Isso permite testes unitários com bindings mockadas.

```dart
// Exemplo: RsaKeyCreator (lib/src/crypto/flows/key_creation/rsa_key_creator.dart:28-32)
class RsaKeyCreator implements KeyCreator {
  final OpenSslBindings _b;
  const RsaKeyCreator(this._b);
```

### 1.6 Gerenciamento de recursos nativos

TODOS os fluxos compartilham o mesmo padrao de liberacao de recursos alocados via FFI.
A explicacao aqui e unica e vale para todos os fluxos. Cada fluxo apenas referencia este padrao.

**Recursos nativos e suas funcoes de liberacao:**

| Alocacao | Liberacao | Onde ocorre |
|----------|-----------|-------------|
| `calloc<Uint8>(n)` / `calloc<EVP_PKEY>()` | `calloc.free(ptr)` | Buffers temporarios, ponteiros out-param |
| `EVP_PKEY_CTX_new_id()` | `EVP_PKEY_CTX_free(ctx)` | Keygen (RSA/EC/ML-KEM/ML-DSA) |
| `EVP_PKEY*` (de `PEM_read_bio_PrivateKey`) | `EVP_PKEY_free(pkey)` | Keygen, Sign, CSR, CMS |
| `EVP_MD_CTX_new()` | `EVP_MD_CTX_free(ctx)` | Digest, Sign/Verify, File Signing |
| `X509_new()` | `X509_free(x509)` | Certificate Builder |
| `X509_STORE_new()` | `X509_STORE_free(store)` | Chain Verification, OCSP |
| `X509_STORE_CTX_new()` | `X509_STORE_CTX_free(ctx)` | Chain Verification |
| `X509_CRL*` (de `PEM_read_bio_X509_CRL`) | `X509_CRL_free(crl)` | CRL Verification |
| `BIO_new()` / `BIO_new_file()` | `BIO_free(bio)` | I/O de arquivos, buffers PEM/DER |
| `OPENSSL_sk_new_null()` | `OPENSSL_sk_free(stack)` | Stack de certificados intermediarios |
| `OCSP_REQUEST_new()` | `OCSP_REQUEST_free(req)` | OCSP Request |
| `OCSP_RESPONSE*` (de `d2i_OCSP_RESPONSE`) | `OCSP_RESPONSE_free(resp)` | OCSP Response |

**Padrao LIFO (Last In, First Out):**

Toda alocacao de recurso nativo e envolvida por `try/finally` aninhado:

```dart
// Pseudo-codigo do padrao  presente em todos os fluxos
final a = allocateA();           // recurso 1
try {
  final b = allocateB();         // recurso 2, depende de A
  try {
    final c = allocateC();       // recurso 3, depende de B
    try {
      use(a, b, c);              // operacao principal
      return resultado;
    } finally { freeC(c); }      // ultimo alocado, primeiro liberado
  } finally { freeB(b); }
} finally { freeA(a); }          // primeiro alocado, ultimo liberado
```

A ordem LIFO e critica: o recurso mais interno (ultimo alocado) deve ser liberado primeiro,
pois recursos externos podem ser necessarios durante a liberacao dos internos.

**Limpeza da fila de erro OpenSSL:**

Em todo bloco `finally` que libera recursos de nivel superior, invoca-se `ERR_clear_error()`.
Isso e **critico no Android**, onde provedores de seguranca podem deixar erros benignos na
fila da thread, poluindo diagnosticos futuros.

```dart
try {
  // ... operacao ...
} finally {
  _b.errClearError();   // ERR_clear_error()
  _b.x509Free(cert);
}
```

**Helper `_fail<T>()`:**

Antes de retornar `CryptoFailure`, todos os fluxos chamam `_fail<T>(error)`, que internamente
invoca `ERR_clear_error()` e entao cria o `CryptoFailure`. NUNCA se retorna `CryptoFailure`
sem antes limpar a fila de erro.

```dart
CryptoFailure<T> _fail<T>(CryptoError error) {
  _ctx.bindings.errClearError();
  return CryptoFailure<T>(error);
}
```

---

## 2. Fluxo 1: Criação de Chaves Assimétricas

### 2.1 Factory Pattern: `KeyCreatorFactory`

O despacho é feito por `runtimeType` do `KeySpec`. Quatro creators são registrados:
`RsaKeyCreator`, `EcKeyCreator`, `MlKemKeyCreator`, `MlDsaKeyCreator`.

```dart
// Padrão de uso
final factory = KeyCreatorFactory(bindings);  // registra os 4 creators
final creator = factory.createOrThrow(RsaKeySpec(2048));
final result = await creator.create(spec);
```

### 2.2 Especificação de Chaves (`KeySpec`)

Hierarquia selada em `lib/src/crypto/models/key_types.dart:13-132`:

```dart
sealed class KeySpec { const KeySpec._(); }

// RSA: bits ∈ {1024, 2048, 3072, ..., 16384}, múltiplo de 1024
class RsaKeySpec extends KeySpec { final int bits; ... }

// EC: curvas NIST nomeadas (prime256v1, secp384r1, secp521r1)
class EcKeySpec extends KeySpec { final String curve; ... }

// ML-KEM (FIPS 203): enum MlKemParameterSet { mlKem512, mlKem768, mlKem1024 }
//   NIDs: 1454, 1455, 1456
class MlKemKeySpec extends KeySpec { final MlKemParameterSet parameterSet; ... }

// ML-DSA (FIPS 204): enum MlDsaParameterSet { mlDsa44, mlDsa65, mlDsa87 }
//   NIDs: 1457, 1458, 1459
class MlDsaKeySpec extends KeySpec { final MlDsaParameterSet parameterSet; ... }
```

### 2.3 RSA Key Creator: Código Real Completo

Arquivo: `lib/src/crypto/flows/key_creation/rsa_key_creator.dart:28-127`

```dart
@override
CryptoResult<KeyPair> create(KeySpec spec) {
  if (spec is! RsaKeySpec) {
    return CryptoFailure(ValidationError(
      field: 'KeySpec',
      reason: 'RsaKeyCreator only accepts RsaKeySpec, got ${spec.runtimeType}',
    ));
  }

  final bits = spec.bits;
  if (bits < 1024 || bits > 16384 || bits % 1024 != 0) {
    return CryptoFailure(ValidationError(
      field: 'RsaKeySpec.bits',
      reason: 'bits must be >= 1024, <= 16384, and a multiple of 1024, got $bits',
    ));
  }

  final ctx = _b.evpPkeyCtxNewId(nidRsa, nullptr); // nidRsa = 6
  if (ctx == nullptr) {
    return _fail<KeyPair>(KeygenError(
      keyType: 'RSA', reason: 'EVP_PKEY_CTX_new_id returned null'));
  }

  try { // (segue o padrão descrito em Gerenciamento de recursos nativos)
    if (_b.evpPkeyKeygenInit(ctx) != 1) {
      return _fail<KeyPair>(KeygenError(keyType: 'RSA',
          reason: 'EVP_PKEY_keygen_init', openSslError: getOpenSslError(_b)));
    }
    if (_b.evpPkeyCtxSetRsaKeygenBits(ctx, bits) != 1) {
      return _fail<KeyPair>(KeygenError(keyType: 'RSA',
          reason: 'EVP_PKEY_CTX_set_rsa_keygen_bits($bits)',
          openSslError: getOpenSslError(_b)));
    }
    final ppkey = calloc<EVP_PKEY>();
    try {
      if (_b.evpPkeyKeygen(ctx, ppkey) != 1) {
        return _fail<KeyPair>(KeygenError(keyType: 'RSA',
            reason: 'EVP_PKEY_keygen', openSslError: getOpenSslError(_b)));
      }
      return KeyPairSerializer(_b).extract(ppkey.value, 'RSA');
    } finally { calloc.free(ppkey); }
  } finally { _b.evpPkeyCtxFree(ctx); }
}
```

#### Cadeia de Funções C: RSA Keygen

```
EVP_PKEY_CTX_new_id(6, NULL)
  └─ ossl_rsa_keymgmt_new() → EVP_PKEY_CTX
EVP_PKEY_keygen_init(ctx)
  └─ evp_keymgmt_gen_init()
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)
  └─ EVP_PKEY_CTX_ctrl(..., EVP_PKEY_CTRL_RSA_KEYGEN_BITS, 2048, ...)
EVP_PKEY_keygen(ctx, &ppkey)
  └─ rsa_keygen() → BN_generate_prime_ex() × 2 → calcula n,d,e
PEM_write_bio_PUBKEY(bio, pkey)
  └─ PEM_ASN1_write_bio(i2d_PUBKEY, ...)
PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)
  └─ PEM_ASN1_write_bio(i2d_PrivateKey, ...)
```

```
DIAGRAMA DE PILHA  RSA Keygen:
┌─────────────────────────────────────────────────┐
│  Dart: RsaKeyCreator.create(RsaKeySpec(2048))   │
│  ├─ _b.evpPkeyCtxNewId(6, nullptr)  ← FFI call │
│  ├─ _b.evpPkeyKeygenInit(ctx)                   │
│  ├─ _b.evpPkeyCtxSetRsaKeygenBits(ctx, 2048)    │
│  ├─ _b.evpPkeyKeygen(ctx, ppkey)                │
│  └─ KeyPairSerializer.extract(pkey, 'RSA')      │
├─────────────────────────────────────────────────┤
│  FFI Boundary (dart:ffi / Pointer<Void>)        │
├─────────────────────────────────────────────────┤
│  libcrypto.so                                    │
│  ├─ EVP_PKEY_CTX_new_id(6, NULL)                │
│  │   └─ int_rsa_new() → EVP_PKEY                │
│  ├─ EVP_PKEY_keygen_init(ctx)                   │
│  │   └─ evp_keymgmt_gen_init()                  │
│  ├─ EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) │
│  │   └─ EVP_PKEY_CTX_ctrl(..., BITS, 2048)      │
│  ├─ EVP_PKEY_keygen(ctx, &ppkey)                │
│  │   └─ rsa_keygen() → BN_generate_prime_ex()   │
│  ├─ PEM_write_bio_PUBKEY(bio, pkey)             │
│  │   └─ PEM_ASN1_write_bio(i2d_PUBKEY, ...)     │
│  ├─ PEM_write_bio_PrivateKey(bio, pkey, ...)    │
│  │   └─ PEM_ASN1_write_bio(i2d_PrivateKey, ...)  │
│  └─ EVP_PKEY_CTX_free(ctx)                       │
│       └─ EVP_PKEY_CTX cleanup + CRYPTO_free()   │
└─────────────────────────────────────────────────┘
```

**Edge cases RSA:**
- `bits = 0`: `RsaKeySpec(0)` → `ArgumentError` no construtor (fail-fast)
- `bits = 1025` (não múltiplo de 1024): `ValidationError` no guard do `create()`
- `bits = 20000` (>16384): `ValidationError`
- `EVP_PKEY_CTX_new_id(6, NULL) == nullptr`: impossível com constante 6, mas tratado
  defensivamente → `KeygenError`
- `EVP_PKEY_keygen` falha por falta de entropia: `KeygenError(reason: 'EVP_PKEY_keygen')`
- `PEM_write_bio_PrivateKey` falha no `KeyPairSerializer`: `KeygenError(keyType: 'RSA', reason: 'Failed to write private key')`

### 2.4 EC Key Creator: Código Real

Arquivo: `lib/src/crypto/flows/key_creation/ec_key_creator.dart:42-136`

```dart
final curveUtf8 = curve.toNativeUtf8();
final nid = _b.objSn2nid(curveUtf8.cast());
calloc.free(curveUtf8);

if (nid == 0) {
  return _fail<KeyPair>(KeygenError(keyType: 'EC',
      reason: 'OBJ_sn2nid("$curve") returned 0',
      openSslError: getOpenSslError(_b)));
}

final ctx = _b.evpPkeyCtxNewId(nidEc, nullptr); // nidEc = 408
// ... init → set_ec_paramgen_curve_nid(ctx, nid) → keygen(ctx, ppkey)
```

**Edge cases EC:**
- Curva não suportada: `ValidationError(field: 'EcKeySpec.curve', reason: 'Unsupported curve...')`
- `OBJ_sn2nid` retorna 0 (curva não reconhecida pelo OpenSSL): `KeygenError(keyType: 'EC', ...)`

### 2.5 ML-KEM / ML-DSA: Código Real

Arquivo: `lib/src/crypto/flows/key_creation/ml_kem_key_creator.dart:43-107` e
`lib/src/crypto/flows/key_creation/ml_dsa_key_creator.dart:43-107`

```dart
final nid = switch (spec.parameterSet) {
  MlKemParameterSet.mlKem512  => nidMlKem512,   // 1454
  MlKemParameterSet.mlKem768  => nidMlKem768,   // 1455
  MlKemParameterSet.mlKem1024 => nidMlKem1024,  // 1456
};

final ctx = _b.evpPkeyCtxNewId(nid, nullptr);
// ... init → keygen(ctx, ppkey)  SEM chamada set_* adicional!
// O NID já embute todo o parameter set.
```

**Nota crítica:** Diferentemente de RSA e EC, o ML-KEM e ML-DSA **não requerem** chamada de
configuração adicional (`EVP_PKEY_CTX_set_*`). O NID passado para `EVP_PKEY_CTX_new_id`
já embute o parameter set completo (FIPS 203 / FIPS 204).

**Edge cases ML-KEM/ML-DSA (unsupported):**
- OpenSSL compilado sem suporte pós-quântico (versão < 3.4 ou sem `enable-ml_kem`/`enable-ml_dsa`):
  `EVP_PKEY_CTX_new_id` retorna `nullptr` → `KeygenError(keyType: 'ML-KEM'|'ML-DSA', reason: 'EVP_PKEY_CTX_new_id returned null (NID ...)')`

### 2.6 KeyPairSerializer: Código Real

Arquivo: `lib/src/crypto/utils/key_pair_serializer.dart:24-71`

```dart
CryptoResult<KeyPair> extract(EVP_PKEY pkey, String keyType) {
  final pubBio = _b.bioNew(_b.bioSMem());
  if (pubBio == nullptr) {
    _b.evpPkeyFree(pkey);
    return _error(keyType, 'Failed to create public key BIO');
  }
  // ... PEM_write_bio_PUBKEY → bioToString
  // ... PEM_write_bio_PrivateKey → bioToString
  _b.evpPkeyFree(pkey); // consome o EVP_PKEY após ambas extrações
  return CryptoSuccess(KeyPair(publicKeyPem: ..., privateKeyPem: ...));
}
```

### 2.7 Tabela Resumo: Criação de Chaves

| Algoritmo | NID | Parâmetros | Config Extra | Função C |
|---|---|---|---|---|
| RSA | 6 | 1024–16384 (mult. 1024) | `set_rsa_keygen_bits` | `rsa_keygen()` |
| EC | 408 | prime256v1, secp384r1, secp521r1 | `set_ec_paramgen_curve_nid` | `ec_keygen()` |
| ML-KEM | 1454/1455/1456 | mlKem512/768/1024 | *nenhuma* | `ml_kem_keygen()` |
| ML-DSA | 1457/1458/1459 | mlDsa44/65/87 | *nenhuma* | `ml_dsa_keygen()` |

---

## 3. Fluxo 2: Criação de Certificado Auto-Assinado X.509 v3

### 3.1 Builder Pattern: Código Real

Arquivo: `lib/src/crypto/flows/certificate_creation/certificate_builder.dart:185-303`

```dart
CryptoResult<Uint8List> build() {
  final validationError = _validate();
  if (validationError != null) return CryptoFailure(validationError);
  return _buildDer();
}

CryptoResult<Uint8List> _buildDer() {
  final cert = _b.x509New();
  if (cert == nullptr) {
    return _fail<Uint8List>(CertificateError(reason: 'X509_new returned null'));
  }
  try {  // (segue o padrão descrito em Gerenciamento de recursos nativos)
    // 1. X509_set_version(cert, 2)      → X.509 v3 (0-indexed)
    // 2. PEM_read_bio_PUBKEY → X509_set_pubkey(cert, pubkey)
    // 3. X509NameBuilder → X509_set_subject_name / _issuer_name
    // 4. ASN1_TIME_set → X509_set1_notBefore / _notAfter
    // 5. Para cada extensão: OBJ_txt2nid → X509V3_EXT_conf_nid → X509_add_ext
    // 6. _signCert: PEM_read_bio_PrivateKey → X509_sign
    // 7. i2d_X509_bio → BIO_read → Uint8List
    return _serializeCertToDer(cert);
  } finally {
    _b.errClearError();  // crítico no Android  limpa erros benignos do provider
    _b.x509Free(cert);
  }
}
```

### 3.2 Assinatura: ML-DSA vs Outros (Digest Mismatch)

Arquivo: `lib/src/crypto/flows/certificate_creation/certificate_builder.dart:430-461`

```dart
CryptoResult<Uint8List>? _signCert(X509 cert, KeyPair issuerKey) {
  final issuerPkey = _loadPrivateKey(issuerKey.privateKeyPem);
  if (issuerPkey == nullptr) {
    return _fail<Uint8List>(CertificateError(
      reason: 'Failed to load issuer private key',
      openSslError: getOpenSslError(_b)));
  }
  try {
    // ══ ML-DSA → nullptr digest (hash interno SHAKE-256) ══════
    // ══ Outros  → EVP_sha256()                          ══════
    final md = _signingAlgorithm.keyType == SigningKeyType.ml_dsa
        ? nullptr
        : _signingAlgorithm.hash.evpMd(_b);

    final signResult = _b.x509Sign(cert, issuerPkey, md);
    if (signResult <= 0) {
      return _fail<Uint8List>(CertificateError(
        reason: 'X509_sign', openSslError: getOpenSslError(_b)));
    }
  } finally { _b.evpPkeyFree(issuerPkey); }
  return null;
}
```

**Edge case: Digest mismatch com ML-DSA:** Se o chamador passar `EVP_sha256()` como
digest para uma chave ML-DSA, o OpenSSL rejeitará com erro `"no digest"` ou `"signature failed"`.
O `CertificateBuilder` previne isso checando `_signingAlgorithm.keyType == SigningKeyType.ml_dsa`
e passando `nullptr`. Se o chamador burlar via `addExtension`, o erro é capturado como
`CertificateError(reason: 'X509_sign', openSslError: ...)`.

### 3.3 Validação de Campos Obrigatórios

```dart
// certificate_builder.dart:207-256
CryptoError? _validate() {
  if (_subjectDn == null) return ValidationError(
    field: 'subjectDn', reason: 'must call subjectDn() before build()');
  if (_issuerDn == null) return ValidationError(...);
  if (_publicKey == null) return ValidationError(...);
  if (_issuerKey == null) return ValidationError(...);
  if (_notBefore == null) return ValidationError(...);
  if (_notAfter == null) return ValidationError(...);
  // Edge case: notBefore >= notAfter
  if (_notBefore!.isAfter(_notAfter!) || _notBefore!.isAtSameMomentAs(_notAfter!)) {
    return ValidationError(field: 'validity',
      reason: 'notBefore must be strictly before notAfter');
  }
  return null;
}
```

### 3.4 Cadeia de Funções C: Certificate Builder

```
X509_new()
X509_set_version(cert, 2)        // v3 (0-indexed)
BIO_new_mem_buf → PEM_read_bio_PUBKEY → X509_set_pubkey → EVP_PKEY_free
X509_NAME_new → _add_entry_by_txt × N entries (CN, O, OU, L, ST, C)
X509_set_subject_name / X509_set_issuer_name → X509_NAME_free
ASN1_TIME_set(NULL, epoch) → X509_set1_notBefore
ASN1_TIME_set(NULL, epoch) → X509_set1_notAfter
(loop extensões): OBJ_txt2nid → X509V3_EXT_conf_nid → X509_add_ext → X509_EXTENSION_free
PEM_read_bio_PrivateKey → X509_sign(cert, pkey, md) → EVP_PKEY_free
BIO_new(BIO_s_mem) → i2d_X509_bio → BIO_read(loop)
```

```
DIAGRAMA DE PILHA  Certificate Builder:
┌───────────────────────────────────────────────────┐
│  Dart: CertificateBuilder.build()                 │
│  ├─ _validate() → 6 campos + validação temporal   │
│  ├─ _buildDer()                                   │
│  │   ├─ _b.x509New()                              │
│  │   ├─ _setCertVersion(cert)                     │
│  │   ├─ _setCertPublicKey(cert, keyPair)          │
│  │   ├─ _setCertNames(cert, subject, issuer)      │
│  │   ├─ _setCertValidity(cert, nb, na)            │
│  │   ├─ _addExtensions(cert) [loop]               │
│  │   ├─ _signCert(cert, issuerKey)  ← ML-DSA check│
│  │   └─ _serializeCertToDer(cert)                 │
│  └─ finally: errClearError(), x509Free(cert)      │
├───────────────────────────────────────────────────┤
│  FFI Boundary                                     │
├───────────────────────────────────────────────────┤
│  libcrypto.so                                      │
│  ├─ X509_new() → aloca X509 v3                    │
│  ├─ X509_set_version(x, 2)                        │
│  ├─ PEM_read_bio_PUBKEY() → X509_set_pubkey()     │
│  ├─ X509_NAME_add_entry_by_txt() × N              │
│  ├─ X509_set_subject_name() / _issuer_name()      │
│  ├─ ASN1_TIME_set() → X509_set1_notBefore/After() │
│  ├─ OBJ_txt2nid() → X509V3_EXT_conf_nid()         │
│  │   → X509_add_ext()                             │
│  ├─ PEM_read_bio_PrivateKey() → X509_sign()       │
│  ├─ i2d_X509_bio() → BIO_read()                   │
│  └─ ERR_clear_error() + X509_free()               │
└───────────────────────────────────────────────────┘
```

---

## 4. Fluxo 3: Assinatura de Arquivos com Streaming

### 4.1 Código Real

(segue o padrão descrito em Gerenciamento de recursos nativos)

Arquivo: `lib/src/crypto/flows/file_signing/streaming_file_signer.dart:50-248`

```dart
CryptoResult<Uint8List> sign(FileSigningRequest request) {
  // Guard: verifica existência → FileSystemException → FileSigningError
  // Guard: valida PEM (BEGIN/END markers) → FileSigningError
  // Guard: HashAlgorithm.fromName → FileSigningError se não suportado

  final fileBio = _b.bioNewFile(fileUtf8.cast(), modeUtf8.cast());
  if (fileBio == nullptr) { return CryptoFailure(FileSigningError(...)); }

  try { // (segue o padrão descrito em Gerenciamento de recursos nativos)
    final pkey = _loadPrivateKey(request.privateKeyPem);
    if (pkey == nullptr) { return CryptoFailure(FileSigningError(...)); }

    try {
      final ctx = _b.evpMdCtxNew();
      if (ctx == nullptr) { return CryptoFailure(FileSigningError(...)); }

      try {
        // ══ INIT COM FALLBACK ML-DSA ═══════════════════════════════
        var initResult = _b.evpDigestSignInit(ctx,nullptr,mdPtr,nullptr,pkey);
        if (initResult != 1) {
          _b.errClearError();
          initResult = _b.evpDigestSignInit(ctx,nullptr,nullptr,nullptr,pkey);
        }
        if (initResult != 1) { return CryptoFailure(FileSigningError(...)); }

        // ══ STREAMING LOOP ═════════════════════════════════════════
        final chunk = calloc<Uint8>(request.chunkSize);
        try {
          while (true) {
            final n = _b.bioRead(fileBio, chunk.cast(), request.chunkSize);
            if (n < 0) return CryptoFailure(FileSigningError(reason: 'BIO_read failed'));
            if (n == 0) break; // EOF
            if (_b.evpDigestSignUpdate(ctx, chunk.cast(), n) != 1)
              return CryptoFailure(FileSigningError(reason: 'EVP_DigestSignUpdate'));
          }
        } finally { calloc.free(chunk); }

        // ══ TWO-PASS FINALIZE ═════════════════════════════════════
        final sigLen = calloc<Size>();
        try {
          _b.evpDigestSign(ctx, nullptr, sigLen, nullptr, 0);  // query len
          final sig = calloc<Uint8>(sigLen.value);
          try {
            _b.evpDigestSign(ctx, sig, sigLen, nullptr, 0);    // sign
            return CryptoSuccess(Uint8List.fromList(sig.asTypedList(sigLen.value)));
          } finally { calloc.free(sig); }
        } finally { calloc.free(sigLen); }
      } finally { _b.evpMdCtxFree(ctx); }
    } finally { _b.evpPkeyFree(pkey); }
  } finally { _b.bioFree(fileBio); }
}
```

### 4.2 Cadeia de Funções C: File Signing

```
BIO_new_file(path, "rb")
BIO_new_mem_buf → PEM_read_bio_PrivateKey
EVP_MD_CTX_new()
EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)
  └─ FALLBACK: EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey)  // ML-DSA

LOOP: BIO_read(fileBio, chunk, chunkSize) → EVP_DigestSignUpdate(ctx, chunk, n)

TWO-PASS:
  EVP_DigestSign(ctx, NULL, &sigLen, NULL, 0)     // query length
  EVP_DigestSign(ctx, sigBuf, &sigLen, NULL, 0)   // finalize

finally (LIFO):
  free(sig) → free(sigLen) → free(chunk) → EVP_MD_CTX_free → EVP_PKEY_free → BIO_free
```

```
DIAGRAMA DE PILHA  Streaming File Signer:
┌───────────────────────────────────────────────────┐
│  Dart: StreamingFileSigner.sign(request)          │
│  ├─ validateFileExists() / validate PEM           │
│  ├─ bioNewFile(path, "rb")                        │
│  ├─ _loadPrivateKey(pem)                          │
│  ├─ evpMdCtxNew()                                 │
│  ├─ evpDigestSignInit() + fallback ML-DSA (null)  │
│  ├─ LOOP: bioRead() → evpDigestSignUpdate()       │
│  ├─ evpDigestSign(NULL, &len) → evpDigestSign()   │
│  └─ finally × 5 (LIFO resource cleanup)           │
├───────────────────────────────────────────────────┤
│  FFI Boundary                                     │
├───────────────────────────────────────────────────┤
│  libcrypto.so                                      │
│  ├─ BIO_new_file(path, "rb") → BIO*               │
│  ├─ PEM_read_bio_PrivateKey() → EVP_PKEY*         │
│  ├─ EVP_MD_CTX_new() → EVP_MD_CTX*                │
│  ├─ EVP_DigestSignInit() [com/sem MD]             │
│  ├─ EVP_DigestSignUpdate() [LOOP de streaming]    │
│  ├─ EVP_DigestSign() × 2 [two-pass finalize]      │
│  └─ EVP_MD_CTX_free() → EVP_PKEY_free()           │
│       → BIO_free(fileBio)                          │
└───────────────────────────────────────────────────┘
```

**Edge cases: File Signing:**
- Arquivo não existe: `FileSystemException` → `FileSigningError`
- PEM sem BEGIN/END: `FileSigningError(reason: 'Invalid private key PEM...')`
- Hash algorithm não suportado: `FileSigningError(reason: 'Unsupported hash algorithm: ...')`
- `BIO_new_file` falha: `FileSigningError(reason: 'BIO_new_file failed  file may not exist or be unreadable')`
- `BIO_read` retorna < 0: `FileSigningError(reason: 'BIO_read failed during streaming')`
- `EVP_DigestSign` retorna len=0: `FileSigningError(reason: 'EVP_DigestSign returned 0 length')`
- **ML-DSA digest mismatch**: fallback automático `EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey)`

---

## 5. Fluxo 4: Verificação de Cadeia de Certificados

### 5.1 Código Real

Arquivo: `lib/src/crypto/flows/certificate_chain/openssl_chain_verifier.dart:37-178`

```dart
CryptoResult<ChainValidationResult> verify(ChainVerificationRequest request) {
  _ctx.bindings.errClearError();  // crítico no Android

  try { request.validate(); }
  on ArgumentError catch (e) {
    return CryptoFailure(ValidationError(field: 'request', reason: e.message.toString()));
  }

  final store = _ctx.bindings.x509StoreNew();
  if (store == nullptr) {
    return _fail<ChainValidationResult>(ChainValidationError(
      chainDetail: 'X509_STORE_new returned null'));
  }
  try {  // (segue o padrão descrito em Gerenciamento de recursos nativos)
    if (request.trustedRoot != null) {
      // loadX509(root) → X509_STORE_add_cert(store, rootX509) → X509_free(rootX509)
    }
    final untrusted = _ctx.bindings.osslSkNewNull();
    try {  // (segue o padrão descrito em Gerenciamento de recursos nativos)
      for (final inter in request.intermediates) {
        // loadX509(inter) → osslSkPush(untrusted, x509)
      }
      final leaf = _loadX509(request.leafCert);
      try {  // (segue o padrão descrito em Gerenciamento de recursos nativos)
        final vfyCtx = _ctx.bindings.x509StoreCtxNew();
        try {  // (segue o padrão descrito em Gerenciamento de recursos nativos)
          _ctx.bindings.x509StoreCtxInit(vfyCtx, store, leaf, untrusted);
          // verificationTime? → X509_VERIFY_PARAM_set_time
          final verifyResult = _ctx.bindings.x509VerifyCert(vfyCtx);

          if (verifyResult == 1) {
            return CryptoSuccess(ChainValidationResult(valid: true));
          }
          // Falha: X509_STORE_CTX_get_error → X509_verify_cert_error_string
          return CryptoSuccess(ChainValidationResult(valid: false,
            errorReason: errStr, chainDepth: errorDepth));
        } finally { _ctx.bindings.x509StoreCtxFree(vfyCtx); }
      } finally { _ctx.bindings.x509Free(leaf); }
    } finally { _ctx.bindings.osslSkFree(untrusted); }
  } finally { _ctx.bindings.x509StoreFree(store); }
}
```

### 5.2 Cadeia de Funções C: Chain Verification

```
ERR_clear_error()
X509_STORE_new()
loadX509(trustedRoot) [PEM→DER fallback] → X509_STORE_add_cert → X509_free
OPENSSL_sk_new_null()
(loop) loadX509(intermediate) → OPENSSL_sk_push
X509_STORE_CTX_new()
X509_STORE_CTX_init(ctx, store, leaf, untrusted)
(opcional) X509_STORE_CTX_get0_param → X509_VERIFY_PARAM_set_time

══ PONTO CENTRAL ══
X509_verify_cert(ctx)
  └─ x509_verify_cert_internal():
     ├─ check_issued() (issuer → subject)
     ├─ check_signature() (cada nível)
     ├─ check_cert_time() (validade)
     ├─ check_name_constraints()
     ├─ check_trust() (root como âncora)
     └─ X509_STORE_CTX_set_error()

X509_STORE_CTX_get_error(ctx) → errorCode
X509_STORE_CTX_get_error_depth(ctx) → depth
X509_verify_cert_error_string(errorCode) → mensagem

finally (LIFO):
  X509_STORE_CTX_free → X509_free(leaf) → osslSkFree(untrusted) → X509_STORE_free
```

```
DIAGRAMA DE PILHA  Chain Verification:
┌───────────────────────────────────────────────────┐
│  Dart: OpensslChainVerifier.verify(request)       │
│  ├─ errClearError()                               │
│  ├─ request.validate() → ArgumentError?           │
│  ├─ x509StoreNew()                                │
│  ├─ loadX509(trustedRoot) → storeAddCert          │
│  ├─ Construir STACK_OF(X509) de intermediárias    │
│  ├─ loadX509(leaf)                                │
│  ├─ x509StoreCtxNew() → x509StoreCtxInit()        │
│  ├─ (opcional) x509VerifyParamSetTime()           │
│  ├─ x509VerifyCert(ctx)  ← PONTO CENTRAL          │
│  ├─ x509StoreCtxGetError() + GetErrorDepth()      │
│  └─ finally × 4 (LIFO: ctx→leaf→stack→store)      │
├───────────────────────────────────────────────────┤
│  FFI Boundary                                     │
├───────────────────────────────────────────────────┤
│  libcrypto.so                                      │
│  ├─ X509_STORE_new()                              │
│  ├─ PEM_read_bio_X509() / d2i_X509_bio()          │
│  ├─ X509_STORE_add_cert()                         │
│  ├─ OPENSSL_sk_new_null() → OPENSSL_sk_push()     │
│  ├─ X509_STORE_CTX_new() → _init()                │
│  ├─ X509_VERIFY_PARAM_set_time()                  │
│  ├─ X509_verify_cert(ctx)                         │
│  │   └─ x509_verify_cert_internal():              │
│  │       ├─ check_issued() / check_signature()    │
│  │       ├─ check_cert_time() / check_trust()     │
│  │       └─ X509_STORE_CTX_set_error()            │
│  ├─ X509_STORE_CTX_get_error()                    │
│  └─ X509_STORE_CTX_free() → ... → _STORE_free()   │
└───────────────────────────────────────────────────┘
```

**Edge cases: Chain Verification:**
- `leafCert` vazio: `ArgumentError` → `ValidationError`
- `verificationTime` no futuro: `ArgumentError` → `ValidationError`
- Certificado corrompido: `ChainValidationError(chainDetail: 'Failed to parse ... certificate')`
- `X509_verify_cert` retorna 0 (cadeia inválida): `CryptoSuccess(valid: false, ...)`: sucesso
  da operação, resultado negativo. NÃO é `CryptoFailure`.
- **BUG-03 fix**: `X509_STORE_add_cert` incrementa refcount; `x509Free` após é seguro

---

## 6. Fluxo 5: Geração de CSR (PKCS#10)

### 6.1 Código Real

Arquivo: `lib/src/crypto/flows/csr/openssl_csr_generator.dart:34-153`

```dart
CryptoResult<CsrData> generate(CsrRequest request) {
  try { request.validate(); }
  catch (e) { return CryptoFailure(CsrError(reason: e.toString())); }

  final pkey = _loadPkey(request.subjectKeyPair.privateKeyPem);
  if (pkey == null) { return CryptoFailure(CsrError(reason: 'Failed to load private key')); }

  try {
    return _doGenerate(request, pkey);
  } finally { _ctx.bindings.evpPkeyFree(pkey); // (segue o padrão descrito em Gerenciamento de recursos nativos)
}

CryptoResult<CsrData> _doGenerate(CsrRequest request, EVP_PKEY pkey) {
  final req = _ctx.bindings.x509ReqNew();
  if (req == nullptr) { return _fail<CsrData>(CsrError(reason: 'X509_REQ_new')); }
  try {
    return _buildReq(req, request, pkey);
  } finally { _ctx.bindings.x509ReqFree(req); // (segue o padrão descrito em Gerenciamento de recursos nativos)
}

CryptoResult<CsrData> _buildReq(X509_REQ req, CsrRequest request, EVP_PKEY pkey) {
  // 1. X509_REQ_set_version(req, 0)
  // 2. X509NameBuilder → X509_REQ_set_subject_name
  // 3. X509_REQ_set_pubkey(req, pkey)
  // 4. (opcional) _addSanExtension: X509V3_set_ctx → X509V3_EXT_conf_nid(SAN)
  //    → OPENSSL_sk_new_null → OPENSSL_sk_push → X509_REQ_add_extensions
  // 5. X509_REQ_sign(req, pkey, EVP_sha256())
  // 6. i2d_X509_REQ_bio → DER / PEM_write_bio_X509_REQ → PEM
  // 7. X509_REQ_get_subject_name → X509_NAME_oneline
}
```

### 6.2 Cadeia de Funções C: CSR Generation

```
BIO_new_mem_buf → PEM_read_bio_PrivateKey → EVP_PKEY*
X509_REQ_new()
X509_REQ_set_version(req, 0)
X509_NAME_new → _add_entry_by_txt × N → X509_REQ_set_subject_name
X509_REQ_set_pubkey(req, pkey)
(opcional) X509V3_set_ctx → X509V3_EXT_conf_nid(SAN)
  → OPENSSL_sk_new_null → _push → X509_REQ_add_extensions
X509_REQ_sign(req, pkey, EVP_sha256())
i2d_X509_REQ_bio → BIO_read → DER
PEM_write_bio_X509_REQ → BIO_read → PEM
X509_REQ_get_subject_name → X509_NAME_oneline → string
```

```
DIAGRAMA DE PILHA  CSR Generation:
┌───────────────────────────────────────────────────┐
│  Dart: OpenSslCsrGenerator.generate(request)      │
│  ├─ request.validate()                            │
│  ├─ _loadPkey(pem)                                │
│  ├─ x509ReqNew()                                  │
│  ├─ x509ReqSetVersion(req, 0)                     │
│  ├─ X509NameBuilder → x509ReqSetSubjectName()     │
│  ├─ x509ReqSetPubkey(req, pkey)                   │
│  ├─ (opcional) _addSanExtension()                 │
│  │   ├─ x509V3SetCtx → x509V3ExtConfNid           │
│  │   ├─ osslSkNewNull → osslSkPush                │
│  │   └─ x509ReqAddExtensions                      │
│  ├─ x509ReqSign(req, pkey, EVP_sha256())          │
│  ├─ _extractDer() / _extractPem()                 │
│  └─ _getSubjectDn()                               │
├───────────────────────────────────────────────────┤
│  FFI Boundary                                     │
├───────────────────────────────────────────────────┤
│  libcrypto.so                                      │
│  ├─ PEM_read_bio_PrivateKey()                     │
│  ├─ X509_REQ_new() → _set_version(0)              │
│  ├─ X509_NAME_add_entry_by_txt() × N              │
│  ├─ X509_REQ_set_subject_name()                   │
│  ├─ X509_REQ_set_pubkey()                         │
│  ├─ X509V3_EXT_conf_nid(85, "DNS:...")            │
│  ├─ X509_REQ_add_extensions()                     │
│  ├─ X509_REQ_sign(req, pkey, sha256)              │
│  ├─ i2d_X509_REQ_bio / PEM_write_bio_X509_REQ     │
│  └─ X509_NAME_oneline()                           │
└───────────────────────────────────────────────────┘
```

**Edge cases: CSR:**
- Chave privada inválida: `CsrError(reason: 'Failed to load private key')`
- `X509_REQ_new` retorna `nullptr`: `CsrError(reason: 'X509_REQ_new')`
- `dnsNames` vazio: extensão SAN não é adicionada
- **TODO conhecido**: ML-DSA não tratado no `X509_REQ_sign` (usa sempre `EVP_sha256()`)

---

## 7. Fluxo 6: Verificação de Revogação: CRL + OCSP

### 7.1 CRL: Verificação de Assinatura

Arquivo: `lib/src/crypto/flows/revocation/crl_verifier.dart:84-137`

```dart
CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert) {
  if (crlData.isEmpty) return CryptoFailure(CrlError(reason: 'crlData must be non-empty'));
  if (caCert.isEmpty)  return CryptoFailure(CrlError(reason: 'caCert must be non-empty'));

  final crl = _loadCrl(crlData);  // PEM → DER fallback
  if (crl == nullptr) {
    return CryptoFailure(CrlError(
      reason: 'Failed to parse CRL for signature verification',
      openSslError: getOpenSslError(_ctx.bindings)));
  }
  try { // (segue o padrão descrito em Gerenciamento de recursos nativos)
    final caPkey = _loadCaPublicKey(caCert);  // loadX509 → X509_get_pubkey
    if (caPkey == nullptr) {
      return CryptoFailure(CrlError(
        reason: 'Failed to load CA certificate public key'));
    }
    try {
      final result = _ctx.bindings.x509CrlVerify(crl, caPkey);
      // 1 = válida, 0 = inválida (assinatura não confere), -1 = erro
      if (result < 0) {
        return CryptoFailure(CrlError(
          reason: 'X509_CRL_verify error',
          openSslError: getOpenSslError(_ctx.bindings)));
      }
      return CryptoSuccess(result == 1);
    } finally { _ctx.bindings.evpPkeyFree(caPkey); }
  } finally { _ctx.bindings.x509CrlFree(crl); }
}
```

(segue o padrão descrito em Gerenciamento de recursos nativos)

#### Cadeia de Funções C: CRL Verify

```
loadCrl(crlData) [PEM→DER fallback]:
  BIO_new_mem_buf → PEM_read_bio_X509_CRL
  (fallback) d2i_X509_CRL_bio

loadCaPublicKey(caCert):
  loadX509(caCert) → X509_get_pubkey(x509) → X509_free(x509)

══ PONTO CENTRAL ══
X509_CRL_verify(crl, caPkey)
  └─ ASN1_item_verify() → verifica assinatura sobre TBSCertList
```

**Edge case: Digest mismatch na assinatura da CRL:**
- `X509_CRL_verify` retorna 0: assinatura não confere → `CryptoSuccess(false)`
- `X509_CRL_verify` retorna -1: erro interno (algoritmo não suportado) → `CryptoFailure(CrlError)`

### 7.2 OCSP: Construção de Request

Arquivo: `lib/src/crypto/flows/revocation/ocsp_verifier.dart:44-116`

```dart
CryptoResult<Uint8List> buildOcspRequest(Uint8List cert, Uint8List issuerCert) {
  if (cert.isEmpty)       return CryptoFailure(OcspError(reason: 'cert must be non-empty'));
  if (issuerCert.isEmpty) return CryptoFailure(OcspError(reason: 'issuerCert must be non-empty'));

  // _parseCert: loadX509(cert) [PEM→DER]
  // _parseCert: loadX509(issuerCert)
  // _doBuildRequest:
  //   x509GetSubjectName → x509Get0PubkeyBitstr → x509GetSerialNumber
  //   OCSP_cert_id_new(EVP_sha256(), issuerName, issuerKey, serialNumber)
  //   OCSP_REQUEST_new() → OCSP_request_add0_id(request, certId)
  //   _requestToDer: i2d_OCSP_REQUEST → two-pass (size query + encode)
}
```

### 7.3 OCSP: Verificação de Response

Arquivo: `lib/src/crypto/flows/revocation/ocsp_verifier.dart:136-328`

```dart
CryptoResult<OcspResponse> _doVerifyResponse(Uint8List respBytes, Uint8List issuerData) {
  // d2i_OCSP_RESPONSE → two-pass via Pointer<Pointer<Uint8>>
  // OCSP_response_status(resp) → deve ser 0 (successful)
  // OCSP_response_get1_basic(resp) → OCSP_BASICRESP
  // _parseCert(issuer) → X509_STORE_new → X509_STORE_add_cert → OCSP_basic_verify
  // OCSP_resp_count → OCSP_resp_get0(bs, 0)
  // OCSP_single_get0_status → reason, revtime, thisupd, nextupd
  // OCSP_check_validity(thisupd, nextupd, 300, -1)
}
```

#### Cadeia de Funções C: OCSP

```
buildOcspRequest:
  X509_get_subject_name(issuer)
  X509_get0_pubkey_bitstr(issuer) → issuerKey (ASN1_BIT_STRING)
  X509_get_serialNumber(leaf) → serialNumber (ASN1_INTEGER)
  OCSP_cert_id_new(EVP_sha256(), issuerName, issuerKey, serialNumber)
  OCSP_REQUEST_new()
  OCSP_request_add0_id(request, certId)  // transfers ownership
  i2d_OCSP_REQUEST(request, NULL)        // query size
  i2d_OCSP_REQUEST(request, &pp)         // encode

verifyOcspResponse:
  d2i_OCSP_RESPONSE(NULL, &pp, len)
  OCSP_response_status(resp) → 0 = successful
  OCSP_response_get1_basic(resp) → OCSP_BASICRESP
  loadX509(issuer) → X509_STORE_new → X509_STORE_add_cert → OCSP_basic_verify
  OCSP_resp_count(bs) → OCSP_resp_get0(bs, 0)
  OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd)
  OCSP_check_validity(thisupd, nextupd, 300, -1)
```

```
DIAGRAMA DE PILHA  OCSP:
┌───────────────────────────────────────────────────┐
│  Dart: OpenSslOcspVerifier                        │
│  buildOcspRequest:                                │
│  ├─ _parseCert(cert) [leaf + issuer]              │
│  ├─ x509GetSubjectName / _get0PubkeyBitstr        │
│  ├─ ocspCertIdNew(EVP_sha256(), ...)              │
│  ├─ ocspRequestNew() → ocspRequestAdd0Id()        │
│  └─ i2dOcspRequest() × 2 [two-pass]              │
│  verifyOcspResponse:                              │
│  ├─ d2iOcspResponse() [two-pass]                  │
│  ├─ ocspResponseStatus() → 0?                     │
│  ├─ ocspResponseGetBasic()                        │
│  ├─ x509StoreNew() → _addCert → ocspBasicVerify   │
│  ├─ ocspRespCount() → ocspRespGet0()              │
│  ├─ ocspSingleGet0Status()                        │
│  └─ ocspCheckValidity(300, -1)                    │
├───────────────────────────────────────────────────┤
│  FFI Boundary                                     │
├───────────────────────────────────────────────────┤
│  libcrypto.so                                      │
│  ├─ X509_get_subject_name / _get0_pubkey_bitstr   │
│  ├─ OCSP_cert_id_new()                            │
│  ├─ OCSP_REQUEST_new() → _add0_id()               │
│  ├─ i2d_OCSP_REQUEST() / d2i_OCSP_RESPONSE()      │
│  ├─ OCSP_response_status() → _get1_basic()        │
│  ├─ OCSP_basic_verify()                           │
│  ├─ OCSP_single_get0_status()                     │
│  └─ OCSP_check_validity()                         │
└───────────────────────────────────────────────────┘
```

**Edge cases: OCSP:**
- Response status ≠ 0 (malformedRequest=1, internalError=2, tryLater=3, etc.):
  `OcspError(reason: 'OCSP_response_status: $statusCode')`
- `OCSP_basic_verify` falha: `OcspError(reason: 'OCSP_basic_verify failed')`
- `OCSP_resp_count` ≤ 0: `OcspResponse(status: CertificateStatus.unknown)`
- `OCSP_check_validity` falha (fora da janela): `OcspError(reason: 'OCSP_check_validity failed')`
- **Status desconhecido**: o enum `CertificateStatus` tem caso `unknown` para quando o
  respondedor OCSP não tem informação sobre o certificado

---

## 8. Fluxo 7: Padrão Universal de Tratamento de Erro e Liberação de Recursos

### 8.1 Hierarquia Selada de Erros

Arquivo: `lib/src/crypto/models/crypto_error.dart:1-233`

```
CryptoError (sealed)
├── KeygenError         { keyType, reason, openSslError? }
├── CertificateError    { reason, openSslError? }
├── FileSigningError    { filePath, reason, openSslError? }
├── ValidationError     { field, reason }
├── ChainValidationError{ chainDetail?, errorDepth?, openSslError? }
├── CrlError            { reason, openSslError? }
├── OcspError           { reason, openSslError? }
├── CsrError            { reason, openSslError? }
├── X509ExtensionError  { oid?, reason, openSslError? }
├── Asn1Error           { reason, openSslError? }
├── AesGcmAuthFailure   { reason, openSslError? }
└── TimestampError      { reason, openSslError? }
```

### 8.2 Captura de Erro OpenSSL

Arquivo: `lib/src/crypto/utils/openssl_error.dart:14-24`

```dart
String? getOpenSslError(OpenSslBindings b) {
  final err = b.errGetError();   // ERR_get_error()
  if (err == 0) return null;
  final buf = calloc<Uint8>(256);
  try {
    b.errErrorStringN(err, buf.cast(), 256);  // ERR_error_string_n
    return buf.cast<Utf8>().toDartString();
  } finally { calloc.free(buf); }
}
```

### 8.3 Padrão `_fail<T>()` Universal

```dart
/// Cria um [CryptoFailure] após limpar a fila de erros do OpenSSL.
CryptoFailure<T> _fail<T>(CryptoError error) {
  _ctx.bindings.errClearError();   // ERR_clear_error()
  return CryptoFailure<T>(error);
}
```

### 8.4 Padrão de Liberação de Recursos (LIFO)

(consolidado em Gerenciamento de recursos nativos; ver seção 1.6)

### 8.5 Propagação de Erro: Dois Modos

1. **Métodos throw-style** (API legada, ex: `AsymmetricOperations`):
   Exceções Dart: `StateError`, `ArgumentError`, `AesGcmAuthFailure`
   ```dart
   // asymmetric_operations.dart:461-467
   void _check1(int result, String op) {
     if (result != 1) {
       final err = getOpenSslError(_b);
       _b.errClearError();
       throw StateError('$op failed${err != null ? ': $err' : ''}');
     }
   }
   ```

2. **Métodos error-as-value** (nova API, TODOS os fluxos documentados):
   `CryptoResult<T>` com pattern matching exaustivo
   ```dart
   switch (result) {
     case CryptoSuccess(:final value): // usa value
     case CryptoFailure(:final error): // trata error.message
   }
   ```

### 8.6 Tabela de Mapeamento Exceção → CryptoError

Arquivo: `lib/src/crypto/models/crypto_error.dart:222-233`

```dart
CryptoError mapExceptionToCryptoError(Object e, String operation) {
  if (e is ArgumentError) {
    return ValidationError(field: 'input',
      reason: (e.message as String?) ?? e.toString());
  }
  if (e is StateError) {
    return KeygenError(keyType: 'unknown', reason: e.message);
  }
  return KeygenError(keyType: 'unknown',
    reason: '$operation: ${e.toString()}');
}
```

### 8.7 BIO Utilities: Gerenciamento de Memória

Arquivo: `lib/src/crypto/utils/bio_utils.dart:1-75`

```dart
BIO bioFromData(OpenSslBindings b, Uint8List data) {
  final bio = b.bioNew(b.bioSMem());
  if (bio == nullptr) return nullptr;
  if (data.isNotEmpty) {
    final dp = calloc<Uint8>(data.length);
    try {
      dp.asTypedList(data.length).setAll(0, data);
      b.bioWrite(bio, dp.cast(), data.length);
    } finally { calloc.free(dp); }
  }
  return bio;
}

Uint8List bioToBytes(OpenSslBindings b, BIO bio) {
  final buffer = BytesBuilder(copy: false);
  final chunk = calloc<Uint8>(4096);
  try {
    while (true) {
      final n = b.bioRead(bio, chunk.cast(), 4096);
      if (n <= 0) break;
      buffer.add(Uint8List.fromList(chunk.asTypedList(n)));
    }
    return buffer.takeBytes();
  } finally { calloc.free(chunk); }
}
```

### 8.8 X.509 Loader: Fallback PEM → DER

Arquivo: `lib/src/crypto/utils/x509_loader.dart:12-26`

```dart
X509 loadX509(OpenSslBindings b, Uint8List data) {
  // Tenta PEM primeiro
  final pemBio = bioFromData(b, data);
  final x509 = b.pemReadBioX509(pemBio, nullptr, nullptr, nullptr);
  b.bioFree(pemBio);
  if (x509 != nullptr) return x509;

  // Fallback: DER
  b.errClearError();
  final derBio = bioFromData(b, data);
  final derX509 = b.d2iX509Bio(derBio, nullptr);
  b.bioFree(derBio);
  return derX509;
}
```

---

## Resumo: Os 7 Fluxos e Suas Cadeias de Funções C

| # | Fluxo | Função C Âncora | Nº de Chamadas FFI |
|---|---|---|---|
| 1 | Criação de Chaves (RSA/EC/ML-KEM/ML-DSA) | `EVP_PKEY_keygen` | 7-10 |
| 2 | Certificado Auto-Assinado X.509 v3 | `X509_sign` | 20-30+ |
| 3 | Assinatura de Arquivos com Streaming | `EVP_DigestSign` | 5 + N×2 (streaming) |
| 4 | Verificação de Cadeia | `X509_verify_cert` | 15-25 |
| 5 | Geração de CSR (PKCS#10) | `X509_REQ_sign` | 15-20 |
| 6a | CRL  Verificação de Assinatura | `X509_CRL_verify` | 8-12 |
| 6b | OCSP  Request + Response | `OCSP_basic_verify` + `d2i_OCSP_RESPONSE` | 15-25 |
| 7 | Padrão de Erro | `ERR_get_error` / `ERR_clear_error` | 1-2 por erro |

---

## Tabela de Edge Cases Críticos

Os 17 edge cases estao agrupados por natureza do erro. Casos dentro de cada grupo
compartilham o mesmo mecanismo de deteccao e tratamento.

### Grupo 1: Erros de validacao (6 casos)

Validacao de parametros ocorre antes de qualquer chamada FFI, lancando `ValidationError`
ou `FileSigningError`. Nao ha interacao com OpenSSL nestes casos. Sao barreiras fail-fast.

| Edge Case | Fluxo | Tipo de Erro | Comportamento |
|---|---|---|---|
| `bits` RSA não múltiplo de 1024 | 1 (RSA) | `ValidationError` | Rejeitado no guard do `create()` |
| `bits` RSA > 16384 | 1 (RSA) | `ValidationError` | Rejeitado no construtor de `RsaKeySpec` |
| Curva EC não suportada (`secp256k1`) | 1 (EC) | `ValidationError` | `'Unsupported curve "secp256k1"'` |
| `notBefore >= notAfter` | 2 | `ValidationError` | Rejeitado em `_validate()` |
| `verificationTime` no futuro | 4 | `ValidationError` | Rejeitado no construtor do request |
| PEM sem BEGIN/END markers | 3 | `FileSigningError` | Validação de string antes do parse |

### Grupo 2: Erros de alocacao e FFI (5 casos)

Falhas na interacao com OpenSSL: contexto nulo, leitura interrompida,
assinatura com tamanho zero. Todos resultam em tipo de erro especifico do dominio.

| Edge Case | Fluxo | Tipo de Erro | Comportamento |
|---|---|---|---|
| `OBJ_sn2nid` retorna 0 (curva não reconhecida) | 1 (EC) | `KeygenError` | Nome de curva inexistente no OpenSSL |
| OpenSSL sem ML-KEM/ML-DSA | 1 (PQC) | `KeygenError` | `EVP_PKEY_CTX_new_id returned null (NID ...)` |
| `BIO_read` retorna < 0 | 3 | `FileSigningError` | Erro de I/O durante streaming |
| `EVP_DigestSign` retorna len=0 | 3 | `FileSigningError` | Two-pass falhou no query de tamanho |
| CRL erro interno (`X509_CRL_verify < 0`) | 6a | `CryptoFailure(CrlError)` | Algoritmo de assinatura nao suportado |

### Grupo 3: Erros de parsing e semantica de protocolo (8 casos)

Envolvem conteudo malformado ou resultados semanticos inesperados.
Diferentemente dos grupos anteriores, alguns destes retornam `CryptoSuccess`
com valor booleano `false`, a operacao em si foi bem-sucedida, mas o resultado
indica falha (assinatura invalida, certificado revogado, etc.).

| Edge Case | Fluxo | Tipo de Erro | Comportamento |
|---|---|---|---|
| Digest mismatch ML-DSA no cert | 2 | `CertificateError` | Prevenido: `md = nullptr` para ML-DSA |
| ML-DSA no `EVP_DigestSignInit` | 3 | `FileSigningError` | Fallback automático com `nullptr` digest |
| Arquivo não existe | 3 | `FileSigningError` | `FileSystemException` capturado |
| Cadeia inválida (assinatura) | 4 | `CryptoSuccess(valid: false)` | NÃO é `CryptoFailure` |
| CRL assinatura inválida (`X509_CRL_verify == 0`) | 6a | `CryptoSuccess(false)` | Assinatura não confere  resultado válido |
| OCSP response status ≠ 0 | 6b | `OcspError` | Ex: malformedRequest=1, tryLater=3 |
| OCSP sem resposta para o cert | 6b | `OcspResponse(status: unknown)` | `OCSP_resp_count ≤ 0` |
| OCSP fora da janela de validade | 6b | `OcspError` | `OCSP_check_validity` falha |

**Nota sobre certificados corrompidos:** `loadX509`/`loadCrl` tenta PEM primeiro e
faz fallback para DER com `ERR_clear_error()` entre as tentativas. Se ambos falharem,
retorna `nullptr`, mapeado para `ChainValidationError`, `CrlError` ou `OcspError`
conforme o fluxo (4, 6a, 6b).
