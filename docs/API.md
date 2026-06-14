# Referencia Completa da API: PluginCrypto

> Documentacao exaustiva de todos os metodos, parametros, retornos, excecoes e exemplos
> da API publica do PluginCrypto. **43 membros publicos documentados com assinaturas literais do codigo-fonte.**

---

## 0. Acesso a API

### `static PluginCryptoAPI get instance`

Singleton lazy, na primeira chamada carrega as bibliotecas nativas (`libcrypto.so.4`,
`libssl.so.4`) e os providers OpenSSL (`default.so`, `legacy.so`, `fips.so`,
`oqsprovider.so`). A inicializacao e thread-safe e acontece uma unica vez.

| Retorno | Descricao |
|---|---|
| `PluginCryptoAPI` | Instancia unica que expoe todos os 40 metodos criptograficos |

### `PluginCryptoAPI get api`

Propriedade de conveniencia na classe `PluginCrypto`. Retorna a mesma instancia
de `PluginCryptoAPI.instance`.

```dart
import 'package:plugin_crypto/plugin_crypto.dart';
final api = PluginCryptoAPI.instance;
// ou via classe de conveniencia:
final api2 = PluginCrypto.instance.api;
// ou via atalho de nivel superior:
final hash = crypto.sha256(dados);
```

### `Future<String?> getPlatformVersion()`

Metodo de conveniencia em `PluginCrypto` que consulta a versao da plataforma
(Android/Linux) via `MethodChannel`. Unico ponto que usa platform channels 
todas as operacoes criptograficas usam FFI puro.

| Retorno | Condicao |
|---|---|
| `Future<String?>` | String da versao da plataforma, ou `null` se indisponivel |

---

## 1. Versao e Diagnostico

### 1.1 `String getOpenSSLVersion()`

Retorna a string de versao do OpenSSL vinculada nativamente.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `String getOpenSSLVersion()` |
| **Retorno** | `String`  ex.: `"OpenSSL 4.0.0 15 Apr 2026"` |
| **Excecoes** | Nenhuma |
| **Chamadas C** | `OpenSSL_version(0)` → le string estatica da biblioteca |

```dart
final api = PluginCryptoAPI.instance;
print(api.getOpenSSLVersion());
// OpenSSL 4.0.0 15 Apr 2026
```

### 1.2 `String? getLastError()`

Retorna a ultima mensagem de erro da fila do OpenSSL, ou `null` se a fila
estiver vazia.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `String? getLastError()` |
| **Retorno** | `String?`  mensagem de erro legivel ou `null` |
| **Excecoes** | Nenhuma |
| **Chamadas C** | `ERR_get_error()` → `ERR_error_string_n()` |

```dart
try {
  api.aes128GcmDecrypt(key, iv, ciphertext, wrongTag);
} on AesGcmAuthFailure {
  final err = api.getLastError();
  print('Erro OpenSSL: $err');
  api.clearErrors();
}
```

### 1.3 `void clearErrors()`

Limpa a fila de erros do OpenSSL. Essencial apos capturar excecoes para evitar
contaminacao entre operacoes.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `void clearErrors()` |
| **Retorno** | `void` |
| **Excecoes** | Nenhuma |
| **Chamadas C** | `ERR_clear_error()` |

---

## 2. Numeros Aleatorios

### 2.1 `Uint8List randomBytes(int length)`

Gera `length` bytes aleatorios criptograficamente seguros.

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `length` | `int` | Deve ser >= 0 | 0 a 65536 |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List randomBytes(int length)` |
| **Retorno** | `Uint8List`  `length` bytes aleatorios (vazio se `length == 0`) |
| **Excecoes** | `StateError("RAND_bytes failed")`  entropia insuficiente (raro) |
| **Chamadas C** | `calloc(length)` → `RAND_bytes(buf, length)` → `Uint8List.fromList()` → `calloc.free(buf)` |

```dart
final api = PluginCryptoAPI.instance;
final key = api.randomBytes(32);  // chave AES-256
final iv  = api.randomBytes(12);  // nonce AES-GCM
final salt = api.randomBytes(16); // salt para KDF
print('${key.length} bytes gerados'); // 32
```

---

## 3. Hash

Os 4 metodos usam o mesmo fluxo nativo: `EVP_MD_CTX_new` → `EVP_DigestInit_ex`
(com `EVP_MD_fetch` interno) → `EVP_DigestUpdate` → `EVP_DigestFinal_ex` →
`EVP_MD_CTX_free`.

### 3.1 `Uint8List sha256(Uint8List data)`

Recebe `data` como `Uint8List` (sem restricoes; vetor vazio aceito).

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List sha256(Uint8List data)` |
| **Retorno** | `Uint8List`  **32 bytes** (256 bits) |
| **Excecoes** | `StateError("EVP_MD_CTX_new failed")`, `StateError("EVP_DigestInit_ex failed: ...")`, `StateError("EVP_DigestUpdate failed: ...")`, `StateError("EVP_DigestFinal_ex failed: ...")` |
| **Chamadas C** | `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)` → `calloc(data.length)` → `EVP_DigestUpdate(ctx, dp, data.length)` → `calloc(32)` → `EVP_DigestFinal_ex(ctx, mdBuf, mdLen)` → `EVP_MD_CTX_free(ctx)` |

### 3.2 `Uint8List sha512(Uint8List data)`

Recebe `data` como `Uint8List` (sem restricoes; vetor vazio aceito).

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List sha512(Uint8List data)` |
| **Retorno** | `Uint8List`  **64 bytes** (512 bits) |
| **Excecoes** | Vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entrada sha256/512/3_256/3_512 |
| **Chamadas C** | `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr)` → `calloc(data.length)` → `EVP_DigestUpdate(ctx, dp, data.length)` → `calloc(64)` → `EVP_DigestFinal_ex(ctx, mdBuf, mdLen)` → `EVP_MD_CTX_free(ctx)` |

### 3.3 `Uint8List sha3_256(Uint8List data)`

Recebe `data` como `Uint8List` (sem restricoes; vetor vazio aceito).

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List sha3_256(Uint8List data)` |
| **Retorno** | `Uint8List`  **32 bytes** (256 bits) |
| **Excecoes** | Vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entrada sha256/512/3_256/3_512 |
| **Chamadas C** | `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr)` → `calloc(data.length)` → `EVP_DigestUpdate(ctx, dp, data.length)` → `calloc(32)` → `EVP_DigestFinal_ex(ctx, mdBuf, mdLen)` → `EVP_MD_CTX_free(ctx)` |

### 3.4 `Uint8List sha3_512(Uint8List data)`

Recebe `data` como `Uint8List` (sem restricoes; vetor vazio aceito).

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List sha3_512(Uint8List data)` |
| **Retorno** | `Uint8List`  **64 bytes** (512 bits) |
| **Excecoes** | Vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entrada sha256/512/3_256/3_512 |
| **Chamadas C** | `EVP_MD_CTX_new()` → `EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr)` → `calloc(data.length)` → `EVP_DigestUpdate(ctx, dp, data.length)` → `calloc(64)` → `EVP_DigestFinal_ex(ctx, mdBuf, mdLen)` → `EVP_MD_CTX_free(ctx)` |

```dart
import 'dart:convert';
final api = PluginCryptoAPI.instance;
final dados = utf8.encode('PluginCrypto');

final h256   = api.sha256(dados);     // [32 bytes]
final h512   = api.sha512(dados);     // [64 bytes]
final h3_256 = api.sha3_256(dados);   // [32 bytes]
final h3_512 = api.sha3_512(dados);   // [64 bytes]

String hex(Uint8List b) =>
    b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
print(hex(h256));
```

---

## 4. AES-128-CBC

Usa `EVP_CIPHER_fetch("AES-128-CBC")`, padding PKCS#7 automatico.

### 4.1 `Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `iv` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `plaintext` | `Uint8List` | Qualquer tamanho | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)` |
| **Retorno** | `Uint8List`  texto cifrado (inclui padding PKCS#7, tamanho >= plaintext) |
| **Excecoes** | `ArgumentError("Key must be 16 bytes for AES-128, got N")`, `ArgumentError("IV must be 16 bytes, got N")`, `StateError("EVP_EncryptInit_ex failed: ...")`, `StateError("EVP_EncryptUpdate failed: ...")`, `StateError("EVP_EncryptFinal_ex failed: ...")` |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)` → `calloc(dataLen + 16)` → `EVP_EncryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen)` → `EVP_CIPHER_CTX_free(ctx)` |

### 4.2 `Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `iv` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `ciphertext` | `Uint8List` | Multiplo de 16 bytes (bloco AES) | 16..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes128CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)` |
| **Retorno** | `Uint8List`  texto claro (padding PKCS#7 removido automaticamente) |
| **Excecoes** | `ArgumentError("Key must be 16 bytes for AES-128, got N")`, `ArgumentError("IV must be 16 bytes, got N")`, `StateError("EVP_DecryptInit_ex failed: ...")`, `StateError("EVP_DecryptUpdate failed: ...")`, `StateError("EVP_DecryptFinal_ex failed: ...")` (padding invalido ou chave incorreta) |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)` → `calloc(dataLen)` → `EVP_DecryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_DecryptFinal_ex(ctx, out + outLen, &finalLen)` → `EVP_CIPHER_CTX_free(ctx)` |

```dart
final api = PluginCryptoAPI.instance;
final key = utf8.encode('0123456789abcdef'); // 16 bytes exatos
final iv  = utf8.encode('fedcba9876543210'); // 16 bytes exatos
final plaintext = utf8.encode('Mensagem secreta com padding automatico');

final cifrado = api.aes128CbcEncrypt(key, iv, plaintext);
final decifrado = api.aes128CbcDecrypt(key, iv, cifrado);
print(utf8.decode(decifrado)); // Mensagem secreta com padding automatico
```

---

## 5. AES-256-CBC

Usa `EVP_CIPHER_fetch("AES-256-CBC")`, padding PKCS#7 automatico, com chave de 32 bytes.

### 5.1 `Uint8List aes256CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 32 bytes | 32 bytes fixo |
| `iv` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `plaintext` | `Uint8List` | Qualquer tamanho | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes256CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext)` |
| **Retorno** | `Uint8List`  texto cifrado com padding PKCS#7 |
| **Excecoes** | `ArgumentError("Key must be 32 bytes for AES-256, got N")`; demais excecoes, vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entrada AES CBC encrypt/decrypt |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)` → `calloc(dataLen + 16)` → `EVP_EncryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen)` → `EVP_CIPHER_CTX_free(ctx)` |

### 5.2 `Uint8List aes256CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 32 bytes | 32 bytes fixo |
| `iv` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `ciphertext` | `Uint8List` | Multiplo de 16 bytes | 16..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes256CbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext)` |
| **Retorno** | `Uint8List`  texto claro |
| **Excecoes** | `ArgumentError("Key must be 32 bytes for AES-256, got N")`, `ArgumentError("IV must be 16 bytes, got M")`; demais excecoes, vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entrada AES CBC encrypt/decrypt |

```dart
final key = api.randomBytes(32); // 32 bytes exatos
final iv  = api.randomBytes(16);
final plaintext = utf8.encode('AES-256 e mais seguro que AES-128');

final cifrado = api.aes256CbcEncrypt(key, iv, plaintext);
final decifrado = api.aes256CbcDecrypt(key, iv, cifrado);
print(utf8.decode(decifrado)); // AES-256 e mais seguro que AES-128
```

---

## 6. AES-128-GCM (Cifra Autenticada)

Usa `EVP_CIPHER_fetch("AES-128-GCM")`, configura IV de 12 bytes (NIST SP 800-38D),
processa AAD opcional (autenticado mas nao cifrado), extrai tag de 16 bytes.

### 6.1 `AesGcmResult aes128GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `iv` | `Uint8List` | 12 bytes recomendado (NIST) | 1..N bytes |
| `plaintext` | `Uint8List` | Qualquer tamanho | 0..N bytes |
| `aad` | `Uint8List?` | Opcional | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `AesGcmResult aes128GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})` |
| **Retorno** | `AesGcmResult { Uint8List ciphertext, Uint8List tag }`  `tag` tem **16 bytes** |
| **Excecoes** | `ArgumentError("Key must be 16 bytes for AES-128, got N")`, `StateError("EVP_EncryptInit_ex failed: ...")`, `StateError("EVP_EncryptUpdate failed: ...")`, `StateError("EVP_EncryptFinal_ex failed: ...")` |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, iv)` → `EVP_CIPHER_CTX_ctrl(ctx, SET_IVLEN, 12)` → `EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nullptr)` → _se aad:_ `EVP_EncryptUpdate(ctx, nullptr, &len, aad, aadLen)` → `EVP_EncryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen)` → `EVP_CIPHER_CTX_ctrl(ctx, GET_TAG, 16, tag)` → `EVP_CIPHER_CTX_free(ctx)` |

### 6.2 `Uint8List aes128GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `iv` | `Uint8List` | Deve ser identico ao usado na cifracao | 1..N bytes |
| `ciphertext` | `Uint8List` | Qualquer tamanho | 0..N bytes |
| `tag` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `aad` | `Uint8List?` | Deve ser identico ao usado na cifracao | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes128GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})` |
| **Retorno** | `Uint8List`  texto claro original |
| **Excecoes** | `ArgumentError("Key must be 16 bytes for AES-128, got N")`, `ArgumentError("Tag must be 16 bytes for GCM, got N")`, **`AesGcmAuthFailure("GCM authentication failed: tag mismatch")`**  tag nao confere, dados corrompidos ou chave/IV/AAD errados, `StateError(...)`  falha nas funcoes EVP |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, iv)` → `EVP_CIPHER_CTX_ctrl(ctx, SET_IVLEN, 12)` → `EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nullptr)` → _se aad:_ `EVP_DecryptUpdate(ctx, nullptr, &len, aad, aadLen)` → `EVP_DecryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_CIPHER_CTX_ctrl(ctx, SET_TAG, 16, tag)` → `EVP_DecryptFinal_ex(ctx, out + outLen, &finalLen)` → **se retorno != 1: lanca `AesGcmAuthFailure`** → `EVP_CIPHER_CTX_free(ctx)` |

```dart
final api = PluginCryptoAPI.instance;
final key = api.randomBytes(16);
final iv  = api.randomBytes(12);
final plaintext = utf8.encode('dados confidenciais');
final aad = utf8.encode('metadados autenticados');

// Cifracao
final result = api.aes128GcmEncrypt(key, iv, plaintext, aad: aad);
print('Ciphertext: ${result.ciphertext.length} bytes, Tag: ${result.tag.length} bytes');

// Transmissao segura: iv + result.ciphertext + result.tag (+ aad)

// Decifracao
try {
  final decifrado = api.aes128GcmDecrypt(
    key, iv, result.ciphertext, result.tag, aad: aad,
  );
  print(utf8.decode(decifrado)); // dados confidenciais
} on AesGcmAuthFailure catch (e) {
  print('Falha de autenticacao GCM: ${e.reason}');
  print('Erro OpenSSL: ${e.openSslError}');
}
```

---

## 7. AES-256-GCM

Usa `EVP_CIPHER_fetch("AES-256-GCM")`, configura IV de 12 bytes (NIST SP 800-38D), processa AAD opcional, extrai tag de 16 bytes, com chave de 32 bytes.

### 7.1 `AesGcmResult aes256GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 32 bytes | 32 bytes fixo |
| `iv` | `Uint8List` | 12 bytes recomendado | 1..N bytes |
| `plaintext` | `Uint8List` | Qualquer tamanho | 0..N bytes |
| `aad` | `Uint8List?` | Opcional | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `AesGcmResult aes256GcmEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext, {Uint8List? aad})` |
| **Retorno** | `AesGcmResult`  `tag` de 16 bytes |
| **Excecoes** | `ArgumentError("Key must be 32 bytes for AES-256, got N")`; demais excecoes, vide [Resumo dos Padroes de Erro](#23-resumo-dos-padroes-de-erro), entradas AES GCM |
| **Chamadas C** | `EVP_CIPHER_CTX_new()` → `EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, iv)` → `EVP_CIPHER_CTX_ctrl(ctx, SET_IVLEN, 12)` → `EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nullptr)` → _se aad:_ `EVP_EncryptUpdate(ctx, nullptr, &len, aad, aadLen)` → `EVP_EncryptUpdate(ctx, out, &outLen, data, dataLen)` → `EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen)` → `EVP_CIPHER_CTX_ctrl(ctx, GET_TAG, 16, tag)` → `EVP_CIPHER_CTX_free(ctx)` |

### 7.2 `Uint8List aes256GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `key` | `Uint8List` | Exatamente 32 bytes | 32 bytes fixo |
| `iv` | `Uint8List` | Deve corresponder ao IV usado na cifracao | 1..N bytes |
| `ciphertext` | `Uint8List` | Qualquer tamanho | 0..N bytes |
| `tag` | `Uint8List` | Exatamente 16 bytes | 16 bytes fixo |
| `aad` | `Uint8List?` | Deve corresponder ao AAD usado na cifracao | 0..N bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List aes256GcmDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext, Uint8List tag, {Uint8List? aad})` |
| **Retorno** | `Uint8List`  texto claro |
| **Excecoes** | `ArgumentError("Key must be 32 bytes for AES-256, got N")`, `ArgumentError("Tag must be 16 bytes for GCM, got N")`, `AesGcmAuthFailure("GCM authentication failed: tag mismatch")` |

```dart
final key = api.randomBytes(32);
final iv  = api.randomBytes(12);
final dados = utf8.encode('AES-256-GCM com AAD');
final aad = utf8.encode('cabecalho seguro');

final result = api.aes256GcmEncrypt(key, iv, dados, aad: aad);
final decifrado = api.aes256GcmDecrypt(
  key, iv, result.ciphertext, result.tag, aad: aad,
);
print(utf8.decode(decifrado)); // AES-256-GCM com AAD
```

---

## 8. Geracao de Chaves RSA

### 8.1 `KeyPair generateRsaKeyPair(int bits)`

Fluxo nativo: `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA)` → `EVP_PKEY_keygen_init` →
`EVP_PKEY_CTX_set_rsa_keygen_bits` → `EVP_PKEY_keygen` → serializacao PEM.

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `bits` | `int` | Multiplo de 1024 | 1024 a 16384 |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `KeyPair generateRsaKeyPair(int bits)` |
| **Retorno** | `KeyPair { String publicKeyPem, String privateKeyPem }`  PEM com cabecalhos `-----BEGIN PUBLIC KEY-----` (X.509 SubjectPublicKeyInfo) e `-----BEGIN PRIVATE KEY-----` (PKCS#8) |
| **Excecoes** | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")`, `StateError("EVP_PKEY_CTX_set_rsa_keygen_bits failed: ...")`, `StateError("EVP_PKEY_keygen failed: ...")` |
| **Chamadas C** | `EVP_PKEY_CTX_new_id(6, nullptr)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits)` → `calloc<EVP_PKEY>()` → `EVP_PKEY_keygen(ctx, ppkey)` → `PEM_write_bio_PUBKEY(bio, pkey)` → `PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)` → libera todos os recursos |

```dart
final api = PluginCryptoAPI.instance;

final kp2048 = api.generateRsaKeyPair(2048);
print(kp2048.publicKeyPem);  // -----BEGIN PUBLIC KEY----- ...
print(kp2048.privateKeyPem); // -----BEGIN PRIVATE KEY----- ...

final kp4096 = api.generateRsaKeyPair(4096); // maior seguranca
```

---

## 9. Geracao de Chaves EC

### 9.1 `KeyPair generateEcKeyPair(String curveName)`

Resolve curva via `OBJ_sn2nid`, configura `EVP_PKEY_CTX_set_ec_paramgen_curve_nid`.

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `curveName` | `String` | Deve ser uma das curvas suportadas | `"prime256v1"`, `"secp384r1"`, `"secp521r1"` |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `KeyPair generateEcKeyPair(String curveName)` |
| **Retorno** | `KeyPair` em formato PEM |
| **Excecoes** | `StateError("OBJ_sn2nid(CurvaInvalida) failed")`  curva nao reconhecida, `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")`, `StateError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed: ...")`, `StateError("EVP_PKEY_keygen failed: ...")` |
| **Chamadas C** | `OBJ_sn2nid(curveName)` → `EVP_PKEY_CTX_new_id(408, nullptr)` → `EVP_PKEY_keygen_init(ctx)` → `EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid)` → `calloc<EVP_PKEY>()` → `EVP_PKEY_keygen(ctx, ppkey)` → `PEM_write_bio_PUBKEY` + `PEM_write_bio_PrivateKey` |

```dart
final api = PluginCryptoAPI.instance;

final kp256 = api.generateEcKeyPair('prime256v1'); // P-256
final kp384 = api.generateEcKeyPair('secp384r1');  // P-384
final kp521 = api.generateEcKeyPair('secp521r1');  // P-521

print(kp256.publicKeyPem.length); // ~180 chars
```

---

## 10. Assinatura e Verificacao

Detecta automaticamente o tipo de chave (RSA, EC, Ed25519, ML-DSA).
Usa `EVP_DigestSignInit` + `EVP_DigestSign`. Para ML-DSA (FIPS 204),
faz fallback para digest `nullptr` (o algoritmo internaliza o hashing).

### 10.1 `Uint8List sign(Uint8List data, Uint8List privateKeyPem, {String hashAlgorithm = 'sha256'})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `data` | `Uint8List` | Bytes a assinar | 0..N bytes |
| `privateKeyPem` | `Uint8List` | Chave privada em PEM ou DER | bytes UTF-8 validos |
| `hashAlgorithm` | `String` | Algoritmo de hash nomeado | `'sha256'` (padrao), `'sha384'`, `'sha512'`, `'sha3_256'` |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List sign(Uint8List data, Uint8List privateKeyPem, {String hashAlgorithm = 'sha256'})` |
| **Retorno** | `Uint8List`  assinatura digital (DER para ECDSA, bytes brutos para RSA) |
| **Excecoes** | `ArgumentError("Unsupported hash: sha1")`  hash nao suportado, `StateError("PEM_read_bio_PrivateKey failed")`  chave invalida, `StateError("EVP_MD_CTX_new failed")`, `StateError("EVP_DigestSignInit failed: ...")`, `StateError("EVP_DigestSign(length) failed")`, `StateError("EVP_DigestSign failed: ...")` |
| **Chamadas C** | `PEM_read_bio_PrivateKey(bio)` → `EVP_MD_CTX_new()` → `EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey)`  _se falhar (ML-DSA):_ `ERR_clearError()` → `EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey)` → `EVP_DigestSign(ctx, nullptr, &sigLen, nullptr, 0)` → `calloc(sigLen)` → `EVP_DigestSign(ctx, sig, &sigLen, data, dataLen)` → `EVP_MD_CTX_free(ctx)` → `EVP_PKEY_free(pkey)` |

### 10.2 `bool verify(Uint8List data, Uint8List publicKeyPem, Uint8List signature, {String hashAlgorithm = 'sha256'})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `data` | `Uint8List` | Dados originais | 0..N bytes |
| `publicKeyPem` | `Uint8List` | Chave publica em PEM ou DER | bytes UTF-8 validos |
| `signature` | `Uint8List` | Assinatura a verificar | bytes da assinatura |
| `hashAlgorithm` | `String` | Deve ser o mesmo usado em `sign()` | `'sha256'`, `'sha384'`, `'sha512'`, `'sha3_256'` |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `bool verify(Uint8List data, Uint8List publicKeyPem, Uint8List signature, {String hashAlgorithm = 'sha256'})` |
| **Retorno** | `true`  assinatura valida; `false`  assinatura invalida (dados adulterados ou chave errada) |
| **Excecoes** | `ArgumentError("Unsupported hash: ...")`, `StateError("PEM_read_bio_PUBKEY failed")`, `StateError("EVP_MD_CTX_new failed")`, `StateError("EVP_DigestVerifyInit(ML-DSA) failed: ...")` |
| **Chamadas C** | `PEM_read_bio_PUBKEY(bio)` → `EVP_MD_CTX_new()` → `EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey)`  _se falhar:_ `ERR_clearError()` → `EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey)` → `EVP_DigestVerify(ctx, sig, sigLen, data, dataLen)` → retorna `result == 1` |

```dart
import 'dart:convert';
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

final kp = api.generateEcKeyPair('prime256v1');
final documento = utf8.encode('Documento importante para assinar');

// Assinar
final assinatura = api.sign(
  Uint8List.fromList(documento),
  pem(kp.privateKeyPem),
  hashAlgorithm: 'sha256',
);

// Verificar
final valido = api.verify(
  Uint8List.fromList(documento),
  pem(kp.publicKeyPem),
  assinatura,
  hashAlgorithm: 'sha256',
);
print(valido); // true

// Assinatura adulterada retorna false
final assinaturaAdulterada = Uint8List.fromList(
  [...assinatura]..[0] ^= 0xFF,
);
print(api.verify(
  Uint8List.fromList(documento),
  pem(kp.publicKeyPem),
  assinaturaAdulterada,
)); // false
```

---

## 11. RSA OAEP (Cifracao Assimetrica)

### 11.1 `Uint8List rsaEncrypt(Uint8List publicKeyPem, Uint8List plaintext)`

RSA-OAEP com SHA-256.

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `publicKeyPem` | `Uint8List` | Chave publica do destinatario (PEM ou DER) | bytes validos |
| `plaintext` | `Uint8List` | Tamanho maximo depende do bits da chave | ~190 bytes para RSA-2048, ~446 bytes para RSA-4096 |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List rsaEncrypt(Uint8List publicKeyPem, Uint8List plaintext)` |
| **Retorno** | `Uint8List`  texto cifrado (tamanho = tamanho da chave em bytes) |
| **Excecoes** | `StateError("PEM_read_bio_PUBKEY failed")`, `StateError("EVP_PKEY_CTX_new failed")`, `StateError("EVP_PKEY_encrypt_init failed: ...")`, `StateError("EVP_PKEY_encrypt(size) failed")`  plaintext muito grande, `StateError("EVP_PKEY_encrypt failed: ...")` |
| **Chamadas C** | `PEM_read_bio_PUBKEY(bio)` → `EVP_PKEY_CTX_new(pkey, nullptr)` → `EVP_PKEY_encrypt_init(ctx)` → `EVP_PKEY_encrypt(ctx, nullptr, &outLen, data, dataLen)` → `calloc(outLen)` → `EVP_PKEY_encrypt(ctx, out, &outLen, data, dataLen)` → `EVP_PKEY_CTX_free(ctx)` → `EVP_PKEY_free(pkey)` |

### 11.2 `Uint8List rsaDecrypt(Uint8List privateKeyPem, Uint8List ciphertext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `privateKeyPem` | `Uint8List` | Chave privada correspondente (PEM ou DER) | bytes validos |
| `ciphertext` | `Uint8List` | Texto cifrado produzido por `rsaEncrypt` | tamanho da chave em bytes |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List rsaDecrypt(Uint8List privateKeyPem, Uint8List ciphertext)` |
| **Retorno** | `Uint8List`  texto claro original |
| **Excecoes** | `StateError("PEM_read_bio_PrivateKey failed")`, `StateError("EVP_PKEY_CTX_new failed")`, `StateError("EVP_PKEY_decrypt_init failed: ...")`, `StateError("EVP_PKEY_decrypt(size) failed")`, `StateError("EVP_PKEY_decrypt failed: ...")`  chave incorreta |
| **Chamadas C** | `PEM_read_bio_PrivateKey(bio)` → `EVP_PKEY_CTX_new(pkey, nullptr)` → `EVP_PKEY_decrypt_init(ctx)` → `EVP_PKEY_decrypt(ctx, nullptr, &outLen, data, dataLen)` → `calloc(outLen)` → `EVP_PKEY_decrypt(ctx, out, &outLen, data, dataLen)` |

```dart
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

final kp = api.generateRsaKeyPair(2048);
final segredo = utf8.encode('Chave simetrica AES-256');

// Cifrar com chave publica do destinatario
final cifrado = api.rsaEncrypt(pem(kp.publicKeyPem), segredo);
print('Tamanho cifrado: ${cifrado.length} bytes'); // 256 bytes para RSA-2048

// Decifrar com chave privada
final decifrado = api.rsaDecrypt(pem(kp.privateKeyPem), cifrado);
print(utf8.decode(decifrado)); // Chave simetrica AES-256
```

---

## 12. ML-KEM: Encapsulamento Pos-Quantico (FIPS 203, Kyber)

O ML-KEM (Kyber) e o algoritmo de encapsulamento de chave pos-quantico
padronizado pelo NIST. Opera como KEM (Key Encapsulation Mechanism).

| Parametro Set | Seguranca | Tamanho Ciphertext | Tamanho Shared Secret |
|---|---|---|---|
| `mlKem512` | 128-bit | ~768 bytes | 32 bytes |
| `mlKem768` | 192-bit | ~1088 bytes | 32 bytes |
| `mlKem1024` | 256-bit | ~1568 bytes | 32 bytes |

### 12.1 `({Uint8List ciphertext, Uint8List sharedSecret}) mlKemEncapsulate(Uint8List publicKeyPem)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `publicKeyPem` | `Uint8List` | Chave publica ML-KEM do destinatario (PEM ou DER) | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `({Uint8List ciphertext, Uint8List sharedSecret}) mlKemEncapsulate(Uint8List publicKeyPem)` |
| **Retorno** | Registro com `ciphertext` (enviar ao peer) + `sharedSecret` (32 bytes, usar como chave AES) |
| **Excecoes** | `StateError("PEM_read_bio_PUBKEY failed")`, `StateError("EVP_PKEY_CTX_new failed")`, `StateError("EVP_PKEY_encapsulate_init failed: ...")`, `StateError("EVP_PKEY_encapsulate(sizes) failed")`, `StateError("EVP_PKEY_encapsulate failed: ...")` |
| **Chamadas C** | `PEM_read_bio_PUBKEY(bio)` → `EVP_PKEY_CTX_new(pkey, nullptr)` → `EVP_PKEY_encapsulate_init(ctx, nullptr)` → `EVP_PKEY_encapsulate(ctx, nullptr, &ctLen, nullptr, &ssLen)` → `calloc(ctLen)` + `calloc(ssLen)` → `EVP_PKEY_encapsulate(ctx, ct, &ctLen, ss, &ssLen)` |

### 12.2 `Uint8List mlKemDecapsulate(Uint8List privateKeyPem, Uint8List ciphertext)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `privateKeyPem` | `Uint8List` | Chave privada ML-KEM (PEM ou DER) | bytes validos |
| `ciphertext` | `Uint8List` | Ciphertext produzido por `mlKemEncapsulate` | bytes do ciphertext |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List mlKemDecapsulate(Uint8List privateKeyPem, Uint8List ciphertext)` |
| **Retorno** | `Uint8List`  `sharedSecret` de 32 bytes (identico ao gerado no encapsulamento) |
| **Excecoes** | `StateError("PEM_read_bio_PrivateKey failed")`, `StateError("EVP_PKEY_CTX_new failed")`, `StateError("EVP_PKEY_decapsulate_init failed: ...")`, `StateError("EVP_PKEY_decapsulate(size) failed")`, `StateError("EVP_PKEY_decapsulate failed: ...")` |
| **Chamadas C** | `PEM_read_bio_PrivateKey(bio)` → `EVP_PKEY_CTX_new(pkey, nullptr)` → `EVP_PKEY_decapsulate_init(ctx, nullptr)` → `EVP_PKEY_decapsulate(ctx, nullptr, &ssLen, ct, ctLen)` → `calloc(ssLen)` → `EVP_PKEY_decapsulate(ctx, ss, &ssLen, ct, ctLen)` |

```dart
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

// Nota: para ML-KEM use KeyCreatorFactory com MlKemKeySpec
// Exemplo com chave EC (placeholder  ML-KEM requer provider pos-quantico):
final kp = api.generateEcKeyPair('prime256v1');

// Alice encapsula
final (:ciphertext, :sharedSecret) = api.mlKemEncapsulate(
  pem(kp.publicKeyPem),
);
print('Shared secret: ${sharedSecret.length} bytes'); // 32

// Bob decapsula
final bobSecret = api.mlKemDecapsulate(
  pem(kp.privateKeyPem),
  ciphertext,
);
// sharedSecret == bobSecret (identicos)
```

---

## 13. X.509: Certificados

### 13.1 `X509Certificate parseX509Certificate(Uint8List certData)`

Recebe `certData` como `Uint8List` contendo um certificado X.509 em formato PEM ou DER.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `X509Certificate parseX509Certificate(Uint8List certData)` |
| **Retorno** | `X509Certificate { String subject, String issuer, String serialNumber, DateTime notBefore, DateTime notAfter, Uint8List rawDer, X509ParsedExtensions? extensions }` |
| **Excecoes** | `StateError("PEM_read_bio_X509 failed: ...")`  dados invalidos ou formato nao reconhecido |
| **Chamadas C** | `BIO_new_mem_buf(certData, certData.length)` → `PEM_read_bio_X509(bio)`  _se falhar:_ `d2i_X509_bio(bio)` → `X509_get_subject_name(x509)` → `X509_NAME_oneline(name)` → `X509_get_issuer_name(x509)` → `X509_get_serialNumber(x509)` → `X509_get0_notBefore(x509)` → `X509_get0_notAfter(x509)` → `ASN1_TIME_print(bio, time)` → `X509ExtensionParser` extrai extensoes |

### 13.2 `bool verifyX509Certificate(Uint8List cert, Uint8List caCert)`

Recebe `cert` (certificado folha) e `caCert` (certificado da CA confiavel), ambos como `Uint8List` em formato PEM ou DER.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `bool verifyX509Certificate(Uint8List cert, Uint8List caCert)` |
| **Retorno** | `true`  cadeia de 1 nivel valida; `false`  falha na validacao |
| **Excecoes** | `StateError("X509_STORE_new failed")`, `StateError("PEM_read_bio_X509(CA) failed: ...")`, `StateError("X509_STORE_add_cert failed: ...")`, `StateError("PEM_read_bio_X509(leaf) failed: ...")`, `StateError("X509_STORE_CTX_new failed")`, `StateError("X509_STORE_CTX_init failed: ...")` |
| **Chamadas C** | `X509_STORE_new()` → `PEM_read_bio_X509(caBio)` → `X509_STORE_add_cert(store, ca)` → `PEM_read_bio_X509(certBio)` → `X509_STORE_CTX_new()` → `X509_STORE_CTX_init(vfyCtx, store, x509, nullptr)` → `X509_verify_cert(vfyCtx)` → retorna `result == 1` |

```dart
import 'dart:io';
final api = PluginCryptoAPI.instance;

// Ler certificado de arquivo
final certBytes = await File('/tmp/cert.pem').readAsBytes();
final parsed = api.parseX509Certificate(certBytes);

print('Subject: ${parsed.subject}');
print('Issuer:  ${parsed.issuer}');
print('Serial:  ${parsed.serialNumber}');
print('Valido de ${parsed.notBefore} ate ${parsed.notAfter}');

// Verificar cadeia
final caBytes = await File('/tmp/ca.pem').readAsBytes();
final cadeiaValida = api.verifyX509Certificate(certBytes, caBytes);
print('Cadeia valida: $cadeiaValida');
```

---

## 14. CMS/PKCS#7: Assinatura

### 14.1 `Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `data` | `Uint8List` | Dados a assinar | 0..N bytes |
| `certPem` | `Uint8List` | Certificado X.509 do signatario (PEM ou DER) | bytes validos |
| `keyPem` | `Uint8List` | Chave privada correspondente (PEM ou DER) | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List cmsSign(Uint8List data, Uint8List certPem, Uint8List keyPem)` |
| **Retorno** | `Uint8List`  CMS SignedData em DER (flag `CMS_BINARY`) |
| **Excecoes** | `StateError("PEM_read_bio_X509 failed: ...")`, `StateError("PEM_read_bio_PrivateKey failed: ...")`, `StateError("CMS_sign failed: ...")` |
| **Chamadas C** | `PEM_read_bio_X509(certBio)` → `PEM_read_bio_PrivateKey(keyBio)` → `BIO_new_mem_buf(data, dataLen)` → `CMS_sign(x509, pkey, nullptr, inBio, CMS_BINARY)` → `PEM_write_bio_CMS(bio, cms)` → extrai DER |

### 14.2 `bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `signedData` | `Uint8List` | CMS SignedData (PEM ou DER) | bytes validos |
| `trustedCert` | `Uint8List?` | Certificado confiavel opcional | bytes validos ou null |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `bool cmsVerify(Uint8List signedData, {Uint8List? trustedCert})` |
| **Retorno** | `true`  assinatura criptograficamente valida; `false`  assinatura invalida |
| **Excecoes** | `StateError("X509_STORE_new failed")`, `StateError("CMS_verify failed: ...")` |
| **Chamadas C** | `X509_STORE_new()` → _se trustedCert:_ `PEM_read_bio_X509` → `X509_STORE_add_cert` → `PEM_read_bio_CMS(bio)` → `CMS_verify(cms, nullptr, store, nullptr, nullptr, CMS_NO_SIGNER_CERT_VERIFY)` |

```dart
import 'dart:convert';
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

final kp = api.generateEcKeyPair('prime256v1');
final dados = utf8.encode('Conteudo do documento');

// Assinar CMS
final signed = api.cmsSign(
  Uint8List.fromList(dados),
  pem(kp.publicKeyPem),
  pem(kp.privateKeyPem),
);

// Verificar
final verificado = api.cmsVerify(signed, trustedCert: pem(kp.publicKeyPem));
print('CMS assinatura valida: $verificado'); // true
```

---

## 15. CMS/PKCS#7: Cifracao

### 15.1 `Uint8List cmsEncrypt(Uint8List data, Uint8List certPem)`

Recebe `data` (bytes a cifrar) e `certPem` (certificado X.509 do destinatario em PEM ou DER), ambos como `Uint8List`.

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List cmsEncrypt(Uint8List data, Uint8List certPem)` |
| **Retorno** | `Uint8List`  CMS EnvelopedData em DER (AES-256-CBC para conteudo, RSA para chave de sessao) |
| **Excecoes** | `StateError("PEM_read_bio_X509 failed: ...")`, `StateError("CMS_encrypt failed: ...")` |
| **Chamadas C** | `PEM_read_bio_X509(certBio)` → `OPENSSL_sk_new_null()` → `OPENSSL_sk_push(certs, x509)` → `BIO_new_mem_buf(data, dataLen)` → `CMS_encrypt(certs, inBio, EVP_aes_256_cbc(), 0)` → `PEM_write_bio_CMS(bio, cms)` → extrai DER |

### 15.2 `Uint8List cmsDecrypt(Uint8List encryptedData, Uint8List certPem, Uint8List keyPem)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `encryptedData` | `Uint8List` | CMS EnvelopedData (PEM ou DER) | bytes validos |
| `certPem` | `Uint8List` | Certificado do destinatario | bytes validos |
| `keyPem` | `Uint8List` | Chave privada do destinatario | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List cmsDecrypt(Uint8List encryptedData, Uint8List certPem, Uint8List keyPem)` |
| **Retorno** | `Uint8List`  dados originais |
| **Excecoes** | `StateError("PEM_read_bio_CMS failed: ...")`, `StateError("PEM_read_bio_PrivateKey failed: ...")`, `StateError("PEM_read_bio_X509 failed: ...")`, `StateError("CMS_decrypt failed: ...")` |
| **Chamadas C** | `PEM_read_bio_CMS(inBio)` → `PEM_read_bio_PrivateKey(keyBio)` → `PEM_read_bio_X509(certBio)` → `BIO_new(BIO_s_mem())` → `CMS_decrypt(cms, pkey, x509, nullptr, outBio, 0)` → `BIO_read(outBio)` → extrai bytes |

```dart
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

final kp = api.generateRsaKeyPair(2048);
final dados = utf8.encode('Documento sigiloso para destinatario');

// Cifrar CMS (enveloped)
final enveloped = api.cmsEncrypt(dados, pem(kp.publicKeyPem));
print('CMS EnvelopedData: ${enveloped.length} bytes');

// Decifrar
final decifrado = api.cmsDecrypt(enveloped, pem(kp.publicKeyPem), pem(kp.privateKeyPem));
print(utf8.decode(decifrado)); // Documento sigiloso para destinatario
```

---

## 16. CAdES-BES (CMS Advanced Electronic Signatures)

### 16.1 `Uint8List cmsSignCades(Uint8List data, Uint8List certPem, Uint8List keyPem, {Uint8List? caCertPem, List<Uint8List>? intermediates, bool addSigningTime = true, bool addMessageDigest = true})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `data` | `Uint8List` | Dados a assinar | Nao vazio (1..N bytes) |
| `certPem` | `Uint8List` | Certificado do signatario (PEM ou DER) | bytes validos |
| `keyPem` | `Uint8List` | Chave privada do signatario (PEM ou DER) | bytes validos |
| `caCertPem` | `Uint8List?` | Certificado CA para bag de certificados | bytes validos ou null |
| `intermediates` | `List<Uint8List>?` | Lista de certificados intermediarios | lista de bytes ou null |
| `addSigningTime` | `bool` | Adiciona atributo signing-time | `true` (padrao) ou `false` |
| `addMessageDigest` | `bool` | Adiciona atributo message-digest | `true` (padrao) ou `false` |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `Uint8List cmsSignCades(Uint8List data, Uint8List certPem, Uint8List keyPem, {Uint8List? caCertPem, List<Uint8List>? intermediates, bool addSigningTime = true, bool addMessageDigest = true})` |
| **Retorno** | `Uint8List`  CMS SignedData DER com perfil CAdES-BES |
| **Excecoes** | `ArgumentError("data must be non-empty")`, `ArgumentError("certPem must be non-empty")`, `ArgumentError("keyPem must be non-empty")`, `StateError("CMS_sign(CAdES) failed: ...")` |
| **Chamadas C** | `PEM_read_bio_X509(certBio)` → `PEM_read_bio_PrivateKey(keyBio)` → `_buildCertStack()` (cadeia completa) → `BIO_new_mem_buf(data, dataLen)` → `CMS_sign(x509, pkey, certs, inBio, CMS_BINARY | CMS_CADES)` → _se addMessageDigest && !addSigningTime:_ `CMS_signed_add1_attr_by_txt(si, "messageDigest", ...)` |

```dart
final api = PluginCryptoAPI.instance;
Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));

final kp = api.generateEcKeyPair('prime256v1');
final dados = utf8.encode('Documento PDF para assinatura avancada');

// CAdES-BES com signing-time e message-digest
final cades = api.cmsSignCades(
  Uint8List.fromList(dados),
  pem(kp.publicKeyPem),
  pem(kp.privateKeyPem),
  addSigningTime: true,
  addMessageDigest: true,
);
print('CAdES-BES assinado: ${cades.length} bytes');

// Verificar como CMS comum
final valido = api.cmsVerify(cades, trustedCert: pem(kp.publicKeyPem));
print('Assinatura CAdES valida: $valido'); // true
```

---

## 17. CRL: Lista de Revogacao de Certificados *(CryptoResult\<T\>)*

Todas as operacoes CRL retornam `CryptoResult<T>` (error-as-value, sem excecoes).

### 17.1 `CryptoResult<CrlInfo> parseCrl(Uint8List crlData)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `crlData` | `Uint8List` | CRL em DER ou PEM | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<CrlInfo> parseCrl(Uint8List crlData)` |
| **Retorno (sucesso)** | `CryptoSuccess<CrlInfo>`  `CrlInfo { DateTime lastUpdate, DateTime nextUpdate, String issuer, List<RevokedEntry> revoked }` |
| **Retorno (falha)** | `CryptoFailure<CrlError>`  `CrlError { String reason, String? openSslError }` |
| **Chamadas C** | `BIO_new_mem_buf(crlData)` → `d2i_X509_CRL_bio(bio)`  _se falhar:_ `PEM_read_bio_X509_CRL(bio)` → `X509_CRL_get0_lastUpdate(crl)` → `X509_CRL_get0_nextUpdate(crl)` → `X509_CRL_get_issuer(crl)` → `X509_CRL_get_REVOKED(crl)` → itera `OPENSSL_sk_num`/`OPENSSL_sk_value` → `X509_REVOKED_get0_serialNumber`/`X509_REVOKED_get0_revocationDate` |

### 17.2 `CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `crlData` | `Uint8List` | CRL em DER ou PEM | bytes validos |
| `caCert` | `Uint8List` | Certificado da CA emissora (PEM ou DER) | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert)` |
| **Retorno** | `CryptoSuccess<bool>`  `true` se assinatura valida; `CryptoFailure<CrlError>` em caso de erro |
| **Chamadas C** | `d2i_X509_CRL_bio`/`PEM_read_bio_X509_CRL` → `PEM_read_bio_X509(caCert)` → `X509_CRL_verify(crl, caPkey)` |

### 17.3 `CryptoResult<CertificateRevocationStatus> checkRevocation(Uint8List certData, Uint8List crlData)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `certData` | `Uint8List` | Certificado a verificar (PEM ou DER) | bytes validos |
| `crlData` | `Uint8List` | CRL onde buscar o certificado | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<CertificateRevocationStatus> checkRevocation(Uint8List certData, Uint8List crlData)` |
| **Retorno** | `CryptoSuccess<CertificateRevocationStatus>`  `{ bool isRevoked, DateTime? revocationDate, int? reasonCode }` |
| **Chamadas C** | Parse do certificado (extrai serial) → Parse da CRL → busca linear comparando numeros de serie |

```dart
import 'dart:io';
final api = PluginCryptoAPI.instance;

final crlBytes = await File('/tmp/minha.crl').readAsBytes();

// 1. Parse da CRL
final parseResult = api.parseCrl(crlBytes);
switch (parseResult) {
  case CryptoSuccess(:final crlInfo):
    print('CRL Emissor: ${crlInfo.issuer}');
    print('Atualizada: ${crlInfo.lastUpdate}');
    print('Proxima: ${crlInfo.nextUpdate}');
    print('Revogados: ${crlInfo.revoked.length}');
    for (final entry in crlInfo.revoked) {
      print('  Serial ${entry.serialNumber} revogado em ${entry.revocationDate}');
    }
  case CryptoFailure(:final error):
    print('Erro ao parse CRL: ${error.message}');
}

// 2. Verificar assinatura da CRL
final caBytes = await File('/tmp/ca.pem').readAsBytes();
final sigResult = api.verifyCrlSignature(crlBytes, caBytes);
switch (sigResult) {
  case CryptoSuccess(:final valid):
    print('Assinatura CRL valida: $valid');
  case CryptoFailure(:final error):
    print('Erro: ${error.message}');
}

// 3. Verificar se certificado especifico esta revogado
final certBytes = await File('/tmp/leaf.pem').readAsBytes();
final revResult = api.checkRevocation(certBytes, crlBytes);
switch (revResult) {
  case CryptoSuccess(:final status):
    if (status.isRevoked) {
      print('CERTIFICADO REVOGADO em ${status.revocationDate}');
    } else {
      print('Certificado nao revogado');
    }
  case CryptoFailure(:final error):
    print('Erro: ${error.message}');
}
```

---

## 18. OCSP: Status Online *(CryptoResult\<T\>)*

### 18.1 `CryptoResult<Uint8List> buildOcspRequest(Uint8List cert, Uint8List issuerCert)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `cert` | `Uint8List` | Certificado a verificar (PEM ou DER) | bytes validos |
| `issuerCert` | `Uint8List` | Certificado do emissor (PEM ou DER) | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<Uint8List> buildOcspRequest(Uint8List cert, Uint8List issuerCert)` |
| **Retorno** | `CryptoSuccess<Uint8List>`  requisicao OCSP DER-encoded pronta para envio ao OCSP responder |
| **Chamadas C** | `PEM_read_bio_X509(cert)` → `PEM_read_bio_X509(issuer)` → `OCSP_CERTID_new(EVP_sha256(), issuer, serial, nullptr)` → `OCSP_REQUEST_new()` → `OCSP_request_add0_id(req, cid)` → `i2d_OCSP_REQUEST(req, &der)` |

### 18.2 `CryptoResult<OcspResponse> verifyOcspResponse(Uint8List ocspRespBytes, Uint8List issuerCert)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `ocspRespBytes` | `Uint8List` | Resposta OCSP DER do responder | bytes validos |
| `issuerCert` | `Uint8List` | Certificado do emissor que assinou a resposta | bytes validos |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<OcspResponse> verifyOcspResponse(Uint8List ocspRespBytes, Uint8List issuerCert)` |
| **Retorno** | `CryptoSuccess<OcspResponse>`  `{ CertificateStatus status, DateTime? producedAt, DateTime? thisUpdate, DateTime? nextUpdate }` onde `status` e `CertificateStatus.good`, `.revoked` ou `.unknown` |
| **Chamadas C** | `d2i_OCSP_RESPONSE(bio)` → `OCSP_response_status(resp)` → `OCSP_response_get1_basic(resp)` → `OCSP_basic_verify(bs, issuerStack, store, 0)` → `OCSP_resp_find_status(bs, cid, &status, &reason, &revtime, &thisupd, &nextupd)` |

```dart
import 'dart:io';
final api = PluginCryptoAPI.instance;

final certBytes = await File('/tmp/leaf.pem').readAsBytes();
final issuerBytes = await File('/tmp/ca.pem').readAsBytes();

// Construir requisicao OCSP
final reqResult = api.buildOcspRequest(certBytes, issuerBytes);
switch (reqResult) {
  case CryptoSuccess(:final ocspReq):
    print('OCSP request: ${ocspReq.length} bytes DER');
    // Enviar ocspReq para http://ocsp.responder.com/
  case CryptoFailure(:final error):
    print('Erro: ${error.message}');
}

// Verificar resposta OCSP recebida
final respBytes = await File('/tmp/ocsp_resp.der').readAsBytes();
final respResult = api.verifyOcspResponse(respBytes, issuerBytes);
switch (respResult) {
  case CryptoSuccess(:final ocspResp):
    switch (ocspResp.status) {
      case CertificateStatus.good:
        print('Certificado VALIDO (good)');
        print('Produzido em: ${ocspResp.producedAt}');
      case CertificateStatus.revoked:
        print('Certificado REVOGADO!');
      case CertificateStatus.unknown:
        print('Status DESCONHECIDO');
    }
  case CryptoFailure(:final error):
    print('Erro na verificacao OCSP: ${error.message}');
}
```

---

## 19. CSR: Certificate Signing Request *(CryptoResult\<T\>)*

### 19.1 `CryptoResult<CsrData> generateCsr(CsrRequest request)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `request` | `CsrRequest` | `CsrRequest { DistinguishedName subject, KeyPair subjectKeyPair, List<String>? dnsNames }` | subject com CN nao vazio, keyPair com chaves nao vazias |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<CsrData> generateCsr(CsrRequest request)` |
| **Retorno (sucesso)** | `CryptoSuccess<CsrData>`  `CsrData { Uint8List derBytes, String pemString, String subjectDn }` |
| **Retorno (falha)** | `CryptoFailure<CsrError>`  `CsrError { String reason, String? openSslError }` |
| **Chamadas C** | `X509_REQ_new()` → `X509_REQ_set_version(req, 0)` → `X509_REQ_set_subject_name(req, name)` → `X509_REQ_set_pubkey(req, pkey)` → _se dnsNames:_ `X509_REQ_add_extensions(req, extStack)` → `X509_REQ_sign(req, pkey, EVP_sha256())` → `i2d_X509_REQ_bio(bio, req)` → `PEM_write_bio_X509_REQ(bio, req)` |

```dart
final api = PluginCryptoAPI.instance;
final kp = api.generateEcKeyPair('prime256v1');

final request = CsrRequest(
  subject: const DistinguishedName(
    commonName: 'meusite.com',
    organization: 'MinhaEmpresa',
    country: 'BR',
  ),
  subjectKeyPair: kp,
  dnsNames: ['meusite.com', '*.meusite.com'],
);

final result = api.generateCsr(request);
switch (result) {
  case CryptoSuccess(:final csrData):
    print('CSR Subject DN: ${csrData.subjectDn}');
    print('CSR PEM:\n${csrData.pemString}');
    // Enviar csrData.derBytes ou csrData.pemString para a CA
  case CryptoFailure(:final error):
    print('Erro na geracao do CSR: ${error.message}');
}
```

---

## 20. Timestamp RFC 3161 *(CryptoResult\<T\>)*

### 20.1 `CryptoResult<Uint8List> createTimestampRequest(Uint8List data, {String hashAlgorithm = 'sha256', Uint8List? nonce})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `data` | `Uint8List` | Dados a serem timestamped | 0..N bytes |
| `hashAlgorithm` | `String` | Algoritmo de hash | `'sha256'` (padrao), `'sha384'`, `'sha512'` |
| `nonce` | `Uint8List?` | Nonce opcional anti-replay | bytes ou null |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<Uint8List> createTimestampRequest(Uint8List data, {String hashAlgorithm = 'sha256', Uint8List? nonce})` |
| **Retorno** | `CryptoSuccess<Uint8List>`  TimeStampReq DER-encoded |
| **Chamadas C** | Constroi DER manual: `SEQUENCE { INTEGER version=1, SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }, INTEGER nonce? }` (nao usa API TS do OpenSSL) |

### 20.2 `CryptoResult<TimestampResponse> verifyTimestampResponse(Uint8List responseData, {Uint8List? cert})`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `responseData` | `Uint8List` | TimeStampResp DER do TSA | bytes validos |
| `cert` | `Uint8List?` | Certificado do TSA para verificacao | bytes ou null |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<TimestampResponse> verifyTimestampResponse(Uint8List responseData, {Uint8List? cert})` |
| **Retorno** | `CryptoSuccess<TimestampResponse>`  `{ TimestampStatus status, String? statusString, Uint8List? tokenData, DateTime? genTime, String? serialNumber, Uint8List? messageImprint, int? nonce, String? policyOid, TimestampAccuracy? accuracy }` |
| **Chamadas C** | Parse DER manual: PKIStatusInfo → TSTInfo do token (SEQUENCE aninhada) |

### 20.3 `CryptoResult<bool> verifyTimestamp(Uint8List tokenData, Uint8List data)`

| Parametro | Tipo | Restricoes | Faixa Valida |
|---|---|---|---|
| `tokenData` | `Uint8List` | Token de timestamp DER (TimeStampToken) | bytes validos |
| `data` | `Uint8List` | Dados originais que foram timestamped | bytes originais |

| Campo | Detalhe |
|---|---|
| **Assinatura** | `CryptoResult<bool> verifyTimestamp(Uint8List tokenData, Uint8List data)` |
| **Retorno** | `CryptoSuccess<bool>`  `true` se token valido e messageImprint confere |
| **Chamadas C** | Verifica assinatura CMS do token → Confere `messageImprint` com hash dos dados |

```dart
final api = PluginCryptoAPI.instance;
final dados = utf8.encode('Documento a ser carimbado no tempo');

// Criar requisicao de timestamp
final reqResult = api.createTimestampRequest(
  Uint8List.fromList(dados),
  hashAlgorithm: 'sha256',
  nonce: api.randomBytes(8),
);
switch (reqResult) {
  case CryptoSuccess(:final requestBytes):
    print('Timestamp request: ${requestBytes.length} bytes');
    // Enviar requestBytes para um TSA (Timestamp Authority)
    // Apos receber resposta: api.verifyTimestampResponse(respBytes)
  case CryptoFailure(:final error):
    print('Erro ao criar request: ${error.message}');
}
```

---

## 21. Hierarquia de Erros

### 21.1 `CryptoError` (sealed, 13 subtipos)

```
CryptoError (sealed) → { String get message }
├── KeygenError            { String keyType, String reason, String? openSslError }
├── CertificateError       { String reason, String? openSslError }
├── FileSigningError       { String filePath, String reason, String? openSslError }
├── ValidationError        { String field, String reason }
├── ChainValidationError   { String? chainDetail, int? errorDepth, String? openSslError }
├── CrlError               { String reason, String? openSslError }
├── X509ExtensionError     { String? oid, String reason, String? openSslError }
├── OcspError              { String reason, String? openSslError }
├── Asn1Error              { String reason, String? openSslError }
├── AesGcmAuthFailure      { String reason, String? openSslError }
├── CsrError               { String reason, String? openSslError }
├── TimestampError         { String reason, String? openSslError }
```

Cada subtipo implementa `String get message` que formata uma mensagem legivel
incluindo o `openSslError` quando disponivel.

### 21.2 `CryptoResult<T>` (Result Monad)

```dart
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

#### Pattern Matching com `switch` exaustivo

```dart
// Exemplo 1: switch simples
switch (result) {
  case CryptoSuccess(:final value):
    print('Sucesso: $value');
  case CryptoFailure(:final error):
    print('Erro: ${error.message}');
}

// Exemplo 2: switch com verificacao de tipo de erro
final crlResult = api.parseCrl(crlBytes);
switch (crlResult) {
  case CryptoSuccess(:final crlInfo):
    print('CRL contem ${crlInfo.revoked.length} entradas revogadas');
  case CryptoFailure(:final CrlError reason: final motivo):
    print('Erro de CRL: $motivo');
  case CryptoFailure(:final error):
    print('Outro erro: ${error.message}');
}
```

### 21.3 Ponte entre Excecoes e Erros Tipados

A funcao `mapExceptionToCryptoError(Object e, String operation)` converte:
- `ArgumentError` → `ValidationError(field: 'input', reason: e.message)`
- `StateError` → `KeygenError(keyType: 'unknown', reason: e.message)`
- Outros → `KeygenError(keyType: 'unknown', reason: '$operation: $e')`

---

## 22. Modelos de Dados

### 22.1 Chaves e Algoritmos

```dart
class KeyPair {
  final String publicKeyPem;   // -----BEGIN PUBLIC KEY-----
  final String privateKeyPem;  // -----BEGIN PRIVATE KEY----- (PKCS#8)
  const KeyPair({required this.publicKeyPem, required this.privateKeyPem});
}

sealed class KeySpec { const KeySpec._(); }
class RsaKeySpec extends KeySpec {
  final int bits;  // 1024-16384, multiplo de 1024
  RsaKeySpec(this.bits);
}
class EcKeySpec extends KeySpec {
  final String curve;  // prime256v1, secp384r1, secp521r1
  EcKeySpec(this.curve);
}
class MlKemKeySpec extends KeySpec {
  final MlKemParameterSet parameterSet;  // mlKem512, mlKem768, mlKem1024
  const MlKemKeySpec(this.parameterSet);
}
class MlDsaKeySpec extends KeySpec {
  final MlDsaParameterSet parameterSet;  // mlDsa44, mlDsa65, mlDsa87
  const MlDsaKeySpec(this.parameterSet);
}

enum MlKemParameterSet { mlKem512, mlKem768, mlKem1024 }
enum MlDsaParameterSet { mlDsa44, mlDsa65, mlDsa87 }
enum HashAlgorithm { sha256, sha512, sha3_256, sha3_512 }
enum SigningKeyType { rsa, ec, ml_dsa }
enum CertificateStatus { good, revoked, unknown }

class SigningAlgorithm {
  final HashAlgorithm hash;
  final SigningKeyType keyType;
  const SigningAlgorithm({required this.hash, required this.keyType});
  String get hashName;
}
```

### 22.2 AesGcmResult

```dart
class AesGcmResult {
  final Uint8List ciphertext;
  final Uint8List tag;  // sempre 16 bytes
  const AesGcmResult(this.ciphertext, this.tag);
}
```

### 22.3 DistinguishedName

```dart
class DistinguishedName {
  final String commonName;           // CN  obrigatorio, nao vazio
  final String? organization;        // O
  final String? organizationalUnit;  // OU
  final String? locality;            // L
  final String? state;               // ST
  final String? country;             // C  2 letras maiusculas ISO 3166-1 alpha-2

  const DistinguishedName({
    required this.commonName, this.organization,
    this.organizationalUnit, this.locality,
    this.state, this.country,
  });

  void validate(); // lanca ArgumentError se CN vazio ou country invalido
  List<(String, String)> get entries; // pares (shortName, value) ordenados
}
```

### 22.4 X509Certificate / CertificateData

```dart
class X509Certificate {
  final String subject;
  final String issuer;
  final String serialNumber;
  final DateTime notBefore;
  final DateTime notAfter;
  final Uint8List rawDer;
  final X509ParsedExtensions? extensions;
  const X509Certificate({required this.subject, required this.issuer,
    required this.serialNumber, required this.notBefore,
    required this.notAfter, required this.rawDer, this.extensions});
}

class CertificateData {
  final Uint8List derBytes;
  final String pemString;
  final X509Certificate parsed;
  final String subjectDn;
  final String issuerDn;
  final DateTime notBefore;
  final DateTime notAfter;
  const CertificateData({required this.derBytes, required this.pemString,
    required this.parsed, required this.subjectDn, required this.issuerDn,
    required this.notBefore, required this.notAfter});
}

class X509ParsedExtensions {
  final List<String>? keyUsage;
  final BasicConstraints? basicConstraints;
  final List<String>? subjectAltNames;
  final List<String>? crlDistributionPoints;
  final List<String>? ocspResponders;
  const X509ParsedExtensions({this.keyUsage, this.basicConstraints,
    this.subjectAltNames, this.crlDistributionPoints, this.ocspResponders});
}

class BasicConstraints {
  final bool isCa;
  final int? pathLen;
  const BasicConstraints({required this.isCa, this.pathLen});
}
```

### 22.5 CSR / CRL / OCSP

```dart
class CsrRequest {
  final DistinguishedName subject;
  final KeyPair subjectKeyPair;
  final List<String>? dnsNames;
  const CsrRequest({required this.subject,
    required this.subjectKeyPair, this.dnsNames});
  CsrRequest validate();
}

class CsrData {
  final Uint8List derBytes;
  final String pemString;
  final String subjectDn;
  const CsrData({required this.derBytes,
    required this.pemString, required this.subjectDn});
}

class CrlInfo {
  final DateTime lastUpdate;
  final DateTime nextUpdate;
  final String issuer;
  final List<RevokedEntry> revoked;
  const CrlInfo({required this.lastUpdate,
    required this.nextUpdate, required this.issuer,
    this.revoked = const []});
}

class RevokedEntry {
  final String serialNumber;
  final DateTime revocationDate;
  final int? reason; // 0=unspecified, 1=keyCompromise, etc.
  const RevokedEntry({required this.serialNumber,
    required this.revocationDate, this.reason});
}

class CertificateRevocationStatus {
  final bool isRevoked;
  final DateTime? revocationDate;
  final int? reasonCode;
  const CertificateRevocationStatus({required this.isRevoked,
    this.revocationDate, this.reasonCode});
  static const notRevoked =
      CertificateRevocationStatus(isRevoked: false);
}

class OcspResponse {
  final CertificateStatus status; // good, revoked, unknown
  final DateTime? producedAt;
  final DateTime? thisUpdate;
  final DateTime? nextUpdate;
  const OcspResponse({required this.status,
    this.producedAt, this.thisUpdate, this.nextUpdate});
}
```

### 22.6 Timestamp

```dart
enum TimestampStatus {
  granted, grantedWithMods, rejection,
  waiting, revocationWarning, revocationNotification,
}

class TimestampResponse {
  final TimestampStatus status;
  final String? statusString;
  final Uint8List? tokenData;
  final DateTime? genTime;
  final String? serialNumber;
  final String? hashAlgorithmOid;
  final Uint8List? messageImprint;
  final int? nonce;
  final String? policyOid;
  final TimestampAccuracy? accuracy;
  const TimestampResponse({required this.status, this.statusString,
    this.tokenData, this.genTime, this.serialNumber,
    this.hashAlgorithmOid, this.messageImprint,
    this.nonce, this.policyOid, this.accuracy});
  bool get isGranted;
}

class TimestampAccuracy {
  final int? seconds;
  final int? millis;
  final int? micros;
  const TimestampAccuracy({this.seconds, this.millis, this.micros});
}
```

---

## 23. Resumo dos Padroes de Erro

### Lancam excecoes (throw-style)

| Operacao | Excecoes Possiveis |
|---|---|
| `getOpenSSLVersion()` | Nenhuma |
| `getLastError()` / `clearErrors()` | Nenhuma |
| `randomBytes(int)` | `StateError("RAND_bytes failed")` |
| `sha256/512/3_256/3_512` | `StateError("EVP_MD_CTX_new failed")`, `StateError("EVP_DigestInit_ex failed: ...")`, `StateError("EVP_DigestUpdate failed: ...")`, `StateError("EVP_DigestFinal_ex failed: ...")` |
| AES CBC encrypt/decrypt | `ArgumentError("Key must be N bytes...")`, `ArgumentError("IV must be 16 bytes, got M")`, `StateError("EVP_EncryptInit_ex/DecryptInit_ex failed: ...")`, `StateError("EVP_EncryptUpdate/DecryptUpdate failed: ...")`, `StateError("EVP_EncryptFinal_ex/DecryptFinal_ex failed: ...")` |
| AES GCM encrypt | `ArgumentError("Key must be N bytes...")`, `StateError("EVP_EncryptInit_ex failed: ...")` |
| AES GCM decrypt | `ArgumentError("Key must be N bytes...")`, `ArgumentError("Tag must be 16 bytes for GCM, got N")`, **`AesGcmAuthFailure("GCM authentication failed: tag mismatch")`** |
| `generateRsaKeyPair` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")`, `StateError("EVP_PKEY_keygen failed: ...")` |
| `generateEcKeyPair` | `StateError("OBJ_sn2nid(NAME) failed")`, `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")`, `StateError("EVP_PKEY_keygen failed: ...")` |
| `sign` | `ArgumentError("Unsupported hash: ...")`, `StateError("PEM_read_bio_PrivateKey failed")`, `StateError("EVP_DigestSignInit failed: ...")`, `StateError("EVP_DigestSignUpdate failed: ...")`, `StateError("EVP_DigestSignFinal failed: ...")` |
| `verify` | `ArgumentError("Unsupported hash: ...")`, `StateError("PEM_read_bio_PUBKEY failed")`, `StateError("EVP_DigestVerifyInit failed: ...")`, `StateError("EVP_DigestVerifyUpdate failed: ...")`, `StateError("EVP_DigestVerifyFinal failed")` |
| `createCsr` | `ArgumentError("Unsupported digest: ...")` |
| `parseCsr` | `FormatException("Failed to read CSR from PEM")` |
| `createCsrFromKeyPair` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")` |
| `parseCertificate` | **`CertificateException`** (retorna `CryptoResult.failure`) |
| `parsePkcs12` | **`Pkcs12Exception`** (retorna `CryptoResult.failure`) |
| `parseCrl` | **`CrlParsingException`** (retorna `CryptoResult.failure`) |
| `verifyCertificateChain` | **`ChainVerificationException`** (retorna `CryptoResult.failure`), **`CrlVerificationException`** (retorna `CryptoResult.failure`) |
| `verifyOcsp` | **`OcspVerificationException`** (retorna `CryptoResult.failure`) |
| `createTimestampRequest` / `parseTimestampToken` | **`TimestampException`** (retorna `CryptoResult.failure`) |
| `encryptWithPublicKey` | `StateError("PEM_read_bio_PUBKEY failed")`, `StateError("EVP_PKEY_encrypt_init failed: ...")` |
| `decryptWithPrivateKey` | `StateError("PEM_read_bio_PrivateKey failed")`, `StateError("EVP_PKEY_decrypt_init failed: ...")` |
| `encryptEnvelope` | **`Pkcs12Exception`** (se certificado invalido), `StateError("PEM_read_bio_X509 failed")` |
| `decryptEnvelope` | **`Pkcs12Exception`** (se chave invalida), `StateError("PEM_read_bio_PrivateKey failed")` |
| `generateKey` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")` |
| `generateDsaKeyPair` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")` |
| `generateMlKemKeyPair` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")` |
| `generateMlDsaKeyPair` | `StateError("EVP_PKEY_CTX_new_id failed")`, `StateError("EVP_PKEY_keygen_init failed: ...")` |

---

## 24. Padroes de Uso do CryptoResult

O tipo `sealed class CryptoResult<T>` possui duas subclasses:

```dart
final result = await plugin.someOperation();

// Pattern matching exaustivo
switch (result) {
  case CryptoSuccess(:final value):
    print("Sucesso: $value");
  case CryptoFailure(:final exception):
    print("Falha: ${exception.message}");
}

// OU com when/is
if (result case CryptoSuccess(value: final v)) {
  print("Sucesso: $v");
} else if (result case CryptoFailure(exception: final ex)) {
  print("Erro: ${ex.message}");
}

// Metodo utilitario fold
final mensagem = result.fold(
  onSuccess: (val) => "OK: $val",
  onFailure: (ex) => "ERRO: ${ex.message}",
);
```

### Exemplo com decisao por tipo de excecao

```dart
final result = await plugin.verifyCertificateChain(
  certPem, chainPems, crlPems, [],
);

result.fold(
  onSuccess: (ChainVerifyData ok) => print("Cadeia valida"),
  onFailure: (CryptoException ex) {
    switch (ex) {
      case ChainVerificationException():
        print("Cadeia quebrada em: ${ex.chainIndex}");
      case CrlVerificationException():
        print("CRL rejeitou o certificado");
      default:
        print("Outro erro: ${ex.message}");
    }
  },
);
```

---

## 25. Referencia Rapida por Caso de Uso

| Caso de Uso | Metodo(s) | Retorno |
|---|---|---|
| **Hash de dados** | `sha256(buf)`, `sha512(buf)`, `sha3_256(buf)`, `sha3_512(buf)` | `Uint8List` |
| **Gerar bytes aleatorios** | `randomBytes(int)` | `Uint8List` |
| **Criptografar simetrico (CBC)** | `aesEncryptCbc(buf, key, iv)` | `Uint8List` |
| **Descriptografar simetrico (CBC)** | `aesDecryptCbc(buf, key, iv)` | `Uint8List` |
| **Criptografar simetrico (GCM)** | `aesEncryptGcm(buf, key, iv, aad?)` | `Uint8List` |
| **Descriptografar simetrico (GCM)** | `aesDecryptGcm(buf, key, iv, tag, aad?)` | `Uint8List` |
| **Gerar par RSA** | `generateRsaKeyPair(int bits, {exponent})` | `KeyPairData` |
| **Gerar par EC** | `generateEcKeyPair(EcCurveName name)` | `KeyPairData` |
| **Gerar par DSA** | `generateDsaKeyPair(int bits)` | `KeyPairData` |
| **Gerar chave ML-KEM** | `generateMlKemKeyPair()` | `KeyPairData` |
| **Gerar chave ML-DSA** | `generateMlDsaKeyPair()` | `KeyPairData` |
| **Gerar chave generica** | `generateKey(KeyType type, {bits, curve, exponent})` | `KeyPairData` |
| **Converter chave** | `extractPublicKey(pem)`, `extractPrivateKey(pem)` | `String` |
| **Extrair pubkey de par** | `extractPublicKeyFromPair(data)` | `String` / `CryptoResult<String>` |
| **Assinar dados** | `sign(data, privKeyPem, HashAlgorithm)` | `Uint8List` |
| **Verificar assinatura** | `verify(data, sig, pubKeyPem, HashAlgorithm)` | `bool` |
| **Criar CSR manual** | `createCsr(subject, privKeyPem, digest?, extensions?)` | `String` |
| **Criar CSR com geracao** | `createCsrFromKeyPair(subject, KeyType, bits?, curve?, exponent?, digest?, extensions?)` | `String` |
| **Parse CSR** | `parseCsr(csrPem)` | `CsrData` |
| **Parse X509 to DER** | `parseX509ToDer(certPem)` | `List<int>` |
| **Parse certificado** | `parseCertificate(certPem)` | `CryptoResult<CertificateData>` |
| **Parse PKCS#12** | `parsePkcs12(p12Data, password?)` | `CryptoResult<Pkcs12Data>` |
| **Parse CRL** | `parseCrl(crlDer)` | `CryptoResult<CrlData>` |
| **Verificar cadeia** | `verifyCertificateChain(cert, chain, crls, ocsp?)` | `CryptoResult<ChainVerifyData>` |
| **Verificar OCSP** | `verifyOcsp(certPem, issuerPem, ...)` | `CryptoResult<OcspVerifyData>` |
| **Criar TSR** | `createTimestampRequest(data, hashAlg?, nonce?, policyOid?)` | `CryptoResult<TimestampRequest>` |
| **Parse TST** | `parseTimestampToken(tokenDer)` | `CryptoResult<TimestampResponse>` |
| **Cifrar com pubkey** | `encryptWithPublicKey(data, pubKeyPem, padding?)` | `Uint8List` |
| **Decifrar com privkey** | `decryptWithPrivateKey(data, privKeyPem, padding?)` | `Uint8List` |
| **Envelope digital (cifrar)** | `encryptEnvelope(data, certPem, cipher?)` | `CryptoResult<EnvelopeData>` |
| **Envelope digital (decifrar)** | `decryptEnvelope(envKey, iv, encData, privKeyPem, certPem, cipher?)` | `CryptoResult<Uint8List>` |
| **Obter versao OpenSSL** | `getOpenSSLVersion()` | `String` |
| **Erro OpenSSL** | `getLastError()`, `clearErrors()` | `String` / `void` |

---

## 26. Notas de Versionamento

### Pre-requisitos de Compilacao

| Componente | Versao Minima | Observacao |
|---|---|---|
| **OpenSSL** | 3.2+ | Necessario para ML-KEM (FIPS 203), ML-DSA (FIPS 204), SHA-3 |
| **Dart SDK** | 3.5+ | Sealed classes, pattern matching |
| **Flutter** | 3.24+ | Compatibilidade com Dart 3.5 |
| **dart:ffi** | N/D | Binding nativo obrigatorio |
| **ABI** | `android_arm64`, `android_x64`, `linux_x64`, `windows_x64` | Plataformas suportadas |

### Limitacoes Conhecidas

- **EC Curves**: Somente curvas NIST nomeadas sao suportadas (`prime256v1`, `secp384r1`, `secp521r1`)
- **ML-KEM/ML-DSA**: Requer OpenSSL 3.2+ compilado com provedor OQS; nao disponivel em distribuicoes LTS antigas
- **PKCS#12**: Suporte somente leitura (parse); nao ha metodo `createPkcs12`
- **CRL**: Aceita DER binario; nao suporta CRLs em PEM diretamente
- **OCSP**: Nao inclui nonce automatico; utilizar `createTimestampRequest` para timestamp proprio

### Ciclo de Vida do Contexto

```dart
// O CryptoContext gerencia automaticamente o ciclo de vida OpenSSL:
// 1. Plugin init -> OSSL_PROVIDER_load("default")
// 2. Metodo chamado -> init_context() (ERR_clear_error, etc.)
// 3. Metodo concluido -> destroy_context() (EVP_MD_CTX_free, etc.)
// 4. NUNCA chamar dispose manualmente no contexto
```

---

<div align="center">

**Fim da Documentacao da API**

*Plugin Crypto v3.0 / OpenSSL 3.2+ / Dart 3.5+*

*Documentacao gerada em 2026-06-14*

</div>