# Guia de Testes: PluginCrypto

> Documentação completa da suíte de **41 zonas de teste**. Cobre cada assertion, fixture,
> padrão de setup/tearDown, execução, tags, tempos, CI/CD completo e guia para escrever novas zonas.
>
> **Idioma:** Português (pt-BR) &middot; **Versão:** 2.0 &middot; **Data:** 2026-06-14

---

## 1. Estrutura da Suíte

```
plugin_crypto/test/
├── zone01_native_loader_test.dart         # Carregamento FFI + versão OpenSSL
├── zone02_hash_test.dart                  # SHA-256, SHA-512, SHA3-256, SHA3-512
├── zone03_random_test.dart                # randomBytes: tamanho, unicidade, entropia
├── zone04_aes_cbc_test.dart               # AES-128/256 CBC: round-trip, padding
├── zone05_aes_gcm_test.dart               # AES-128/256 GCM: encrypt/decrypt, tag, AAD
├── zone06_rsa_test.dart                   # RSA keygen, sign, verify, OAEP encrypt/decrypt
├── zone07_ecdsa_test.dart                 # EC keygen (P-256/384/521), sign, verify
├── zone08_x509_test.dart                  # parseX509Certificate, verifyX509Certificate
├── zone09_cms_test.dart                   # CMS sign + verify
├── zone10_error_handling_test.dart        # Erros: chaves inválidas, buffers vazios, stress
├── zone11_cms_encrypt_decrypt_test.dart   # CMS encrypt + decrypt (EnvelopedData)
├── zone11_deprecation_audit_test.dart     # Auditoria de APIs depreciadas
├── zone12_error_handling_extended_test.dart  # Erros estendidos: edge cases
├── zone13_aes_cbc_edge_test.dart          # AES-CBC: 0 bytes, 1 byte, 1 MB
├── zone14_random_edge_test.dart           # randomBytes: 0, 1, 65536 bytes
├── zone15_hash_boundary_test.dart         # Hash: 0 bytes, 1 byte, 1 MB
├── zone16_rsa_edge_test.dart              # RSA: key sizes limite, plaintext grande
├── zone17_ecdsa_edge_test.dart            # ECDSA: curvas inválidas, cross-key verify
├── zone18_x509_edge_test.dart             # X.509: PEM corrompido, DER truncado
├── zone19_key_creation_flow_test.dart     # Fluxo KeyCreator: RSA, EC, factory
├── zone20_certificate_creation_flow_test.dart  # CertificateBuilder + SelfSignedCertCreator
├── zone21_file_signing_flow_test.dart     # StreamingFileSigner: arquivos, streaming
├── zone22_pq_key_creation_flow_test.dart  # Fluxo PQ: ML-KEM, ML-DSA (condicional)
├── zone23_chain_validation_test.dart      # Cadeia: 2-level, 3-level, expirada, errada
├── zone24_crl_test.dart                   # CRL: parse, verify signature, check revocation
├── zone25_ocsp_test.dart                  # OCSP: build request, verify response
├── zone26_csr_test.dart                   # CSR: generate, fields, SAN
├── zone27_x509_extensions_test.dart       # Extensões: SAN, BC, KU, EKU, CRL DP
├── zone28_cades_test.dart                 # CAdES: signingTime, messageDigest, chain
├── zone29_asn1_test.dart                  # ASN.1: parse DER, tipos universais
├── zone30_property_based_test.dart        # Propriedades (glados): idempotência, round-trip
├── zone31_randomized_fuzzing_test.dart    # Fuzzing: 10.000 casos (SHA, AES, X.509, CMS)
├── zone32_nist_sp800_22_test.dart         # NIST SP 800-22: aleatoriedade estatística
├── zone33_nist_sp800_90b_test.dart        # NIST SP 800-90B: entropia
├── zone34_rsa_timing_test.dart            # Timing RSA: CV, t-test (side-channel)
├── zone35_fips186_4_validation_test.dart  # FIPS 186-4: tamanhos de chave, curvas
├── zone36_differential_cli_test.dart      # Diferencial: Dart vs OpenSSL CLI
├── zone37_soak_test.dart                  # Soak: 4×5 min (hash, AES, keygen, sign)
├── zone38_interop_matrix_test.dart        # Interoperabilidade: combinações algoritmo×tamanho
├── zone39_combinatorial_test.dart         # Combinatorial: exaustivo de parâmetros
└── zone40_public_api_icp_test.dart        # Contrato API pública ICP & Timestamping

Fixtures:
plugin_crypto/test/fixtures/
├── certificates.dart               # Certificados embedados (pem/der) + lazy key pairs
├── certificate_fixtures.dart       # Fixtures programáticas de certificados
├── file_signing_fixtures.dart      # Fixtures para testes de assinatura de arquivos
├── helpers.dart                    # Funções utilitárias: hex(), pem(), api(), randomBytes()
├── key_creation_fixtures.dart      # Fixtures para fluxo KeyCreator
├── pki_fixtures.dart               # Fábrica de hierarquia PKI (3 níveis)
├── pq_key_creation_fixtures.dart   # Fixtures para chaves pós-quânticas (ML-KEM/ML-DSA)
├── shared_pki_factory.dart         # Fábrica PKI com CryptoContext (injeção de dependência)
└── test_vectors.dart               # Vetores de teste determinísticos (NIST CAVP)
```

---

## 2. Padrões de Setup e TearDown

### 2.1 Convenção Geral

Toda zona segue o mesmo layout canônico:

```dart
@TestOn('linux')
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zoneXX', 'Nome descritivo da zona');

  late PluginCryptoAPI api;

  setUpAll(() {
    api = PluginCryptoAPI.instance;
  });

  group('Nome do grupo', () {
    // testes aqui
  });

  m?.endZone();
}
```

**Características do padrão:**

- `@TestOn('linux')`: Restringe execução ao VM Linux (FFI com OpenSSL).
- `MetricsCollector`: Coleta métricas opcionais via `startZone`/`endZone`. Ativado apenas quando `TCC_METRICS_OUTPUT` está definida.
- `setUpAll` com inicialização única do `PluginCryptoAPI.instance` (singleton).
- `setUp`/`tearDown` por teste quando necessário (ex.: limpar estado entre iterações).

### 2.2 Fixtures: Como São Geradas

As fixtures são geradas de **três formas distintas**, dependendo da zona:

| Método | Onde | Como Funciona |
|--------|------|---------------|
| **Embedadas como constantes** | `fixtures/certificates.dart:28-105` | Strings PEM estáticas (`const String testCertPem = '-----BEGIN CERTIFICATE-----...'`) compiladas no binário. Convertidas para `Uint8List` via `pem()` (utf8.encode). |
| **Lazy-initialized via API** | `fixtures/certificates.dart:120-156` | `getTestEcKeyPair()` e `getTestRsaKeyPair()` chamam `api().generateEcKeyPair('prime256v1')` / `api().generateRsaKeyPair(2048)` uma única vez e cacheiam o resultado. |
| **OpenSSL CLI (shell)** | `fixtures/certificates.dart:162-295` | `getTestRsaCertAndKey()` e `getTestEcCert()` executam `openssl req -x509 -newkey` com `Process.runSync()`, escrevem em `/tmp/`, leem de volta e cacheiam. **Não funciona no Android.** |
| **Fábrica PKI programática** | `fixtures/pki_fixtures.dart:73-222` | `PkiFixtureFactory` (injeção via `OpenSslBindings`) cria hierarquias Root CA → Intermediate CA → Leaf EE com `CertificateBuilder`. |
| **Fábrica PKI com CryptoContext** | `fixtures/shared_pki_factory.dart:66-153` | `SharedPkiFactory` usa `CryptoContext` (abstração sobre bindings + operações). Usada por zone23 e testes E2E. |
| **Funções utilitárias** | `fixtures/helpers.dart:24-79` | `hex()`, `pem()`, `api()`, `randomBytes(n)`, `garbageKey()`, `oneMbData()`. Todas stateless e puras. |

### 2.3 Padrão Esperado vs Obtido

**Padrão A: Verificação direta (operações síncronas que retornam valor):**

```dart
test('sha256 produces 32-byte output', () {
  final hash = api.sha256(Uint8List.fromList('hello'.codeUnits));
  expect(hash.length, equals(32));
  expect(hash, isNotEmpty);
});
```

**Padrão B: Pattern match com `CryptoResult` (operações que podem falhar):**

```dart
test('parseCrl returns CryptoFailure for garbage data', () {
  final garbage = Uint8List.fromList(List.generate(256, (i) => i % 256));
  final result = api.parseCrl(garbage);

  switch (result) {
    case CryptoSuccess():
      fail('Expected failure for garbage data');
    case CryptoFailure(:final error):
      expect(error, isA<CrlError>());
      expect(error.message, contains('parse'));
  }
});
```

---

## 3. Catálogo das 41 Zonas de Teste

### Zona 01: Native Loader

**Arquivo:** `zone01_native_loader_test.dart`

**Propósito:** Confere o carregamento FFI das bibliotecas nativas OpenSSL e garante que as versões reportadas são as esperadas.

**O que é testado (5 assertions):**

1. `loadCrypto()` retorna `DynamicLibrary` não-nulo.
2. `loadSsl()` retorna `DynamicLibrary` não-nulo.
3. `OpenSslBindings.create(loadCrypto(), loadSsl())` não lança exceção.
4. Versão OpenSSL reportada contém `"3."` (OpenSSL 3.x).
5. Bindings conseguem acessar funções essenciais (`SSLeay`, `OpenSSL_version_num`).

**Código de exemplo:**

```dart
expect(loadCrypto(), isNotNull);
expect(loadSsl(), isNotNull);
expect(bindings, isNotNull);
expect(version, contains('3.'));
```

**Setup/TearDown:** Sem `setUpAll`. Carregamento direto no corpo dos testes. Sem fixtures externas.

---

### Zona 02: Hash

**Arquivo:** `zone02_hash_test.dart`

**Propósito:** Testa se os algoritmos de hash produzem outputs de tamanho correto e são determinísticos.

**O que é testado:**

1. `sha256`: output 32 bytes, determinístico (mesma entrada → mesmo hash).
2. `sha512`: output 64 bytes, determinístico.
3. `sha3_256`: output 32 bytes, determinístico.
4. `sha3_512`: output 64 bytes, determinístico.
5. Hashes de strings vazias produzem valores conhecidos (NIST test vectors).
6. Hashes de 1 MiB não causam crash.

**Código de exemplo:**

```dart
test('sha256 produces 32-byte deterministic output', () {
  final data = Uint8List.fromList('test'.codeUnits);
  final h1 = api.sha256(data);
  final h2 = api.sha256(data);
  expect(h1.length, equals(32));
  expect(h1, equals(h2));
});
```

**Setup/TearDown:** `PluginCryptoAPI.instance` em `setUpAll`. Sem fixtures. Dados inline.

---

### Zona 03: Random

**Arquivo:** `zone03_random_test.dart`

**Propósito:** Garantir que `randomBytes` produz saída do tamanho solicitado e que chamadas consecutivas geram valores diferentes.

**O que é testado:**

1. `randomBytes(32).length == 32`
2. `randomBytes(64).length == 64`
3. `randomBytes(256).length == 256`
4. Duas chamadas `randomBytes(32)` consecutivas produzem arrays diferentes.
5. `randomBytes(0)` tem comportamento definido (array vazio ou exceção documentada).

**Código de exemplo:**

```dart
test('randomBytes produces unique values', () {
  final a = api.randomBytes(32);
  final b = api.randomBytes(32);
  expect(a, isNot(equals(b)));
});
```

---

### Zona 04: AES-CBC

**Arquivo:** `zone04_aes_cbc_test.dart`

**Propósito:** Round-trip de criptografia simétrica AES-CBC com chaves de 128 e 256 bits.

**O que é testado:**

1. AES-128-CBC: encrypt → decrypt retorna o plaintext original.
2. AES-256-CBC: encrypt → decrypt retorna o plaintext original.
3. Ciphertext é diferente do plaintext (criptografia real).
4. IV aleatório produz ciphertext diferente a cada chamada.
5. Decrypt com chave errada falha.

**Código de exemplo:**

```dart
test('AES-128-CBC round-trip', () {
  final key = api.randomBytes(16);
  final iv = api.randomBytes(16);
  final plaintext = Uint8List.fromList('Mensagem secreta AES'.codeUnits);

  final ciphertext = api.aesEncryptCbc(plaintext, key, iv: iv);
  final decrypted = api.aesDecryptCbc(ciphertext, key, iv: iv);

  expect(ciphertext, isNot(equals(plaintext)));
  expect(decrypted, equals(plaintext));
});
```

**Setup/TearDown:** `api` em `setUpAll`. Chaves e IVs gerados inline com `randomBytes`.

---

### Zona 05: AES-GCM

**Arquivo:** `zone05_aes_gcm_test.dart`

**Propósito:** Round-trip AES-GCM (authenticated encryption) com tag de autenticação e AAD.

**O que é testado:**

1. AES-128-GCM: encrypt → decrypt com tag de 16 bytes.
2. AES-256-GCM: encrypt → decrypt com tag de 16 bytes.
3. AAD (Additional Authenticated Data) é validado no decrypt.
4. Tag corrompida causa falha no decrypt.
5. Ciphertext corrompido causa falha no decrypt.

**Código de exemplo:**

```dart
test('AES-256-GCM round-trip with AAD', () {
  final key = api.randomBytes(32);
  final nonce = api.randomBytes(12);
  final plaintext = Uint8List.fromList('GCM autenticado'.codeUnits);
  final aad = Uint8List.fromList('dados-associados'.codeUnits);

  final encrypted = api.aesEncryptGcm(plaintext, key, nonce: nonce, aad: aad);
  final decrypted = api.aesDecryptGcm(
    encrypted.ciphertext, key,
    nonce: nonce, tag: encrypted.tag, aad: aad,
  );

  expect(decrypted, equals(plaintext));
  expect(encrypted.tag.length, equals(16));
});
```

---

### Zona 06: RSA

**Arquivo:** `zone06_rsa_test.dart`

**Propósito:** Validação completa de operações RSA: geração de chaves, assinatura, verificação, OAEP encrypt/decrypt.

**O que é testado:**

1. `generateRsaKeyPair(2048)` retorna `KeyPair` com PEMs não-vazios.
2. `generateRsaKeyPair(4096)` funciona (chave maior).
3. RSA sign + verify round-trip com SHA-256.
4. RSA sign + verify round-trip com SHA-512.
5. Verificação com chave errada retorna `false`.
6. OAEP encrypt + decrypt round-trip (SHA-256).
7. OAEP com plaintext grande demais falha.

**Código de exemplo:**

```dart
test('RSA verify with wrong key returns false', () {
  final kp1 = api.generateRsaKeyPair(2048);
  final kp2 = api.generateRsaKeyPair(2048);
  final sig = api.rsaSign(Uint8List.fromList('data'.codeUnits), kp1.privateKeyPem);
  expect(api.rsaVerify(Uint8List.fromList('data'.codeUnits), sig, kp2.publicKeyPem), isFalse);
});
```

---

### Zona 07: ECDSA

**Arquivo:** `zone07_ecdsa_test.dart`

**Propósito:** Assinatura e verificação com curvas elípticas (prime256v1, secp384r1, secp521r1).

**O que é testado:**

1. `generateEcKeyPair('prime256v1')` produz chave válida.
2. `generateEcKeyPair('secp384r1')` produz chave válida.
3. `generateEcKeyPair('secp521r1')` produz chave válida.
4. ECDSA sign + verify round-trip para cada curva.
5. Cross-curve verify falha (assinatura P-256 não verifica como P-384).

**Código de exemplo:**

```dart
test('ECDSA P-256 sign and verify', () {
  final kp = api.generateEcKeyPair('prime256v1');
  final data = Uint8List.fromList('mensagem EC'.codeUnits);
  final sig = api.ecSign(data, kp.privateKeyPem);
  expect(api.ecVerify(data, sig, kp.publicKeyPem), isTrue);
});
```

---

### Zona 08: X.509

**Arquivo:** `zone08_x509_test.dart`

**Propósito:** Parsing e verificação de certificados X.509.

**O que é testado:**

1. `parseX509Certificate` retorna campos: `subject`, `issuer`, `notBefore`, `notAfter`.
2. Subject contém `CN=TCC Test Cert`.
3. `notBefore` é antes de `notAfter`.
4. `verifyX509Certificate` com certificado auto-assinado retorna `true`.
5. Certificado PEM sem cabeçalho causa `CryptoFailure`.

**Código de exemplo:**

```dart
test('parseX509Certificate extracts subject fields', () {
  final result = api.parseX509Certificate(testCertBytes);
  expect(result.subject, contains('CN=TCC Test Cert'));
  expect(result.issuer, contains('CN=TCC Test Cert'));
  expect(result.notBefore.isBefore(result.notAfter), isTrue);
});
```

**Fixtures:** `testCertBytes` de `fixtures/certificates.dart:110-111`. Certificado EC auto-assinado embedado como constante PEM.

---

### Zona 09: CMS Sign

**Arquivo:** `zone09_cms_test.dart`

**Propósito:** Assinatura e verificação CMS (Cryptographic Message Syntax) SignedData.

**O que é testado:**

1. `cmsSign` com certificado RSA produz DER não-vazio.
2. `cmsSign` + `cmsVerify` round-trip retorna `true`.
3. CMS sign com chave EC funciona.
4. CMS verify com certificado trusted não-confiável falha.

**Código de exemplo:**

```dart
test('CMS sign and verify round-trip', () {
  final (cert, key) = getTestRsaCertAndKey();
  final data = Uint8List.fromList('dados CMS'.codeUnits);
  final signed = api.cmsSign(data, cert, key);
  expect(signed, isNotEmpty);
  expect(api.cmsVerify(signed, trustedCert: cert), isTrue);
});
```

**Fixtures:** `getTestRsaCertAndKey()` de `certificates.dart:169`. Gera via `openssl req -x509` com `Process.runSync` e cacheia.

---

### Zona 10: Error Handling

**Arquivo:** `zone10_error_handling_test.dart`

**Propósito:** Cobre o cenário onde operações com entradas inválidas retornam `CryptoFailure` em vez de crash nativo.

**O que é testado:**

1. Hash com chave HMAC vazia.
2. AES decrypt com chave de 1 byte (tamanho inválido).
3. RSA sign com chave privada garbage.
4. RSA verify com assinatura vazia.
5. ECDSA com curva inexistente (`'curva-invalida'`).
6. X.509 parse com bytes aleatórios.
7. CMS verify com DER corrompido.
8. Stress básico: 100 chamadas `randomBytes(64)` sem crash.

**Código de exemplo:**

```dart
test('RSA sign with garbage key returns CryptoFailure', () {
  final result = api.rsaSign(
    Uint8List.fromList('data'.codeUnits),
    'CHAVE INVALIDA',
  );
  expect(result, isA<CryptoFailure>());
});
```

---

### Zona 11a: CMS Encrypt/Decrypt

**Arquivo:** `zone11_cms_encrypt_decrypt_test.dart`

**Propósito:** CMS EnvelopedData: criptografar dados com certificado do destinatário e recuperar com chave privada.

**O que é testado:**

1. `cmsEncrypt` com certificado RSA produz DER não-vazio.
2. `cmsEncrypt` + `cmsDecrypt` round-trip recupera plaintext original.
3. CMS decrypt com chave privada errada falha.
4. CMS encrypt com certificado EC funciona.
5. CMS encrypt para múltiplos destinatários (se suportado).

**Código de exemplo:**

```dart
test('CMS encrypt and decrypt round-trip', () {
  final (cert, key) = getTestRsaCertAndKey();
  final data = Uint8List.fromList('dados envelopados'.codeUnits);
  final encrypted = api.cmsEncrypt(data, cert);
  final decrypted = api.cmsDecrypt(encrypted, key, cert);
  expect(decrypted, equals(data));
});
```

**Fixtures:** `getTestRsaCertAndKey()` via CLI OpenSSL (cacheada).

---

### Zona 11b: Deprecation Audit

**Arquivo:** `zone11_deprecation_audit_test.dart`

**Propósito:** Auditoria de APIs depreciadas. Confere se funções `@Deprecated` ainda compilam e funcionam.

**O que é testado:**

1. Levantamento de todos os símbolos `@Deprecated` no código fonte.
2. Cada método depreciado ainda existe e pode ser invocado.
3. Contagem de anotações `@Deprecated` corresponde ao relatório anterior (anti-regressão).
4. Métodos depreciados emitem aviso em modo debug.

---

### Zona 12: Error Handling Extended

**Arquivo:** `zone12_error_handling_extended_test.dart`

**Propósito:** Casos de borda adicionais para tratamento de erros.

**O que é testado:**

1. Hash de `Uint8List(0)` (array vazio) retorna hash válido.
2. AES com plaintext vazio.
3. RSA keygen com tamanho inválido (ex.: 1023 bits, não múltiplo de 8).
4. ECDSA com dados de 1 MiB.
5. CMS com dados vazios.
6. Strings PEM malformadas (falta `-----END`).

---

### Zona 13: AES-CBC Edge

**Arquivo:** `zone13_aes_cbc_edge_test.dart`

**Propósito:** Casos-limite de AES-CBC: tamanhos extremos de plaintext.

**O que é testado:**

1. Plaintext de 0 bytes: encrypt produz ciphertext (padding-only block).
2. Plaintext de 1 byte: round-trip funciona.
3. Plaintext de exatamente 16 bytes (1 bloco): round-trip.
4. Plaintext de 17 bytes (1 bloco + 1 byte): padding PKCS#7.
5. Plaintext de 1 MiB: round-trip sem corrupção.

**Código de exemplo:**

```dart
test('AES-CBC round-trip with 1 MB of random data', () {
  final key = api.randomBytes(32);
  final iv = api.randomBytes(16);
  final plaintext = oneMbData();

  final encrypted = api.aesEncryptCbc(plaintext, key, iv: iv);
  final decrypted = api.aesDecryptCbc(encrypted, key, iv: iv);
  expect(decrypted, equals(plaintext));
});
```

**Fixtures:** `oneMbData()` de `helpers.dart:75-79`. 1 MiB de dados aleatórios cacheados.

---

### Zona 14: Random Edge

**Arquivo:** `zone14_random_edge_test.dart`

**Propósito:** Comportamento de `randomBytes` em tamanhos extremos.

**O que é testado:**

1. `randomBytes(0)`: comportamento definido.
2. `randomBytes(1)`: 1 byte.
3. `randomBytes(65536)`: 64 KiB.
4. Taxa de colisão em 10.000 chamadas de `randomBytes(8)` < 1%.

**Código de exemplo:**

```dart
test('randomBytes with large size succeeds', () {
  final bytes = api.randomBytes(65536);
  expect(bytes.length, equals(65536));
  expect(bytes.any((b) => b != 0), isTrue);
});
```

---

### Zona 15: Hash Boundary

**Arquivo:** `zone15_hash_boundary_test.dart`

**Propósito:** Comportamento de hash com tamanhos de entrada extremos.

**O que é testado:**

1. Hash de 0 bytes: output de tamanho correto para cada algoritmo.
2. Hash de 1 byte.
3. Hash de 1 MiB via streaming ou chunked.
4. SHA-256(1 MiB) determinístico: duas chamadas produzem o mesmo hash.
5. Consistência cross-algorithm: dados iguais produzem hashes de tamanhos diferentes mas todos válidos.

---

### Zona 16: RSA Edge

**Arquivo:** `zone16_rsa_edge_test.dart`

**Propósito:** Comportamento RSA em condições-limite.

**O que é testado:**

1. `generateRsaKeyPair(512)`: chave mínima (insegura, mas deve funcionar).
2. `generateRsaKeyPair(8192)`: chave muito grande (pode ser `slow`-tagged).
3. OAEP encrypt com plaintext no limite máximo.
4. Mensagem maior que o limite OAEP causa `CryptoFailure`.
5. Assinatura com chave de 4096 bits funciona.

**Código de exemplo:**

```dart
test('RSA OAEP fails for plaintext too large', () {
  final kp = api.generateRsaKeyPair(2048);
  final tooBig = api.randomBytes(512); // maior que ~214 bytes máximo
  final result = api.rsaEncryptOaep(tooBig, kp.publicKeyPem);
  expect(result, isA<CryptoFailure>());
});
```

---

### Zona 17: ECDSA Edge

**Arquivo:** `zone17_ecdsa_edge_test.dart`

**Propósito:** Comportamento ECDSA com entradas inválidas e cenários de borda.

**O que é testado:**

1. `generateEcKeyPair` com curva inválida → `CryptoFailure`.
2. EC sign com chave RSA (tipo errado) → `CryptoFailure`.
3. EC verify com assinatura truncada → `CryptoFailure`.
4. Cross-curve: assinar com P-256, verificar com P-384 → `false`.
5. Assinatura DER de tamanho inválido.

---

### Zona 18: X.509 Edge

**Arquivo:** `zone18_x509_edge_test.dart`

**Propósito:** Robustez do parser X.509 com entradas malformadas.

**O que é testado:**

1. PEM sem `-----BEGIN CERTIFICATE-----` → `CryptoFailure`.
2. PEM com cabeçalho mas base64 corrompido → `CryptoFailure`.
3. DER truncado (SEQUENCE incompleta) → `CryptoFailure`.
4. Certificado com `notAfter` no passado → verificação falha.
5. Certificado com `notBefore` no futuro → verificação falha.
6. Certificado auto-assinado com subject ≠ issuer → verificação falha.

**Código de exemplo:**

```dart
test('parseX509Certificate fails on truncated DER', () {
  final truncated = Uint8List.fromList([0x30, 0x82, 0x00]);
  final result = api.parseX509Certificate(truncated);
  expect(result, isA<CryptoFailure>());
});
```

---

### Zona 19: Key Creation Flow

**Arquivo:** `zone19_key_creation_flow_test.dart`

**Propósito:** Teste de integração do fluxo completo de criação de chaves via `KeyCreator`.

**O que é testado:**

1. `KeyCreator` factory cria instância corretamente.
2. `createRsaKeyPair(2048)` retorna `KeyPair` com PEMs válidos.
3. `createEcKeyPair('prime256v1')` retorna `KeyPair` válido.
4. Chave privada PEM contém `BEGIN PRIVATE KEY`.
5. Chave pública PEM contém `BEGIN PUBLIC KEY`.
6. Chaves têm o algoritmo correto nos metadados.
7. `KeyCreator.listAvailableAlgorithms()` inclui RSA e EC.

**Fixtures:** `key_creation_fixtures.dart`. Wrappers que inicializam `KeyCreator` com bindings injetados.

---

### Zona 20: Certificate Creation Flow

**Arquivo:** `zone20_certificate_creation_flow_test.dart`

**Propósito:** Teste do `CertificateBuilder` e `SelfSignedCertCreator`.

**O que é testado:**

1. `CertificateBuilder` com subject, issuer, publicKey, notBefore, notAfter → build DER.
2. Certificado gerado faz parse com `parseX509Certificate`.
3. Certificado auto-assinado verifica com a própria chave pública.
4. `addExtension('keyUsage', 'digitalSignature')` aparece no certificado.
5. `addBasicConstraints(ca: true)` define `CA: TRUE`.
6. Certificado com validade de 1 ano a partir de `now`.

**Código de exemplo:**

```dart
test('CertificateBuilder produces parseable self-signed cert', () {
  final kp = api.generateRsaKeyPair(2048);
  final now = DateTime.now();

  final result = CertificateBuilder(bindings)
      .subjectDn(const DistinguishedName(commonName: 'Test'))
      .issuerDn(const DistinguishedName(commonName: 'Test'))
      .publicKey(kp)
      .notBefore(now)
      .notAfter(now.add(const Duration(days: 365)))
      .signWith(kp)
      .build();

  final cert = (result as CryptoSuccess<Uint8List>).value;
  final parsed = api.parseX509Certificate(cert);
  expect(parsed.subject, contains('CN=Test'));
});
```

**Fixtures:** `certificate_fixtures.dart`. Builders pré-configurados.

---

### Zona 21: File Signing Flow

**Arquivo:** `zone21_file_signing_flow_test.dart`

**Propósito:** `StreamingFileSigner`: assinatura de arquivos com hash progressivo em streaming.

**O que é testado:**

1. Criar arquivo temporário com conteúdo conhecido.
2. `StreamingFileSigner.signFile()` produz assinatura.
3. `StreamingFileSigner.verifyFileSignature()` verifica corretamente.
4. Assinatura de arquivo modificado (1 byte diferente) → verificação falha.
5. Arquivo de 10 MiB: assinatura e verificação em streaming.

**Fixtures:** `file_signing_fixtures.dart`. Helpers para criar arquivos temporários.

---

### Zona 22: PQ Key Creation Flow

**Arquivo:** `zone22_pq_key_creation_flow_test.dart`

**Propósito:** Geração de chaves pós-quânticas (ML-KEM-768, ML-DSA-65), condicional ao provider OQS.

**O que é testado:**

1. Verifica se provider OQS está disponível (`api.isPqAvailable()`).
2. Se disponível: `generateMlKemKeyPair(768)` retorna `KeyPair`.
3. Se disponível: `generateMlDsaKeyPair(65)` retorna `KeyPair`.
4. Se indisponível: operações PQ lançam `UnsupportedError` ou `CryptoFailure`.
5. Tamanhos de chave PQ são muito maiores que RSA/EC equivalentes.

**Setup:** Testes com `skip: isPqAvailable() == false` para pular silenciosamente.

**Fixtures:** `pq_key_creation_fixtures.dart`. Wrappers condicionais.

---

### Zona 23: Chain Validation

**Arquivo:** `zone23_chain_validation_test.dart`

**Propósito:** Validação de cadeias de certificados X.509 (2 níveis, 3 níveis, expirada, ordem errada).

**O que é testado:**

1. Cadeia de 3 níveis válida (Root → Intermediate → Leaf) → verificação OK.
2. Cadeia de 2 níveis (Root → Leaf) → verificação OK.
3. Cadeia com intermediário ausente → falha.
4. Cadeia com intermediário expirado → falha.
5. Cadeia com ordem invertida → falha.
6. Cadeia cross-algorithm (RSA root → EC intermediate → RSA leaf) → OK.
7. Cadeia onde leaf foi assinado por chave errada → falha.

**Código de exemplo:**

```dart
test('3-level chain validates successfully', () {
  final pki = createPkiHierarchy();
  final request = ChainVerificationRequest(
    leafCert: pki.leafDer,
    trustedRoot: pki.rootDer,
    intermediates: [pki.intermediateDer],
  );
  final result = api.verifyCertificateChain(request);
  expect((result as CryptoSuccess<bool>).value, isTrue);
});

test('expired intermediate fails chain validation', () {
  final pki = createExpiredChain();
  final request = ChainVerificationRequest(
    leafCert: pki.leafDer,
    trustedRoot: pki.rootDer,
    intermediates: [pki.intermediateDer],
  );
  final result = api.verifyCertificateChain(request);
  expect((result as CryptoSuccess<bool>).value, isFalse);
});
```

**Fixtures:** `createPkiHierarchy()` de `pki_fixtures.dart:231`. `createExpiredChain()` e `createCrossAlgorithmHierarchy()` em `pki_fixtures.dart:237-377`.

---

### Zona 24: CRL

**Arquivo:** `zone24_crl_test.dart`

**Propósito:** Certificate Revocation List: parsing, verificação de assinatura, consulta de revogação.

**O que é testado:**

1. `parseCrl` em CRL DER válida retorna `CrlInfo` com `lastUpdate`, `nextUpdate`, `issuer`.
2. `parseCrl` em bytes vazios → `CryptoFailure<CrlError>`.
3. `parseCrl` em garbage → `CryptoFailure<CrlError>`.
4. `verifyCrlSignature` com CRL assinada pela CA correta → OK.
5. `verifyCrlSignature` com CA errada → falha.
6. `checkRevocation` com certificado serial na CRL → `isRevoked == true`.
7. `checkRevocation` com certificado não-listado → `CertificateRevocationStatus.notRevoked`.

**Setup:** Cria CA root + certificado leaf, gera CRL via OpenSSL CLI.

**Model types:** `CrlInfo`, `CrlError`, `RevokedCertificate`, `CertificateRevocationStatus`.

---

### Zona 25: OCSP

**Arquivo:** `zone25_ocsp_test.dart`

**Propósito:** Online Certificate Status Protocol: construir request e verificar response.

**O que é testado:**

1. `buildOcspRequest(certBytes, issuerCert)` retorna DER ASN.1 válido.
2. Request para cert serial válido tem tamanho > 0.
3. `verifyOcspResponse` com response OCSP real ou simulado.
4. Response com status `good` → `CertificateStatus.good`.
5. Response com status `revoked` → `CertificateStatus.revoked`.
6. `buildOcspRequest` com cert vazio → `CryptoFailure<OcspError>`.
7. `buildOcspRequest` com issuerCert vazio → `CryptoFailure<OcspError>`.
8. `verifyOcspResponse` com bytes vazios → `CryptoFailure`.

**Model types:** `OcspResponse`, `OcspError`, `CertificateStatus`.

---

### Zona 26: CSR

**Arquivo:** `zone26_csr_test.dart`

**Propósito:** Certificate Signing Request: geração com diferentes parâmetros e curvas.

**O que é testado:**

1. `generateCsr` com RSA-2048 retorna DER + PEM.
2. CSR PEM contém `-----BEGIN CERTIFICATE REQUEST-----`.
3. CSR contém o `commonName` especificado.
4. `generateCsr` com EC prime256v1 funciona.
5. CSR com SAN (Subject Alternative Names) inclui DNS names.
6. `generateCsr` com `commonName` vazio → `CryptoFailure<CsrError>`, mensagem contém `'commonName'`.
7. `generateCsr` com `KeyPair` vazio → `CryptoFailure<CsrError>`.

**Código de exemplo:**

```dart
test('generateCsr with RSA returns valid CsrData', () {
  final result = api.generateCsr(CsrRequest(
    subject: const DistinguishedName(
      commonName: 'csr-api-rsa.example.com',
      organization: 'API Test',
      country: 'BR',
    ),
    subjectKeyPair: rsaKeyPair,
  ));

  switch (result) {
    case CryptoSuccess(:final value):
      expect(value, isA<CsrData>());
      expect(value.derBytes, isNotEmpty);
      expect(value.pemString, contains('-----BEGIN CERTIFICATE REQUEST-----'));
      expect(value.subjectDn, contains('CN=csr-api-rsa.example.com'));
    case CryptoFailure(:final error):
      fail('Expected success but got: ${error.message}');
  }
});
```

**Model types:** `CsrData`, `CsrRequest`, `CsrError`.

---

### Zona 27: X.509 Extensions

**Arquivo:** `zone27_x509_extensions_test.dart`

**Propósito:** Parsing e validação de extensões X.509 v3.

**O que é testado:**

1. Subject Alternative Name (SAN): DNS, IP, email.
2. Basic Constraints: `CA: TRUE`, `pathLenConstraint`.
3. Key Usage: `digitalSignature`, `keyEncipherment`, `keyCertSign`, `cRLSign`.
4. Extended Key Usage: `serverAuth`, `clientAuth`, `codeSigning`.
5. CRL Distribution Points: URI presente e parseável.
6. Authority Key Identifier: corresponde ao Subject Key Identifier do issuer.

**Código de exemplo:**

```dart
test('BasicConstraints CA:TRUE with pathLen:0', () {
  final cert = buildCaCert(pathLen: 0);
  final parsed = api.parseX509Certificate(cert);
  expect(parsed.basicConstraints.isCa, isTrue);
  expect(parsed.basicConstraints.pathLen, equals(0));
});
```

---

### Zona 28: CAdES

**Arquivo:** `zone28_cades_test.dart`

**Propósito:** CAdES-BES (CMS Advanced Electronic Signatures): atributos signed, cadeia de certificados.

**O que é testado:**

1. `cmsSignCades` produz CMS SignedData com atributos CAdES.
2. Atributo `signing-time` presente na assinatura.
3. Atributo `message-digest` corresponde ao hash do conteúdo.
4. Cadeia de certificados embedada (certificate set).
5. `cmsSignCades` com `caCertPem` inclui o certificado da CA.
6. `cmsSignCades` com `intermediates` inclui intermediários.
7. Round-trip: `cmsSignCades` → `cmsVerify` retorna `true`.

**Código de exemplo:**

```dart
test('cmsSignCades round-trip verify via facade', () {
  final data = Uint8List.fromList('CAdES round-trip API'.codeUnits);
  final signed = api.cmsSignCades(data, rsaCertPem, rsaKeyPemBytes);
  final verified = api.cmsVerify(signed, trustedCert: rsaCertPem);
  expect(verified, isTrue);
});
```

---

### Zona 29: ASN.1

**Arquivo:** `zone29_asn1_test.dart`

**Propósito:** Validação do parser ASN.1 DER: tipos universais, estruturas aninhadas.

**O que é testado:**

1. Parse de INTEGER (short form e long form).
2. Parse de OCTET STRING.
3. Parse de OID, ex.: `2.5.4.3` (commonName).
4. Parse de SEQUENCE e SEQUENCE OF.
5. Parse de SET e SET OF.
6. Parse de BOOLEAN, NULL, BIT STRING.
7. Parse de UTF8String, PrintableString, IA5String.
8. Parse de UTCTime e GeneralizedTime.
9. TLV com length definido vs indefinido (0x80).
10. Estrutura aninhada: SEQUENCE contendo SEQUENCE contendo INTEGER.

---

### Zona 30: Property-Based Testing

**Arquivo:** `zone30_property_based_test.dart`

**Propósito:** Testes baseados em propriedades com `glados` (geração aleatória de inputs).

**Propriedades testadas:**

| # | Propriedade | Descrição Formal |
|---|-------------|-----------------|
| P1 | Hash idempotência | `∀ x: sha256(x) == sha256(x)` |
| P2 | Hash resistência a colisão | `∀ x≠y: sha256(x) ≠ sha256(y)` (probabilística) |
| P3 | Random size | `∀ n ∈ [1,65536]: randomBytes(n).length == n` |
| P4 | AES round-trip | `∀ k,iv,x: aesDecrypt(k,iv,aesEncrypt(k,iv,x)) == x` |
| P5 | Sign round-trip | `∀ kp,x: verify(pub(kp), sign(priv(kp), x), x) == true` |
| P6 | Key uniqueness | `generateRsaKeyPair()₁ ≠ generateRsaKeyPair()₂` |

**Código de exemplo:**

```dart
Glados(any.positiveIntegerOrZero, any.uInt8List).test(
  'P4: AES round-trip',
  (keyLength, plaintext) {
    final key = api.randomBytes(max(16, keyLength % 32 + 16));
    final iv = api.randomBytes(16);
    final encrypted = api.aesEncryptCbc(plaintext, key, iv: iv);
    final decrypted = api.aesDecryptCbc(encrypted, key, iv: iv);
    expect(decrypted, equals(plaintext));
  },
);
```

**Tags:** `property`. Tempo: ~30s.

---

### Zona 31: Randomized Fuzzing

**Arquivo:** `zone31_randomized_fuzzing_test.dart`

**Propósito:** Resistência a crashes com 10.000 casos de fuzzing.

**Categorias:**

| Categoria | Casos | Estratégia |
|-----------|-------|------------|
| F1: SHA-256 | 2.000 | Entradas aleatórias de 0 a 2048 bytes |
| F2: SHA-512 | 2.000 | Entradas aleatórias de 0 a 4096 bytes |
| F3: AES-GCM malformed | 2.000 | Ciphertext/IV/tag corrompidos (3 modos) |
| F4: X.509 DER fuzz | 2.000 | Arrays aleatórios como certificados |
| F5: CMS corruption | 2.000 | Bit-flips (1-3 bits) em CMS SignedData válido |

**Critério de sucesso:** Zero crashes nativos. O teste captura exceções via wrapper `_runCase`:

```dart
int _crashes = 0;

void _runCase(String label, void Function() fn) {
  try {
    fn();
  } catch (e) {
    _crashes++;
  }
}

tearDownAll(() {
  expect(_crashes, equals(0),
    reason: '$_crashes native crashes detected during fuzzing');
});
```

**Setup:** `setUpAll` gera par RSA-2048 + certificado auto-assinado via `openssl req -x509`.

**Tags:** `fuzzing`, `slow`. Tempo: ~8 min.

---

### Zona 32: NIST SP 800-22

**Arquivo:** `zone32_nist_sp800_22_test.dart`

**Propósito:** Bateria de testes estatísticos de aleatoriedade do NIST SP 800-22.

**Testes implementados:**

1. **Frequency (Monobit) Test:** Proporção de 1s ~0.5, p > 0.01.
2. **Frequency Test within a Block:** Sub-blocos balanceados.
3. **Runs Test:** Oscilações 0→1 e 1→0 seguem distribuição esperada.
4. **Longest Run of Ones in a Block:** Máximo de 1s consecutivos.
5. **Approximate Entropy Test:** Entropia com template de tamanho m.

**Código de exemplo:**

```dart
test('Frequency (Monobit) Test passes for randomBytes', () {
  final data = api.randomBytes(1024 * 1024); // 1 MiB
  final pValue = frequencyMonobitTest(data);
  expect(pValue, greaterThan(0.01),
    reason: 'p-value $pValue below significance level 0.01');
});
```

**Tags:** `nist`, `statistical`. Tempo: ~2 min.

---

### Zona 33: NIST SP 800-90B

**Arquivo:** `zone33_nist_sp800_90b_test.dart`

**Propósito:** Estimativa de entropia conforme NIST SP 800-90B.

**Testes implementados:**

1. **Most Common Value Estimate:** Entropia via frequência do valor mais comum.
2. **Collision Estimate:** Baseada no número médio de amostras até primeira colisão.
3. **Markov Estimate:** Probabilidades de transição entre estados.
4. **Min-Entropy:** Mínimo excede 7.5 bits/byte.

**Código de exemplo:**

```dart
test('Min-entropy exceeds 7.5 bits per byte', () {
  final samples = List.generate(1000, (_) => api.randomBytes(32));
  final minEntropy = estimateMinEntropy(samples);
  expect(minEntropy, greaterThan(7.5),
    reason: 'Insufficient entropy: $minEntropy bits/byte');
});
```

**Tags:** `nist`, `health`. Tempo: ~1 min.

---

### Zona 34: RSA Timing

**Arquivo:** `zone34_rsa_timing_test.dart`

**Propósito:** Análise de canal lateral: testa se operações RSA não vazam informação por timing.

**O que é testado:**

1. Coleta de N (≥500) amostras de tempo para `rsaSign`.
2. Coeficiente de variação (CV = σ/μ) < 0.5.
3. Teste t de Student (Welch): p > 0.01 entre grupos de mensagens curtas vs longas.
4. Médias dos grupos não divergem significativamente.

**Código de exemplo:**

```dart
test('RSA sign timing has low coefficient of variation', () {
  final timings = <int>[];
  final kp = api.generateRsaKeyPair(2048);
  for (var i = 0; i < 500; i++) {
    final sw = Stopwatch()..start();
    api.rsaSign(api.randomBytes(32), kp.privateKeyPem);
    timings.add(sw.elapsedMicroseconds);
  }
  final mean = timings.reduce((a, b) => a + b) / timings.length;
  final variance = timings
    .map((t) => (t - mean) * (t - mean))
    .reduce((a, b) => a + b) / timings.length;
  final cv = sqrt(variance) / mean;
  expect(cv, lessThan(0.5), reason: 'CV too high: $cv');
});
```

**Tags:** `timing`, `side-channel`. Tempo: ~20s.

---

### Zona 35: FIPS 186-4 Validation

**Arquivo:** `zone35_fips186_4_validation_test.dart`

**Propósito:** Conformidade com FIPS 186-4 (Digital Signature Standard).

**O que é testado:**

1. Tamanhos de chave RSA aprovados: 2048, 3072.
2. Tamanhos NÃO aprovados: < 2048 bits (1024, 512) → rejeitados.
3. Curvas aprovadas: P-256, P-384, P-521.
4. Curvas NÃO aprovadas: P-224, P-192 → rejeitadas.
5. Tamanho mínimo de hash: SHA-256 (SHA-1 rejeitado).
6. DRBG aprovado (CTR_DRBG ou HASH_DRBG).

**Código de exemplo:**

```dart
test('FIPS 186-4: only approved curves are accepted', () {
  expect(() => api.generateEcKeyPair('prime256v1'), returnsNormally);
  expect(() => api.generateEcKeyPair('secp384r1'), returnsNormally);
  expect(() => api.generateEcKeyPair('secp224k1'), throwsA(isA<CryptoFailure>()));
});
```

**Tags:** `fips`, `validation`. Tempo: ~30s.

---

### Zona 36: Differential CLI

**Arquivo:** `zone36_differential_cli_test.dart`

**Propósito:** Teste diferencial: saída da API Dart idêntica à saída do OpenSSL CLI.

**O que é testado:**

1. `sha256` via API == `openssl dgst -sha256 -binary` (hex idêntico).
2. `sha512` via API == `openssl dgst -sha512 -binary`.
3. `randomBytes(N)` mesmo tamanho que `openssl rand N`.
4. Certificado gerado pela API faz parse com `openssl x509 -text`.
5. CMS gerado pela API faz parse com `openssl cms -verify`.

**Código de exemplo:**

```dart
test('SHA-256 matches OpenSSL CLI output', () {
  final data = Uint8List.fromList('test vector'.codeUnits);
  final dartHash = hex(api.sha256(data));
  final cliResult = Process.runSync('openssl', ['dgst', '-sha256', '-binary'],
    input: utf8.decode(data),
  );
  final cliHash = hex(Uint8List.fromList(cliResult.stdout.codeUnits));
  expect(dartHash, equals(cliHash));
});
```

**Tags:** `differential`, `cli`. Tempo: ~15s.

---

### Zona 37: Soak Test

**Arquivo:** `zone37_soak_test.dart`

**Propósito:** Estabilidade sob carga contínua prolongada (4 operações × 5 min = 20 min).

**Etapas:**

| Etapa | Operação | Duração | Métrica |
|-------|----------|---------|---------|
| S1 | SHA-256(1 KiB random) em loop | 5 min | RSS growth < 10 MiB |
| S2 | AES-256-GCM(1 KiB) encrypt + decrypt | 5 min | 100% sucesso, RSS estável |
| S3 | RSA-2048 keygen × 30 iterações | 5 min | Todas geradas, sem growth |
| S4 | RSA-2048 sign(1 KiB) + verify em loop | 5 min | RSS estável, 100% verificação |

**Monitoramento RSS:**

```dart
int _getRssMb() => ProcessInfo.currentRss ~/ (1024 * 1024);

test('S1: SHA-256 soak for 5 minutes', () {
  final deadline = DateTime.now().add(const Duration(minutes: 5));
  final initialRss = _getRssMb();
  var ops = 0;
  while (DateTime.now().isBefore(deadline)) {
    api.sha256(oneMbData());
    ops++;
  }
  final finalRss = _getRssMb();
  expect(finalRss - initialRss, lessThan(10),
    reason: 'RSS grew by ${finalRss - initialRss} MiB after $ops ops');
});
```

**Tags:** `soak`, `slow`. Tempo: ~20 min.

---

### Zona 38: Interop Matrix

**Arquivo:** `zone38_interop_matrix_test.dart`

**Propósito:** Matriz de interoperabilidade: cada combinação algoritmo × tamanho funciona.

**O que é testado:**

1. Todos os hashes × todos os tamanhos de entrada (16B, 1 KiB, 64 KiB).
2. Todas as curvas EC (P-256, P-384, P-521) × sign + verify.
3. Todos os tamanhos RSA (2048, 3072, 4096) × todos os hashes (SHA-256/384/512).
4. AES: todas as combinações AES-{128,256} × {CBC,GCM} × tamanhos.

**Código de exemplo:**

```dart
test('Interop matrix: RSA key sizes × hash algorithms', () {
  for (final keySize in [2048, 3072, 4096]) {
    for (final hash in ['sha256', 'sha384', 'sha512']) {
      final kp = api.generateRsaKeyPair(keySize);
      final data = api.randomBytes(64);
      final sig = api.rsaSign(data, kp.privateKeyPem, hashAlgorithm: hash);
      expect(api.rsaVerify(data, sig, kp.publicKeyPem, hashAlgorithm: hash), isTrue,
        reason: 'Failed: RSA-$keySize × $hash');
    }
  }
});
```

**Tags:** `interop`, `differential`. Tempo: ~45s.

---

### Zona 39: Combinatorial

**Arquivo:** `zone39_combinatorial_test.dart`

**Propósito:** Teste combinatório exaustivo de parâmetros da API pública.

**O que é testado:**

1. Permutações de parâmetros em `generateCsr` (SAN, algoritmos, key types).
2. Combinações de flags em `CertificateBuilder` (isCa × pathLen × keyUsage × extKeyUsage).
3. Combinações em `createTimestampRequest` (hashAlgorithm × nonce × certReq).
4. Combinações inválidas produzem `CryptoFailure` (não crash).

**Tags:** `combinatorial`, `exhaustive`. Tempo: ~30s.

---

### Zona 40: Public API ICP & Timestamping

**Arquivo:** `zone40_public_api_icp_test.dart`

**Propósito:** Teste de contrato da API pública para operações ICP e RFC 3161 Timestamping. Cobre 6 grupos (A-F).

**Grupo A: CAdES-BES via PluginCryptoAPI (4 testes):**

1. `cmsSignCades` retorna DER não-vazio (>100 bytes).
2. Round-trip `cmsSignCades` → `cmsVerify` → `true`.
3. `cmsSignCades` com `caCertPem` embeda o certificado da CA.
4. `cmsSignCades` com `intermediates` (lista de PEMs).

**Grupo B: CRL via PluginCryptoAPI (6 testes):**

1. `parseCrl(Uint8List(0))` → `CryptoFailure<CrlError>`.
2. `parseCrl(garbage 256 bytes)` → `CryptoFailure<CrlError>`.
3. `verifyCrlSignature` com `crlData` vazio → mensagem contém `'crlData'`.
4. `verifyCrlSignature` com `caCert` vazio → mensagem contém `'caCert'`.
5. `checkRevocation` com `certData` vazio → `CryptoFailure`.
6. `checkRevocation` com `crlData` vazio → `CryptoFailure`.

**Grupo C: OCSP via PluginCryptoAPI (6 testes):**

1. `buildOcspRequest(Uint8List(0), validPem)` → `CryptoFailure<OcspError>`.
2. `buildOcspRequest(validPem, Uint8List(0))` → `CryptoFailure`.
3. `buildOcspRequest(garbage, validPem)` → `CryptoFailure`.
4. `verifyOcspResponse(Uint8List(0), validPem)` → mensagem contém `'ocspRespBytes'`.
5. `verifyOcspResponse(der, Uint8List(0))` → mensagem contém `'issuerCert'`.
6. `verifyOcspResponse(garbage, validPem)` → `CryptoFailure`.

**Grupo D: CSR via PluginCryptoAPI (5 testes):**

1. `generateCsr` com RSA: `CsrData` com `derBytes` não-vazio, `pemString` contém `BEGIN CERTIFICATE REQUEST`, `subjectDn` contém CN.
2. `generateCsr` com EC: `subjectDn` contém `CN=csr-api-ec.example.com`.
3. `generateCsr` com DNS SANs: `subjectDn` contém `CN=san-api.local`.
4. `generateCsr` com `commonName: ''` → `CryptoFailure<CsrError>`, mensagem contém `'commonName'`.
5. `generateCsr` com `KeyPair('', '')` vazio → `CryptoFailure<CsrError>`.

**Grupo E: RFC 3161 Timestamping (11 testes):**

1. `createTimestampRequest(data)` → DER começando com `0x30` (SEQUENCE).
2. `createTimestampRequest` com nonce → pacote maior.
3. `createTimestampRequest` com `hashAlgorithm: 'sha512'` → funciona.
4. `createTimestampRequest` com `hashAlgorithm: 'sha384'` → funciona.
5. `createTimestampRequest(Uint8List(0))` → `CryptoFailure`, mensagem `'non-empty'`.
6. `verifyTimestampResponse(Uint8List(0))` → `CryptoFailure`, mensagem `'non-empty'`.
7. `verifyTimestampResponse(garbage)` → `CryptoFailure` ou `isGranted == false`.
8. Round-trip: 2 chamadas `createTimestampRequest` mesma entrada → saída idêntica.
9. `verifyTimestamp(Uint8List(0), data)` → `CryptoFailure`, mensagem `'tokenData'`.
10. `verifyTimestamp(tokenData, Uint8List(0))` → `CryptoFailure`, mensagem `'data'`.
11. `verifyTimestamp(garbage, data)` → `CryptoFailure` ou `value == false`.

**Grupo F: API Public Type Exports (7 testes):**

1. `TimestampResponse` → `isGranted == true`, `statusString == 'Operation Okay'`.
2. `TimestampStatus.values.length == 6` (granted, grantedWithMods, rejection, waiting, revocationWarning, revocationNotification).
3. `TimestampAccuracy(seconds: 1, millis: 500)` → campos corretos, `micros == null`.
4. `CrlInfo` com `revoked` vazio → `issuer == '/CN=Test CA'`.
5. `CertificateRevocationStatus.notRevoked` → `isRevoked == false`, `revocationDate == null`.
6. `CsrData` construtível com PEM, DER, subjectDn.
7. `OcspResponse(status: CertificateStatus.good)` → `status == CertificateStatus.good`.

**Setup:** `PluginCryptoAPI.instance` + `OpenSslBindings.create(loadCrypto(), loadSsl())`. Gera `KeyPair` RSA-2048 + certificado via `CertificateBuilder` para CAdES. Para OCSP gera `validPem`. Para CSR gera `rsaKeyPair` e `ecKeyPair`.

**Imports de model types:**
```dart
import 'package:plugin_crypto/src/crypto/models/csr_data.dart';
import 'package:plugin_crypto/src/crypto/models/crl_data.dart';
import 'package:plugin_crypto/src/crypto/models/ocsp_data.dart';
import 'package:plugin_crypto/src/crypto/models/ts_data.dart';
import 'package:plugin_crypto/src/crypto/models/distinguished_name.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
```

---

## 4. Sistema de Tags

Arquivo `dart_test.yaml` controla o comportamento:

| Tag | Comportamento | Como Executar |
|-----|---------------|---------------|
| `slow` | **Pulado** por padrão | `--tags slow` ou `--run-skipped` |
| `stress` | **Pulado** por padrão | `--tags stress` ou `--run-skipped` |
| `concurrent` | **Pulado** por padrão | `--tags concurrent` ou `--run-skipped` |
| `metrics` | **Pulado** por padrão | `--tags metrics --run-skipped` + `TCC_METRICS_OUTPUT` |

Tags informativas (não causam skip): `fuzzing`, `soak`, `nist`, `statistical`, `health`, `timing`, `side-channel`, `fips`, `validation`, `differential`, `cli`, `interop`, `combinatorial`, `exhaustive`, `property`.

### Zonas com tags especiais:

| Zona | Tags | Tempo Estimado |
|------|------|----------------|
| zone30 | `property` | 30s |
| zone31 | `fuzzing`, **`slow`** | 8 min (10.000 casos) |
| zone32 | `nist`, `statistical` | 2 min |
| zone33 | `nist`, `health` | 1 min |
| zone34 | `timing`, `side-channel` | 20s |
| zone35 | `fips`, `validation` | 30s |
| zone36 | `differential`, `cli` | 15s |
| zone37 | `soak`, **`slow`** | 20 min (4×5 min) |
| zone38 | `interop`, `differential` | 45s |
| zone39 | `combinatorial`, `exhaustive` | 30s |

---

## 5. Execução

### 5.1 Pré-requisitos

```bash
cd plugin_crypto
flutter pub get
```

### 5.2 Modos de execução

```bash
# Rápido (~2 min, sem slow/stress/concurrent/metrics)
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH flutter test

# Completo (~30 min, TODOS os testes)
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH flutter test --run-skipped

# Por zona específica
flutter test test/zone06_rsa_test.dart

# Múltiplas zonas
flutter test test/zone01_native_loader_test.dart test/zone02_hash_test.dart

# Por tag
flutter test --tags slow --run-skipped
flutter test --tags fuzzing --run-skipped

# Métricas (gera JSON)
TCC_METRICS_OUTPUT=/tmp/metrics.json flutter test --tags metrics --run-skipped

# Cobertura
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
```

### 5.3 Testes do `tcc_test_app`

```bash
cd tcc_test_app
flutter pub get
flutter test test/widget_test.dart              # Widget test (~1s)
flutter test integration_test/                  # Requer dispositivo Android
```

---

## 6. Tempos de Execução

| Conjunto | Zonas | Tempo |
|----------|-------|-------|
| Smoke (crítico) | 01, 02, 03, 04, 05, 06, 07 | ~15s |
| Básico (sem slow) | 01-30, 32-36, 38-40 | ~2 min |
| Fuzzing | 31 | ~8 min |
| Soak | 37 | ~20 min |
| **Completo** | Todas (01-40) | **~30 min** |

---

## 7. Variáveis de Ambiente

| Variável | Obrigatória | Propósito |
|----------|-------------|-----------|
| `LD_LIBRARY_PATH` | **Sim** | Incluir `native/linux/x86_64/` para localizar `libcrypto.so.4` e `libssl.so.4` |
| `TCC_METRICS_OUTPUT` | Não | Caminho para relatório JSON de métricas |
| `OPENSSL_CONF` | Não | Configuração OpenSSL (definida por `reproduce_all.sh`) |
| `TCC_PQ_PROVIDER` | Não | Caminho para provider OQS (liboqsprovider.so). Zone22 pula se ausente. |

---

## 8. Configuração `dart_test.yaml`

```yaml
tags:
  slow:
    skip: "Slow test  run with --tags slow to include"
    skip_reason: "Opt-in tag; use --tags slow to execute"
  stress:
    skip: "Stress test  run with --tags stress to include"
    skip_reason: "Opt-in tag; use --tags stress to execute"
  concurrent:
    skip: "Concurrent-sensitive test  run with --tags concurrent to include"
    skip_reason: "Opt-in tag; use --tags concurrent to execute"
  metrics:
    skip: "Metrics collection test  run with --tags metrics --run-skipped to include"

timeout: 2m
platforms: [vm]
reporter: expanded
```

---

## 9. Interpretação de Falhas

| Sintoma | Causa Provável | Ação |
|---------|---------------|------|
| `Error: Can't find '}' to match '{'` | Erro de sintaxe | Corrigir chaves no arquivo |
| `Expected: <0> Actual: <10>` | `expect()` falhou | Verificar lógica do teste |
| `Failed to load libcrypto.so` | `LD_LIBRARY_PATH` errado | `export LD_LIBRARY_PATH=...` |
| `Bad state: PEM_read_bio_X509 failed` | OpenSSL rejeitou entrada | Verificar formato PEM vs DER |
| `Test timed out after 2 minutes` | Operação lenta | `--timeout 5m` ou verificar deadlock |
| `A tag was used that wasn't specified` | Tag informativa sem declaração | Inofensivo  ignorada |
| `Unsupported algorithm (ML-KEM-768)` | Provider OQS ausente | Esperado  zone22 pula |
| `Null check operator used on a null value` | `MetricsCollector.instance` null | Usar `m?.startZone()` |
| `Process.runSync failed` | `openssl` CLI não instalado | `sudo apt-get install openssl` |
| `Platform.isAndroid == true` | Fixture CLI no Android | Usar `getTestRsaKeyPair()` |

---

## 10. CI/CD Completo

### 10.1 Pipeline de Pull Request (fast feedback, < 3 min)

Este pipeline usa a **mesma base** do Nightly (seção 10.2), com as seguintes diferenças:

| Atributo | Nightly (referência) | PR |
|----------|---------------------|-----|
| Gatilho | `schedule` (cron 03:00) + `workflow_dispatch` | `pull_request` + `push` nas branches `main`/`develop` com path filters (`plugin_crypto/**`, `tcc_clean/**`, `.github/workflows/**`) |
| Concurrency |  | Grupo `${{ github.workflow }}-${{ github.ref }}`, `cancel-in-progress: true` |
| Jobs | `test-full`, `audit`, `notify` | `analyze` + `test-fast` |
| `analyze` job |  | `dart analyze --no-fatal-infos` + `dart format --output=none --set-exit-if-changed .` (timeout 5 min) |
| `test-fast` job |  | Depende de `analyze`; timeout 10 min; executa `flutter test` **sem** `--run-skipped` (apenas testes rápidos) |
| Cobertura | Gera lcov + upload Codecov | Não |
| Métricas JSON | Coleta `TCC_METRICS_OUTPUT` | Não |
| Artefatos | Upload sempre (`/tmp/test-output.log`, `/tmp/metrics.json`, `coverage/html/`) | Upload **apenas em falha** (`test/**/*.dart`, `native/build/**/*.log`), retenção 7 dias |
| Auditoria | Job `audit` com `dart pub outdated` + testes de segurança | Não |

O `test-fast` herda todos os passos do `test-full`: checkout@v4, `subosito/flutter-action@v2` (Flutter 3.24.x, cache), `apt-get install openssl libssl-dev`, `build_linux.sh`, `flutter pub get` e `export LD_LIBRARY_PATH`.

### 10.2 Pipeline de Nightly (completa, ~35 min)

```yaml
name: Test PluginCrypto (Nightly)

on:
  schedule:
    - cron: '0 3 * * *'       # 03:00 UTC = 00:00 BRT
  workflow_dispatch:
    inputs:
      run_soak:
        description: 'Run soak tests (zone37, ~20 min)'
        type: boolean
        default: true
      run_fuzzing:
        description: 'Run fuzzing tests (zone31, ~8 min)'
        type: boolean
        default: true

jobs:
  test-full:
    name: Full Test Suite
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.x'
          channel: 'stable'
          cache: true
      - name: Install system dependencies
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq openssl libssl-dev genhtml lcov
      - name: Build native libraries
        working-directory: plugin_crypto/native
        run: |
          chmod +x build_linux.sh
          ./build_linux.sh
      - name: Install Dart dependencies
        working-directory: plugin_crypto
        run: flutter pub get
      - name: Run ALL tests
        working-directory: plugin_crypto
        run: |
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          export TCC_METRICS_OUTPUT=/tmp/metrics.json
          flutter test --run-skipped --reporter expanded --timeout 5m 2>&1 | tee /tmp/test-output.log
      - name: Generate coverage report
        if: success()
        working-directory: plugin_crypto
        run: |
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          flutter test --run-skipped --coverage
          genhtml coverage/lcov.info -o coverage/html
      - name: Upload coverage to Codecov
        if: success()
        uses: codecov/codecov-action@v4
        with:
          files: plugin_crypto/coverage/lcov.info
          flags: plugin_crypto
          name: plugin-crypto-nightly
          fail_ci_if_error: false
      - name: Collect test output log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-output-nightly
          path: /tmp/test-output.log
          retention-days: 14
      - name: Collect metrics JSON
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: metrics-nightly
          path: /tmp/metrics.json
          retention-days: 30
      - name: Collect coverage HTML
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: coverage-nightly
          path: plugin_crypto/coverage/html/
          retention-days: 7

  audit:
    name: Security Audit
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.24.x'
          channel: 'stable'
          cache: true
      - name: Check for known vulnerabilities
        working-directory: plugin_crypto
        run: flutter pub get && dart pub outdated --no-dependency-overrides
      - name: Run security-critical tests
        working-directory: plugin_crypto
        run: |
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          flutter test \
            test/zone31_randomized_fuzzing_test.dart \
            test/zone34_rsa_timing_test.dart \
            test/zone35_fips186_4_validation_test.dart \
            --reporter expanded --timeout 15m

  notify:
    name: Notify Failure
    runs-on: ubuntu-24.04
    needs: [test-full, audit]
    if: failure()
    steps:
      - name: Create issue on test failure
        uses: actions/github-script@v7
        with:
          script: |
            const { owner, repo } = context.repo;
            const runUrl = `https://github.com/${owner}/${repo}/actions/runs/${context.runId}`;
            await github.rest.issues.create({
              owner,
              repo,
              title: `[NIGHTLY] Testes falharam  ${new Date().toISOString().slice(0, 10)}`,
              body: `A suite de testes **nightly** falhou.\n\nDetalhes: ${runUrl}\n\nInvestigar logs de artefato.`,
              labels: ['bug', 'nightly', 'ci'],
            });
```

### 10.3 Pipeline de Release Tag

Usa a **mesma base** do Nightly (seção 10.2), com as seguintes diferenças:

| Atributo | Nightly (referência) | Release |
|----------|---------------------|---------|
| Gatilho | `schedule` (cron 03:00) + `workflow_dispatch` | `push` de tags `v*.*.*` ou `plugin_crypto-v*` |
| Jobs | `test-full`, `audit`, `notify` | Único job `test-release` |
| `test-release` job |  | Herda todos os passos do `test-full` (checkout, flutter-action, deps, build nativo, `flutter pub get`, `LD_LIBRARY_PATH`) + coverage gate |
| Coverage gate |  | `lcov --summary` extrai cobertura de linhas; se < 75%, **falha o pipeline** (`exit 1`) |
| Auditoria | Job `audit` com `dart pub outdated` + testes de segurança | Não |
| Notificação | Cria issue automática em falha | Não |
| Métricas JSON | Coleta `TCC_METRICS_OUTPUT` | Não |
| Artefatos | Upload de log, métricas e coverage HTML | Não (apenas o gate decide) |

O comando de teste é idêntico ao Nightly: `flutter test --run-skipped --coverage --reporter expanded --timeout 5m`. A diferença essencial é o **gate de cobertura mínima de 75%** que barra o release se a métrica não for atingida.

---

## 11. Como Escrever uma Nova Zona de Teste

### 11.1 Convenções de Nomenclatura

- **Arquivo:** `zoneNN_nome_descritivo_test.dart` onde `NN` é o próximo número sequencial (41, 42, ...).
- **Library:** `@TestOn('linux')` obrigatório na linha 1.
- **Função `main`:** Iniciar com `MetricsCollector.instance?.startZone('zoneNN', 'Descricao')` e terminar com `m?.endZone()`.

### 11.2 Template de Arquivo

```dart
@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';

import '../fixtures/helpers.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zoneXX', 'Descricao breve (max 60 chars)');

  late PluginCryptoAPI api;

  setUpAll(() {
    api = PluginCryptoAPI.instance;
  });

  group('Nome do grupo', () {
    test('descricao direta do que o teste confere (caminho feliz)', () {
      // Arrange
      final input = Uint8List.fromList('dados'.codeUnits);

      // Act
      final result = api.algumaOperacao(input);

      // Assert
      expect(result, isNotEmpty);
      expect(result.length, equals(32));
    });

    test('caminho de erro: descricao da condicao de erro', () {
      final garbage = Uint8List.fromList(List.generate(256, (i) => i % 256));
      final result = api.operacaoQuePodeFalhar(garbage);

      switch (result) {
        case CryptoSuccess():
          fail('Esperava CryptoFailure para garbage');
        case CryptoFailure(:final error):
          expect(error, isA<TipoDeErroEsperado>());
          expect(error.message, contains('termo relevante'));
      }
    });
  });

  m?.endZone();
}
```

### 11.3 Checklist de Qualidade

Ao submeter uma nova zona, verifique:

- [ ] **Caminho feliz:** Pelo menos 1 teste para o caso de sucesso principal.
- [ ] **Caminho de erro:** Teste com `Uint8List(0)`, garbage, chaves inválidas.
- [ ] **Caminho de borda:** Teste com tamanhos 0, 1, limite máximo, 1 MiB.
- [ ] **Pattern match correto:** Operações fallíveis usam `CryptoSuccess`/`CryptoFailure`.
- [ ] **Sem dependências de rede:** Usar OCSP/CRL locais ou simulados.
- [ ] **Fixtures isoladas:** Dados em `setUpAll` ou `fixtures/`. NUNCA depender de estado de outra zona.
- [ ] **Tags apropriadas:** Adicionar `slow` se >30s, `stress` se >1000 iterações.
- [ ] **`MetricsCollector` null-safe:** Usar `m?.startZone()` e `m?.endZone()`.
- [ ] **Comentário `///` na library:** Documentar propósito da zona.
- [ ] **`@TestOn('linux')`:** Obrigatório para FFI.
- [ ] **Rodou localmente:** `LD_LIBRARY_PATH=... flutter test test/zoneNN_...dart`

### 11.4 Exemplo: Criando Zona 41: HMAC

**1. Criar arquivo `zone41_hmac_test.dart`:**

```dart
@TestOn('linux')
library;

import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import '../fixtures/helpers.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone41', 'HMAC: SHA-256/512, key sizes, tamper detection');

  late PluginCryptoAPI api;
  setUpAll(() => api = PluginCryptoAPI.instance);

  group('HMAC-SHA-256', () {
    test('produces 32-byte tag', () {
      final key = api.randomBytes(32);
      final data = Uint8List.fromList('mensagem'.codeUnits);
      final hmac = api.hmacSha256(key, data);
      expect(hmac.length, equals(32));
    });

    test('same key+data produces identical HMAC', () {
      final key = api.randomBytes(32);
      final data = Uint8List.fromList('deterministico'.codeUnits);
      expect(api.hmacSha256(key, data), equals(api.hmacSha256(key, data)));
    });

    test('different keys produce different HMACs', () {
      final data = Uint8List.fromList('teste'.codeUnits);
      final h1 = api.hmacSha256(api.randomBytes(32), data);
      final h2 = api.hmacSha256(api.randomBytes(32), data);
      expect(h1, isNot(equals(h2)));
    });

    test('empty key returns CryptoFailure', () {
      final result = api.hmacSha256(Uint8List(0), Uint8List.fromList('x'.codeUnits));
      expect(result, isA<CryptoFailure>());
    });

    test('tampered data produces different HMAC', () {
      final key = api.randomBytes(32);
      final original = Uint8List.fromList('original'.codeUnits);
      final tampered = Uint8List.fromList('tampered'.codeUnits);
      expect(api.hmacSha256(key, original), isNot(equals(api.hmacSha256(key, tampered))));
    });
  });

  m?.endZone();
}
```

**2. Rodar localmente:**
```bash
LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH \
  flutter test test/zone41_hmac_test.dart
```

**3. Atualizar `GUIA_TESTES.md`** (este documento) com a nova entrada de zona.
