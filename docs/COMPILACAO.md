# Guia de Compilação: PluginCrypto

Compilação do PluginCrypto e do app de testes para Linux e Android: requisitos,
estrutura de diretórios nativos, providers OpenSSL, build CMake/Gradle, NDK
cross-compilação, script de reprodutibilidade, troubleshooting e profiling.

---

## 1. Requisitos de Sistema

### 1.1 Software

| Ferramenta | Versão | Onde é usada | Notas |
|---|---|---|---|
| Flutter SDK | ≥ 3.3.0 (3.41.8+) | Build orchestration, `flutter` CLI | Inclui Dart SDK ≥ 3.11.5 |
| Dart SDK | 3.11.5+ | Compilação Dart, análise estática, testes | Gerenciado pelo Flutter |
| Java / JDK | 17 (LTS) | Build Android (Gradle, DEX) | `JAVA_HOME` deve apontar para JDK 17 |
| CMake | ≥ 3.10 (3.28 recomendado) | Build Linux (plugin + testes C++) | Ubuntu: `sudo apt install cmake` |
| Ninja | 1.11+ | Executor de build Linux | Ubuntu: `sudo apt install ninja-build` |
| Clang / GCC | Clang 18 ou GCC 13+ | Compilador C++ (Linux + NDK) | `build-essential` no Ubuntu |
| GTK 3 | 3.x (`libgtk-3-dev`) | Runtime Linux para plugins Flutter | `sudo apt install libgtk-3-dev` |
| pkg-config | system | Resolução de dependências no Linux | Normalmente já instalado |
| Android SDK | 36 (compileSdk) | Alvo de compilação Android | Gerenciado pelo Android Studio ou `sdkmanager` |
| Android NDK | 27.1.12297006 (plugin) / 28.2.13676358 (app) | Cross-compilação nativa Android | Gerenciado pelo Gradle |
| Gradle | 8.x (wrapper Flutter) | Automação de build Android | Não requer instalação manual |
| Kotlin | 2.2.20 | Código de plataforma Android | Gerenciado pelo Gradle |
| Google Test | 1.11.0 | Testes unitários C++ do plugin | Baixado via `FetchContent` no build |
| lcov | 1.16+ | Análise de cobertura de testes | `sudo apt install lcov` (opcional) |
| Bash | 4.x+ | Script `tool/reproduce_all.sh` | Padrão em qualquer Linux |
| `openssl` CLI | qualquer | Testes diferenciais (zone36) | `sudo apt install openssl` (opcional) |
| `adb` | qualquer | Testes Android (deploy + instrumentação) | Android SDK Platform Tools |

### 1.2 Hardware

| Plataforma | Arquitetura | Memória recomendada | Espaço em disco |
|---|---|---|---|
| Linux (dev) | x86_64 | 8 GB | ~5 GB (SDK + builds + .so) |
| Android (target) | arm64-v8a, armeabi-v7a, x86_64 | 4 GB+ | Depende do APK (~15-20 MB) |

### 1.3 Variáveis de Ambiente Obrigatórias

```bash
# Flutter + Dart no PATH
export PATH="$HOME/flutter-sdk/flutter/bin:$PATH"

# Android SDK (exemplo)
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

# Java
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
```

---

## 2. Estrutura de Bibliotecas Nativas

As bibliotecas OpenSSL são **pré-compiladas e incluídas no repositório** (não requerem
OpenSSL instalado no sistema). Cada `.so` é posicionado manualmente conforme as
instruções em `plugin_crypto/native/README.md`.

### 2.1 Linux

```
plugin_crypto/native/linux/x86_64/
├── libcrypto.so.4       # ~7.0 MB  todos os algoritmos (EVP, digest, cipher, PKEY)
├── libcrypto.so         # link simbólico → libcrypto.so.4
├── libssl.so.4          # ~1.3 MB  TLS, CMS, OCSP, CRL, X.509
├── libssl.so            # link simbólico → libssl.so.4
└── providers/
    ├── default.so       # Provider padrão (RSA, EC, AES, SHA-2/3)
    ├── legacy.so        # Algoritmos depreciados (DES, RC4, MD5)
    ├── fips.so          # Provider certificado FIPS 140-3
    └── oqsprovider.so   # Provider pós-quântico (ML-KEM/Kyber, ML-DSA/Dilithium)
```

**Características dos binários Linux:**
- Compilados com `./Configure linux-x86_64` a partir do source `openssl-4.0.0.tar.gz`
- Flags típicas: `-O3 -fPIC -DOPENSSL_USE_NODELETE`
- `SONAME` versionado: `libcrypto.so.4`, `libssl.so.4`
- Links simbólicos permitem carregamento sem versão (`libcrypto.so` → `libcrypto.so.4`)
- Providers são módulos carregáveis (`dlopen`) em runtime

### 2.2 Android

```
plugin_crypto/android/src/main/jniLibs/
├── arm64-v8a/           # Dispositivos 64-bit modernos (maioria dos smartphones)
│   ├── libcrypto.so     # ~3.3 MB
│   └── libssl.so        # ~0.7 MB
├── armeabi-v7a/         # Dispositivos 32-bit legados
│   ├── libcrypto.so     # ~2.4 MB
│   └── libssl.so        # ~0.5 MB
└── x86_64/              # Emuladores Android e dispositivos Intel
    ├── libcrypto.so     # ~3.5 MB
    └── libssl.so        # ~0.8 MB
```

**Características dos binários Android:**
- Convertidos a partir de arquivos estáticos `.a` usando NDK clang (não compilados do source)
- `SONAME` não versionado (apenas `libcrypto.so`, `libssl.so`)
- `minSdk = 29` (Android 10+, API level 29)
- `--whole-archive` usado para forçar exportação de símbolos escondidos
- Gradle auto-inclui `.so` das pastas `jniLibs/` por ABI

---

## 3. Compilação Passo a Passo: Plugin (Linux)

Compilação completa do plugin para Linux x86_64: comandos CMake, flags de
compilador e saídas esperadas.

### 3.1 Pré-requisitos: Instalar Dependências do Sistema

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y \
  cmake ninja-build clang build-essential \
  libgtk-3-dev pkg-config \
  lcov curl unzip

# Verificar versões
cmake --version        # Esperado: cmake version 3.28.x
ninja --version        # Esperado: 1.11.x
clang --version        # Esperado: clang version 18.x
pkg-config --version   # Esperado: 0.29.x
```

### 3.2 Posicionar as Bibliotecas OpenSSL

As `.so` pré-compiladas devem ser copiadas manualmente para o diretório nativo.
Este passo é **obrigatório**. Sem ele, a compilação falha.

```bash
# Certifique-se de que os arquivos existem
ls plugin_crypto/native/linux/x86_64/
# Saída esperada:
#   libcrypto.so    libcrypto.so.4    libssl.so    libssl.so.4    providers/

# Se ausentes, copie do pacote de distribuição:
# cp /caminho/para/openssl-4.0.0-linux-x86_64/libcrypto.so.4 \
#    plugin_crypto/native/linux/x86_64/
# cp /caminho/para/openssl-4.0.0-linux-x86_64/libssl.so.4 \
#    plugin_crypto/native/linux/x86_64/
# cp -r /caminho/para/openssl-4.0.0-linux-x86_64/providers/ \
#    plugin_crypto/native/linux/x86_64/
# cd plugin_crypto/native/linux/x86_64 && \
#   ln -sf libcrypto.so.4 libcrypto.so && \
#   ln -sf libssl.so.4 libssl.so
```

### 3.3 Resolver Dependências Dart

```bash
cd plugin_crypto
flutter pub get
```

**Saída esperada:**
```
Resolving dependencies...
  ffi 2.1.4
  flutter 0.0.0 from sdk flutter
  flutter_lints 6.0.0
  flutter_test 0.0.0 from sdk flutter
  plugin_platform_interface 2.0.2
Got dependencies!
```

### 3.4 Executar a Compilação Linux

```bash
cd plugin_crypto
flutter build linux
```

Este comando único dispara toda a pipeline CMake + Ninja descrita nas subseções abaixo.

### 3.5 O Que Acontece Internamente Durante `flutter build linux`

#### Fase 1: Geração do Sistema de Build (CMake Configure)

O Flutter invoca o CMake com:

```bash
cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DFLUTTER_TARGET_PLATFORM=linux-x64 \
  -S plugin_crypto/linux \
  -B plugin_crypto/build/linux/x64/release
```

**Saída esperada desta fase:**
```
-- The CXX compiler identification is Clang 18.1.3
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/clang++ - skipped
-- Found PkgConfig: /usr/bin/pkg-config
-- Checking for module 'gtk+-3.0'
--   Found gtk+-3.0, version 3.24.41
-- Configuring done
-- Generating done
-- Build files have been written to: plugin_crypto/build/linux/x64/release
```

#### Fase 2: Compilação do Plugin Stub C++ (Ninja Build)

O Ninja compila o arquivo `plugin_crypto/linux/plugin_crypto_plugin.cc` (76 linhas)
com as seguintes flags:

```
-std=c++14 -Wall -Werror -O3 -DNDEBUG -DFLUTTER_PLUGIN_IMPL -fvisibility=hidden
```

**Flags explicadas:**

| Flag | Propósito |
|---|---|
| `-std=c++14` | Padrão C++14 (exigido pelo Flutter) |
| `-Wall` | Todos os warnings do compilador |
| `-Werror` | Warnings são tratados como erros (build falha em qualquer warning) |
| `-O3` | Otimização agressiva (apenas em Release/Profile) |
| `-DNDEBUG` | Desabilita asserts (apenas em Release/Profile) |
| `-DFLUTTER_PLUGIN_IMPL` | Define macro para exportação de símbolos do plugin |
| `-fvisibility=hidden` | Símbolos ocultos por padrão (reduz risco de conflitos) |

**Saída esperada desta fase:**
```
[1/3] Building CXX object CMakeFiles/plugin_crypto_plugin.dir/plugin_crypto_plugin.cc.o
[2/3] Linking CXX shared library libplugin_crypto_plugin.so
[3/3] Build complete
```

#### Fase 3: Vinculação (Linking)

O linker produz `libplugin_crypto_plugin.so` vinculando contra:

- `libflutter_linux_gtk.so`: biblioteca do engine Flutter
- `libgtk-3.so`: GTK 3 (resolvido via `PkgConfig::GTK`)

O `CMakeLists.txt` em `plugin_crypto/linux/CMakeLists.txt:49-55` declara o
`PLUGIN_BUNDLED_LIBRARIES` com caminhos absolutos para as `.so` OpenSSL:

```cmake
set(OPENSSL_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../native/linux/x86_64")
set(PLUGIN_BUNDLED_LIBRARIES
  "${OPENSSL_NATIVE_DIR}/libcrypto.so.4"
  "${OPENSSL_NATIVE_DIR}/libssl.so.4"
  PARENT_SCOPE
)
```

#### Fase 4: Flutter Assemble + Empacotamento

O Flutter então:
1. Compila o código Dart para kernel (debug) ou AOT (release/profile)
2. Coleta `flutter_assets` (imagens, fontes, etc.)
3. Copia dados ICU (`icudtl.dat`)
4. Copia as bibliotecas listadas em `PLUGIN_BUNDLED_LIBRARIES`
5. Aplica `RPATH $ORIGIN/lib` para carregamento relocável

#### Fase 5: Instalação no Bundle

O CMake instala tudo no bundle final:
```
plugin_crypto/build/linux/x64/release/bundle/
├── plugin_crypto               # ELF executável
├── lib/
│   ├── libflutter_linux_gtk.so # Engine Flutter
│   ├── libplugin_crypto_plugin.so  # Plugin stub
│   ├── libcrypto.so.4          # OpenSSL crypto
│   ├── libcrypto.so            # symlink → libcrypto.so.4
│   ├── libssl.so.4             # OpenSSL SSL
│   └── libssl.so               # symlink → libssl.so.4
└── data/
    ├── flutter_assets/         # Assets da aplicação
    └── icudtl.dat              # Dados ICU
```

### 3.6 Verificar o Binário Produzido

```bash
# Confirmar que o binário existe e é executável
file plugin_crypto/build/linux/x64/release/bundle/plugin_crypto
# Saída esperada:
#   ELF 64-bit LSB executable, x86-64, dynamically linked

# Verificar RPATH
readelf -d plugin_crypto/build/linux/x64/release/bundle/plugin_crypto | grep RPATH
# Saída esperada:
#   0x000000000000000f (RPATH)    Library rpath: [$ORIGIN/lib]

# Verificar dependências
ldd plugin_crypto/build/linux/x64/release/bundle/plugin_crypto
# Saída esperada (parcial):
#   libflutter_linux_gtk.so => ./lib/libflutter_linux_gtk.so
#   libcrypto.so.4 => ./lib/libcrypto.so.4
#   libssl.so.4 => ./lib/libssl.so.4
#   libgtk-3.so.0 => /usr/lib/x86_64-linux-gnu/libgtk-3.so.0
```

### 3.7 Executar Testes Unitários do Plugin (Linux)

```bash
cd plugin_crypto

# Configurar LD_LIBRARY_PATH (OBRIGATÓRIO)
export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH

# Testes rápidos (~2 min, 93 testes em 10 zonas + smoke test)
flutter test --reporter compact

# Testes completos incluindo métricas e soak (~30 min)
flutter test --run-skipped --reporter compact

# Testes com cobertura
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
```

**Saída esperada dos testes rápidos:**
```
00:01 +93 ~0 -0: All tests passed!
```

**Por que `LD_LIBRARY_PATH` é obrigatório?** O dynamic linker do Linux (`ld.so`)
precisa encontrar `libcrypto.so.4` e `libssl.so.4` em runtime. Como essas
bibliotecas não estão instaladas no sistema, o caminho deve ser explicitamente
adicionado ao `LD_LIBRARY_PATH`.

---

## 4. Compilação Passo a Passo: Plugin (Android)

### 4.1 Configuração do Gradle no Plugin

O arquivo `plugin_crypto/android/build.gradle.kts` define:

```kotlin
// plugin_crypto/android/build.gradle.kts:29-55
android {
    namespace = "com.tcc.plugin_crypto"
    compileSdk = 36                        // Alvo API 36
    minSdk = 29                            // Android 10+ (API 29)
    ndkVersion = "27.1.12297006"           // NDK para conversão .a → .so
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")    // PluginCryptoPlugin.kt
            jniLibs.srcDirs("src/main/jniLibs") // ← .so files aqui
        }
    }
}
```

**Ponto crítico:** `jniLibs.srcDirs("src/main/jniLibs")` instrui o Gradle a
empacotar automaticamente as `.so` de `jniLibs/{abi}/` no APK. Nenhuma
compilação nativa ocorre durante o build Android, as `.so` são pré-compiladas.

### 4.2 Posicionar as Bibliotecas Android

```bash
# Cada ABI deve conter libcrypto.so e libssl.so
ls plugin_crypto/android/src/main/jniLibs/arm64-v8a/
# Saída esperada:
#   libcrypto.so    libssl.so

ls plugin_crypto/android/src/main/jniLibs/armeabi-v7a/
# Saída esperada:
#   libcrypto.so    libssl.so

ls plugin_crypto/android/src/main/jniLibs/x86_64/
# Saída esperada:
#   libcrypto.so    libssl.so
```

### 4.3 Conversão .a → .so com NDK (Pré-Build Manual)

As bibliotecas Android são produzidas convertendo arquivos estáticos `.a` em
shared objects `.so` usando o NDK clang. Este processo é feito **uma única vez**
e fora do build Gradle.

#### Para arm64-v8a (64-bit ARM):

```bash
NDK=$ANDROID_HOME/ndk/27.1.12297006
CLANG=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
TARGET=aarch64-linux-android29

# libcrypto.so
$CLANG -shared \
  -o libcrypto.so \
  -Wl,--whole-archive libcrypto.a -Wl,--no-whole-archive \
  -target $TARGET

# libssl.so (linka contra libcrypto)
$CLANG -shared \
  -o libssl.so \
  -Wl,--whole-archive libssl.a -Wl,--no-whole-archive \
  -target $TARGET -L. -lcrypto
```

#### Para armeabi-v7a (32-bit ARM):

```bash
TARGET=armv7a-linux-androideabi29

$CLANG -shared \
  -o libcrypto.so \
  -Wl,--whole-archive libcrypto.a -Wl,--no-whole-archive \
  -target $TARGET

$CLANG -shared \
  -o libssl.so \
  -Wl,--whole-archive libssl.a -Wl,--no-whole-archive \
  -target $TARGET -L. -lcrypto
```

#### Para x86_64 (Emuladores):

```bash
TARGET=x86_64-linux-android29

$CLANG -shared \
  -o libcrypto.so \
  -Wl,--whole-archive libcrypto.a -Wl,--no-whole-archive \
  -target $TARGET

$CLANG -shared \
  -o libssl.so \
  -Wl,--whole-archive libssl.a -Wl,--no-whole-archive \
  -target $TARGET -L. -lcrypto
```

**Por que `--whole-archive`?** O OpenSSL compila seus símbolos com
`__attribute__((visibility("hidden")))` nos arquivos `.a`. O flag
`--whole-archive` força o linker a exportar todos os símbolos no `.so`
resultante, tornando-os visíveis para `dart:ffi`.

### 4.4 Build do Plugin (Android)

```bash
cd plugin_crypto
flutter build apk --debug
```

### 4.5 Fases Internas do Build Android

#### Fase 1: Gradle Configuration

O `settings.gradle.kts` (em `tcc_test_app/android/`) lê o caminho do Flutter SDK
do arquivo `local.properties` e carrega o `flutter-plugin-loader`:

```kotlin
// settings.gradle.kts:1-18
pluginManagement {
    val flutterSdkPath = run {
        val properties = java.util.Properties()
        file("local.properties").inputStream().use { properties.load(it) }
        properties.getProperty("flutter.sdk")
            ?: error("flutter.sdk not set in local.properties")
    }
    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")
}
plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
}
```

#### Fase 2: Resolução de Dependências

O Gradle resolve:
- `com.android.application` (AGP 8.11.1)
- `org.jetbrains.kotlin.android` (Kotlin 2.2.20)
- `plugin_crypto` via dependência de caminho (`path: ../plugin_crypto`)
- Android SDK platform 36, build-tools

#### Fase 3: Compilação Kotlin → DEX

O arquivo `PluginCryptoPlugin.kt` (38 linhas, método único `getPlatformVersion()`)
é compilado para bytecode JVM e depois convertido para DEX (Dalvik Executable).

#### Fase 4: Inclusão de jniLibs

O Gradle automaticamente inclui todas as `.so` das pastas `jniLibs/{abi}/` no APK.
A ABI correta (arm64-v8a, armeabi-v7a, x86_64) é selecionada em runtime pelo
Android Package Manager.

#### Fase 5: Compilação Dart → kernel (Debug)

O Flutter compila o código Dart para kernel snapshot (modo debug) ou AOT (release).

#### Fase 6: Empacotamento APK

O APK é montado com:
- `classes.dex`: código Kotlin compilado
- `lib/{abi}/libcrypto.so` + `libssl.so`: bibliotecas nativas
- `flutter_assets/`: assets da aplicação
- `AndroidManifest.xml`: manifesto com permissões e activities

```bash
# APK gerado em:
ls tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk
# Saída esperada:
#   tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk

# Inspecionar conteúdo do APK:
unzip -l tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk | grep '\.so$'
# Saída esperada (parcial):
#   lib/arm64-v8a/libcrypto.so
#   lib/arm64-v8a/libssl.so
#   lib/armeabi-v7a/libcrypto.so
#   lib/armeabi-v7a/libssl.so
#   lib/x86_64/libcrypto.so
#   lib/x86_64/libssl.so
```

---

## 5. Compilação dos Providers OpenSSL

Os providers são **módulos carregáveis** que o OpenSSL carrega em runtime via
`OSSL_PROVIDER_load()`. São compilados separadamente: `default` e `legacy` no
build padrão do OpenSSL 4.0.0, `fips` com `enable-fips`, e `oqsprovider` via
liboqs. Cada provider contém implementações de algoritmos específicos.

### 5.1 Estrutura de Providers

| Provider | Arquivo | Algoritmos |
|---|---|---|
| `default` | `default.so` | RSA, EC (P-256/P-384/P-521), AES-128/256 (CBC, GCM), SHA-256/512, SHA3-256/512, HKDF, PBKDF2 |
| `legacy` | `legacy.so` | DES, 3DES, RC4, MD4, MD5, Blowfish, CAST5, IDEA, SEED |
| `fips` | `fips.so` | Subconjunto certificado FIPS 140-3: AES, SHA-2/3, RSA (≥2048), EC (P-256/P-384/P-521), DRBG, HMAC, KDF |
| `oqsprovider` | `oqsprovider.so` | ML-KEM-512/768/1024 (Kyber), ML-DSA-44/65/87 (Dilithium), p256_mlkem512/768, X25519_mlkem512/768 |

### 5.2 Como os Providers são Compilados

#### Provider default.so e legacy.so

Incluídos no build padrão do OpenSSL 4.0.0:

```bash
./Configure linux-x86_64 \
  --prefix=/opt/openssl-4.0.0 \
  enable-legacy \
  -O3 -fPIC
make -j$(nproc)
make install
```

Os módulos `default.so` e `legacy.so` são gerados em `lib/ossl-modules/`.

#### Provider fips.so

Exige um build **separado** com a flag `enable-fips`:

```bash
./Configure linux-x86_64 \
  --prefix=/opt/openssl-4.0.0-fips \
  enable-fips \
  -O3 -fPIC
make -j$(nproc)
make install
```

O `fips.so` gerado inclui:
- `fipsmodule.cnf`: configuração de integridade HMAC do módulo FIPS
- `fips.module.sources`: lista de fontes para auditoria

**Verificação de integridade FIPS:**
```bash
openssl fipsinstall -out fipsmodule.cnf -module providers/fips.so
# Saída esperada:
#   INSTALL PASSED
```

#### Provider oqsprovider.so (Pós-Quântico)

Compilado separadamente usando liboqs:

```bash
# 1. Compilar liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_USE_OPENSSL=OFF \
  ..
ninja && sudo ninja install

# 2. Compilar oqsprovider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/opt/openssl-4.0.0 \
  -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
  ..
ninja
# oqsprovider.so gerado em lib/
```

### 5.3 Carregamento em Runtime

O código Dart carrega providers sob demanda. O carregamento é feito via FFI:

```dart
// Binding correspondente em openssl_bindings.dart:
// late final OSSL_PROVIDER_load_func OSSL_PROVIDER_load;

// Uso em crypto_api.dart:
final provider = _b.OSSL_PROVIDER_load(nullptr, "oqsprovider");
if (provider == nullptr) {
  // Provider pós-quântico não disponível  algoritmos PQ serão pulados
}
```

Se o `oqsprovider.so` não estiver presente, os testes de algoritmos pós-quânticos
pulam condicionalmente. **É comportamento esperado**.

---

## 6. Compilação: App de Testes (tcc_test_app)

### 6.1 Linux

```bash
cd tcc_test_app
flutter pub get
flutter build linux
```

**Bundle gerado:**
```
tcc_test_app/build/linux/x64/release/bundle/
├── tcc_test_app                  # ELF executável
├── lib/
│   ├── libflutter_linux_gtk.so
│   ├── libplugin_crypto_plugin.so
│   ├── libcrypto.so.4
│   ├── libcrypto.so
│   ├── libssl.so.4
│   └── libssl.so
└── data/
    ├── flutter_assets/
    └── icudtl.dat
```

O `CMakeLists.txt` do app (`tcc_test_app/linux/CMakeLists.txt:17`) define
`RPATH $ORIGIN/lib`, garantindo que o executável encontre as `.so` no
subdiretório `lib/` relativo ao binário.

### 6.2 Android (APK Debug)

```bash
cd tcc_test_app
flutter pub get
flutter build apk --debug
```

**APK gerado:** `tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk`

### 6.3 Android (APK Release)

```bash
cd tcc_test_app
flutter build apk --release
```

**Nota sobre assinatura:** O `build.gradle.kts` do app (`tcc_test_app/android/app/build.gradle.kts:33-38`)
usa `signingConfig = signingConfigs.getByName("debug")` para release. Isso é
apenas para desenvolvimento. Para produção, configure um keystore de release.

### 6.4 Android (App Bundle)

```bash
cd tcc_test_app
flutter build appbundle
```

Gera `build/app/outputs/bundle/release/app-release.aab` para publicação na
Google Play Store.

### 6.5 Executar Testes de Integração

```bash
# Linux
cd tcc_test_app
export LD_LIBRARY_PATH=$PWD/../plugin_crypto/native/linux/x86_64:$LD_LIBRARY_PATH
flutter test integration_test/

# Android (requer dispositivo conectado)
cd tcc_test_app
flutter test integration_test/crypto_integration_test.dart
```

---

## 7. Análise Estática

O arquivo `plugin_crypto/analysis_options.yaml` (227 linhas) configura ~190
regras de lint com modo estrito. Build falha se qualquer regra crítica for
violada.

### 7.1 Configuração do Linter

Trecho relevante do `analysis_options.yaml`:

```yaml
# plugin_crypto/analysis_options.yaml:206-227
analyzer:
  errors:
    missing_return: error
    dead_code: error
    always_declare_return_types: error
    unawaited_futures: error
  language:
    strict-casts: true
    strict-inference: true
    strict-raw-types: true
```

**Regras críticas tratadas como erro (build falha se violadas):**

| Regra | Descrição |
|---|---|
| `missing_return` | Função com tipo de retorno sem `return` explícito |
| `dead_code` | Código inalcançável |
| `always_declare_return_types` | Todo método/função deve declarar tipo de retorno |
| `unawaited_futures` | Future não aguardado (potencial bug de concorrência) |

### 7.2 Execução

```bash
cd plugin_crypto
flutter analyze

# Saída esperada (sem problemas):
# Analyzing plugin_crypto...
# No issues found! (ran in 1.2s)
```

```bash
cd tcc_test_app
flutter analyze

# Saída esperada:
# Analyzing tcc_test_app...
# No issues found! (ran in 0.8s)
```

---

## 8. Script de Reprodutibilidade

O script `tool/reproduce_all.sh` (981 linhas) automatiza a compilação completa
e a execução de todos os testes.

### 8.1 Uso

```bash
cd tool

# Todos os testes (requer dispositivo Android conectado)
./reproduce_all.sh

# Sem Android (apenas Linux)
./reproduce_all.sh --skip-android

# Ajuda
./reproduce_all.sh --help
```

### 8.2 Fases do Script

| Fase | Descrição | Comando interno | Tempo estimado |
|---|---|---|---|
| 1 | Linux unit tests | `flutter test --reporter compact` | ~2 min |
| 2 | Métricas | `flutter test --tags metrics --run-skipped --reporter compact` | ~5 min |
| 3 | Linux integration tests | `flutter test integration_test/ --reporter compact` | ~8 min |
| 4 | Android integration | 8 arquivos de teste no dispositivo conectado | ~15 min |
| 5 | FIPS/PQ tests | `tool/run_fips_tests.sh` | ~10 min |
| 6 | Cobertura | `flutter test --coverage` + `lcov --summary` | ~5 min |

### 8.3 Variáveis de Ambiente Configuradas pelo Script

```bash
# tool/reproduce_all.sh:303-320
export LD_LIBRARY_PATH="plugin_crypto/native/linux/x86_64"
export TCC_METRICS_OUTPUT="plugin_crypto/tcc_metrics_report.json"
export OPENSSL_CONF="plugin_crypto/native/linux/x86_64_fips/providers/openssl.cnf"
```

### 8.4 Relatório Gerado

O script produz um relatório Markdown em:
```
tool/reports/reproducibility_report_YYYYMMDD_HHMMSS.md
```

Conteúdo do relatório:
- Informações do sistema (host, kernel, arquitetura)
- Resultado de cada fase (PASS/FAIL/SKIP) com contagem de testes
- Agregados totais (total de testes, passados, pulados, falhos)
- Lista de arquivos de log por fase
- Status FIPS build e dispositivo Android

---

## 9. Solução de Problemas (Troubleshooting)

Problemas comuns de compilação e execução, com diagnóstico e correção. Nem todo
problema segue o mesmo formato: alguns são diretos, outros exigem verificação
em cadeia.

### Cenário 1: `libcrypto.so.4: cannot open shared object file: No such file or directory`

**Mensagem exata:**
```
Unhandled exception:
Invalid argument(s): Failed to load dynamic library 'libcrypto.so.4':
  libcrypto.so.4: cannot open shared object file: No such file or directory
```

**Causa:** `LD_LIBRARY_PATH` não inclui o diretório nativo. O dynamic linker não
consegue encontrar as `.so` em runtime.

**Solução:**
```bash
export LD_LIBRARY_PATH=$PWD/plugin_crypto/native/linux/x86_64:$LD_LIBRARY_PATH
```

**Verificação:**
```bash
ldconfig -p | grep libcrypto
# Se não listar libcrypto.so.4, confirme que o arquivo existe:
ls -la plugin_crypto/native/linux/x86_64/libcrypto.so.4
```

---

### Cenário 2: `wrong ELF class: ELFCLASS32`

Biblioteca de 32 bits carregada em sistema 64 bits (ou vice-versa). Acontece
quando `.so` da ABI errada é copiada para o diretório nativo.

```bash
# Verificar arquitetura da .so
file plugin_crypto/native/linux/x86_64/libcrypto.so.4
# Deve retornar: ELF 64-bit LSB shared object, x86-64

# Se retornar ELF 32-bit, substitua pela versão x86_64 correta
```

---

### Cenário 3: `Unsupported algorithm: ML-KEM-768`

Provider `oqsprovider.so` não está presente no diretório `providers/` ou falhou
ao carregar.

- Verifique se o arquivo existe: `ls plugin_crypto/native/linux/x86_64/providers/oqsprovider.so`
- Se ausente, copie do build de oqs-provider: `cp /caminho/oqs-provider/build/lib/oqsprovider.so plugin_crypto/native/linux/x86_64/providers/`
- Se o arquivo existe mas o erro persiste, verifique dependências: `ldd plugin_crypto/native/linux/x86_64/providers/oqsprovider.so`; pode faltar `liboqs.so` no `LD_LIBRARY_PATH`
- Se não houver necessidade de algoritmos pós-quânticos, o erro é esperado. Os testes de PQ pulam condicionalmente.

---

### Cenário 4: `minSdk version 29 too low`

Alguma dependência transitiva exige `minSdk` maior que 29.

- Em `tcc_test_app/android/app/build.gradle.kts`, aumente `minSdk`: `minSdk = 31` (ou o valor exigido pela dependência).

---

### Cenário 5: `flutter: command not found`

Flutter SDK não está no `PATH`. Adicione ao `~/.bashrc` ou `~/.zshrc`:

```bash
export PATH="$HOME/flutter-sdk/flutter/bin:$PATH"
```

Recarregue com `source ~/.bashrc` e verifique com `flutter --version`.

---

### Cenário 6: Timeout nos testes (`--run-skipped`)

Testes com tag `slow` ou `soak` excedem o timeout padrão de 2 minutos.

- Aumente o timeout: `flutter test --run-skipped --timeout 5m`
- Para testes específicos com mais tempo: `flutter test --tags metrics --run-skipped --timeout 10m`

---

### Cenário 7: `CMake Error: Could not find a package configuration file for GTK`

`libgtk-3-dev` não está instalado.

- Instale: `sudo apt update && sudo apt install -y libgtk-3-dev pkg-config`
- Verifique: `pkg-config --modversion gtk+-3.0` deve retornar `3.24.x`

---

### Cenário 8: `java.lang.OutOfMemoryError: Java heap space` durante build Android

Memória heap insuficiente para o Gradle Daemon.

- Crie ou edite `gradle.properties` com: `org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=512m`
- Ou via variável de ambiente: `export GRADLE_OPTS="-Xmx4096m"`

---

### Cenário 9: `NDK is not installed` ou `NDK version X not found`

NDK versão 27.1.12297006 não está instalado no Android SDK.

- Via sdkmanager: `$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "ndk;27.1.12297006"`
- Ou via Android Studio: SDK Manager → SDK Tools → NDK (Side by side) → marcar 27.1.12297006

---

### Cenário 10: Falha na conversão `.a` → `.so`: `undefined reference`

**Mensagem exata:**
```
ld.lld: error: undefined reference to 'pthread_create'
ld.lld: error: undefined reference to 'dlopen'
...
clang: error: linker command failed with exit code 1
```

**Causa:** Flags de linking ausentes na conversão NDK.

**Solução:**
```bash
# Adicionar -lc++_shared e demais libs do NDK:
$CLANG -shared \
  -o libcrypto.so \
  -Wl,--whole-archive libcrypto.a -Wl,--no-whole-archive \
  -target aarch64-linux-android29 \
  -lc++_shared -ldl -lm
```

---

### Cenário 11: `APK signature verification failed` ao instalar APK release

APK release não está assinado corretamente. O `build.gradle.kts` usa debug
keystore para release (configuração de desenvolvimento).

**Para desenvolvimento**, use APK debug:
```bash
flutter build apk --debug
adb install build/app/outputs/flutter-apk/app-debug.apk
```

**Para produção**, configure signing de release no `android/app/build.gradle.kts`:
```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file("keystore.jks")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = "upload"
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

---

### Cenário 12: `Cannot find libflutter_linux_gtk.so`

Você está executando o binário fora do bundle. O `RPATH $ORIGIN/lib` resolve as
`.so` relativas ao binário, mas o binário em `intermediates_do_not_run/` não tem
o bundle montado ao lado.

Use o binário do bundle (`./build/linux/x64/release/bundle/tcc_test_app`) ou
`flutter run -d linux`.

---

### Cenário 13: `Symbol not found` ao carregar libcrypto.so no Android

A `.so` não exporta os símbolos necessários. Provavelmente o `--whole-archive`
não foi usado na conversão `.a` → `.so`.

- Verifique os símbolos exportados: `$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm -D libcrypto.so | grep EVP_MD_CTX_new`
  - Deve retornar `000xxxxx T EVP_MD_CTX_new` (T maiúsculo = exportado)
  - Se retornar vazio ou com `t` minúsculo (local), a .so não exporta o símbolo
- Refazer conversão com `--whole-archive`:
  ```bash
  $CLANG -shared \
    -o libcrypto.so \
    -Wl,--whole-archive libcrypto.a -Wl,--no-whole-archive \
    -target aarch64-linux-android29
  ```

---

### Cenário 14: `flutter pub get` falha com conflito de dependências

Incompatibilidade de versão entre dependências declaradas.

- Alinhe as versões no `tcc_test_app/pubspec.yaml`: `ffi: ^2.1.4`
- Execute: `cd tcc_test_app && flutter pub get`

---

### Cenário 15: Provider FIPS falha na verificação de integridade

**Mensagem exata:**
```
fipsinstall: integrity check failed for module providers/fips.so
HMAC mismatch
```

**Causa:** O binário `fips.so` foi modificado após a geração do `fipsmodule.cnf`
ou o arquivo de configuração não corresponde ao binário.

**Solução:**
```bash
# Regenerar o fipsmodule.cnf:
openssl fipsinstall \
  -out providers/fipsmodule.cnf \
  -module providers/fips.so

# Copiar para o diretório do plugin:
cp providers/fipsmodule.cnf \
  plugin_crypto/native/linux/x86_64/providers/
```

---

### Cenário 16: `Incorrect IDE `kotlin` for module 'plugin_crypto'`

O `plugin_crypto/android/build.gradle.kts` está no modo standalone (fora do
contexto do app Flutter). Sempre faça o build a partir do `tcc_test_app`, não
do plugin isoladamente:

```bash
# Correto (a partir do app):
cd tcc_test_app && flutter build apk --debug

# Incorreto (plugin standalone não funciona para APK completo):
cd plugin_crypto && flutter build apk  # ← erro
```

---

## 10. Profiling

Ferramentas e comandos para analisar CPU, memória e tempo de carregamento de
providers no Linux e Android.

### 10.1 Profiling de Performance Dart

```bash
# Build profile (mantém símbolos de debug com otimizações):
cd tcc_test_app
flutter build linux --profile

# Iniciar com observatory:
flutter run -d linux --profile

# No observatory (http://127.0.0.1:XXXXX):
# - Timeline view: CPU profiling, flame chart
# - Allocation view: rastreamento de alocação de memória
```

### 10.2 Profiling de Memória (Dart)

```bash
# Executar com DevTools:
flutter pub global activate devtools
flutter run -d linux --profile
devtools

# No DevTools:
# Memory → Diff snapshots: comparar antes/depois de operações crypto
# Memory → Trace allocations: rastrear alocações por operação
```

### 10.3 Profiling de CPU Nativa (Linux)

```bash
# Usando perf:
perf record -g ./build/linux/x64/release/bundle/tcc_test_app
perf report

# Focar nas chamadas OpenSSL:
perf record -g -e cycles:u --call-graph dwarf \
  ./build/linux/x64/release/bundle/tcc_test_app
perf report --sort=symbol | grep -E 'EVP_|OSSL_|RSA_|AES_'
```

### 10.4 Profiling de Alocação Nativa (Linux)

```bash
# Valgrind  memory leak check:
valgrind --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  ./build/linux/x64/release/bundle/tcc_test_app

# Massif  heap profiling:
valgrind --tool=massif \
  --massif-out-file=massif.out \
  ./build/linux/x64/release/bundle/tcc_test_app
ms_print massif.out
```

### 10.5 Profiling Android (CPU)

```bash
# Iniciar app em modo profile:
cd tcc_test_app
flutter run --profile

# Usar Android Studio Profiler:
# Run → Profile 'app' → CPU Profiler
# Selecionar threads de interesse (Dart, JNI)

# Ou via linha de comando:
adb shell ps | grep tcc_test_app  # obter PID
adb shell simpleperf record -p <PID> -o /data/local/tmp/perf.data
adb pull /data/local/tmp/perf.data
simpleperf report -i perf.data
```

### 10.6 Profiling Android (Memória)

```bash
# Heap dump via adb:
adb shell am dumpheap $(adb shell ps | grep tcc_test_app | awk '{print $2}') \
  /data/local/tmp/heap.hprof
adb pull /data/local/tmp/heap.hprof

# Analisar no Android Studio:
# File → Open → heap.hprof
# Verificar retenção de ByteBuffer, Uint8List, Pointer
```

### 10.7 Profiling de Providers (Tempo de Carregamento)

```bash
# Medir tempo de OSSL_PROVIDER_load():
cd plugin_crypto
export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH

# Teste com métricas habilitadas:
TCC_METRICS_OUTPUT=/tmp/provider_metrics.json \
  flutter test --tags metrics --run-skipped

# Analisar JSON:
python3 -c "
import json
with open('/tmp/provider_metrics.json') as f:
    data = json.load(f)
for k, v in data.items():
    if 'provider' in k.lower() or 'load' in k.lower():
        print(f'{k}: {v}')
"
```

### 10.8 Benchmark de Algoritmos Específicos

```bash
cd plugin_crypto
export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH

# Executar apenas zona de interesse:
flutter test test/zone06_rsa_test.dart --reporter expanded
flutter test test/zone05_aes_gcm_test.dart --reporter expanded

# Para profiling mais granular, usar logging de tempo no código Dart:
# Adicionar temporariamente em crypto_api.dart:
#   final sw = Stopwatch()..start();
#   ... operação crypto ...
#   print('${operation}: ${sw.elapsedMicroseconds}us');
```

---

## 11. CI/CD

Workflows prontos para GitHub Actions e GitLab CI: análise estática, testes
unitários Linux, build Android e script de reprodutibilidade.

### 11.1 GitHub Actions

```yaml
# .github/workflows/test.yml
name: Test PluginCrypto

on: [push, pull_request]

jobs:
  test-linux:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.41.8'

      - name: Install system dependencies
        run: |
          sudo apt update
          sudo apt install -y cmake ninja-build clang \
            libgtk-3-dev pkg-config lcov

      - name: Resolve Dart dependencies
        run: cd plugin_crypto && flutter pub get

      - name: Static analysis
        run: cd plugin_crypto && flutter analyze

      - name: Place OpenSSL libraries
        run: |
          # Copiar .so do cache/artefato para native/linux/x86_64/
          # (assumindo que as .so estão em um artefato ou cache seguro)

      - name: Run unit tests
        run: |
          cd plugin_crypto
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          flutter test --reporter expanded

      - name: Run full tests (nightly only)
        if: github.event_name == 'schedule'
        run: |
          cd plugin_crypto
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          flutter test --run-skipped --reporter expanded

      - name: Generate coverage
        run: |
          cd plugin_crypto
          export LD_LIBRARY_PATH=$PWD/native/linux/x86_64:$LD_LIBRARY_PATH
          flutter test --coverage
          lcov --summary coverage/lcov.info

  build-android:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.41.8'

      - name: Setup Java
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Setup Android SDK
        uses: android-actions/setup-android@v3
        with:
          packages: 'platforms;android-36 ndk;27.1.12297006'

      - name: Build Android APK
        run: |
          cd tcc_test_app
          flutter pub get
          flutter build apk --debug

      - name: Upload APK artifact
        uses: actions/upload-artifact@v4
        with:
          name: app-debug
          path: tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk

  test-full-reproducibility:
    runs-on: ubuntu-24.04
    if: github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.41.8'

      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y cmake ninja-build clang \
            libgtk-3-dev pkg-config lcov

      - name: Run reproducibility script
        run: |
          cd tool
          ./reproduce_all.sh --skip-android

      - name: Upload reproducibility report
        uses: actions/upload-artifact@v4
        with:
          name: reproducibility-report
          path: tool/reports/
```

### 11.2 GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - reproducibility

variables:
  FLUTTER_VERSION: "3.41.8"
  LD_LIBRARY_PATH: "$CI_PROJECT_DIR/plugin_crypto/native/linux/x86_64"

test-linux:
  stage: test
  image: ubuntu:24.04
  before_script:
    - apt update && apt install -y cmake ninja-build clang libgtk-3-dev pkg-config lcov curl unzip git
    - git clone https://github.com/flutter/flutter.git -b stable /opt/flutter
    - export PATH="/opt/flutter/bin:$PATH"
    - cd plugin_crypto && flutter pub get
  script:
    - cd plugin_crypto && flutter analyze
    - cd plugin_crypto && flutter test --reporter expanded

build-android:
  stage: build
  image: ubuntu:24.04
  before_script:
    - apt update && apt install -y openjdk-17-jdk curl unzip git
    - git clone https://github.com/flutter/flutter.git -b stable /opt/flutter
    - export PATH="/opt/flutter/bin:$PATH"
    - export ANDROID_HOME="/opt/android-sdk"
    # Configurar Android SDK + NDK aqui
  script:
    - cd tcc_test_app && flutter pub get
    - cd tcc_test_app && flutter build apk --debug
  artifacts:
    paths:
      - tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk

reproducibility:
  stage: reproducibility
  image: ubuntu:24.04
  only:
    - schedules
  before_script:
    - apt update && apt install -y cmake ninja-build clang libgtk-3-dev pkg-config lcov curl unzip git
    - git clone https://github.com/flutter/flutter.git -b stable /opt/flutter
    - export PATH="/opt/flutter/bin:$PATH"
  script:
    - cd tool && ./reproduce_all.sh --skip-android
  artifacts:
    paths:
      - tool/reports/
```

---

## 12. Estrutura do pubspec.yaml

### 12.1 Plugin (`plugin_crypto/pubspec.yaml`)

```yaml
name: plugin_crypto
version: 0.0.1
environment:
  sdk: ^3.11.5
  flutter: '>=3.3.0'
dependencies:
  flutter: { sdk: flutter }
  platform_interface: ^2.0.2
  ffi: ^2.1.4
dev_dependencies:
  flutter_test: { sdk: flutter }
  flutter_lints: ^6.0.0
  ffigen: ^20.1.1
  coverage: ^1.14.0
  glados: ^1.1.7
flutter:
  plugin:
    platforms:
      android:
        ffiPlugin: true                    # ← FFI plugin
        package: com.tcc.plugin_crypto
        pluginClass: PluginCryptoPlugin
      linux:
        ffiPlugin: true
        pluginClass: PluginCryptoPlugin
```

### 12.2 App de Testes (`tcc_test_app/pubspec.yaml`)

```yaml
name: tcc_test_app
version: 1.0.0+1
environment:
  sdk: ^3.11.5
dependencies:
  flutter: { sdk: flutter }
  cupertino_icons: ^1.0.8
  plugin_crypto:
    path: ../plugin_crypto            # ← dependência local
  ffi: ^2.1.4
dev_dependencies:
  flutter_test: { sdk: flutter }
  flutter_lints: ^6.0.0
  integration_test: { sdk: flutter }
```

---

## 13. Cheat Sheet de Comandos

Comandos de verificação e diagnóstico que complementam o passo a passo.
Comandos de build e teste já documentados nas seções 3–10 não são repetidos aqui.

```bash
# ═══════════════════════════════════════════════════════════════════
# VERIFICAÇÃO DE BINÁRIOS
# ═══════════════════════════════════════════════════════════════════

# Verificar ELF e RPATH
file build/linux/x64/release/bundle/tcc_test_app
readelf -d build/linux/x64/release/bundle/tcc_test_app | grep RPATH

# Listar dependências .so
ldd build/linux/x64/release/bundle/tcc_test_app

# Verificar símbolos exportados em .so
nm -D plugin_crypto/native/linux/x86_64/libcrypto.so.4 | head -30

# Verificar conteúdo do APK
unzip -l tcc_test_app/build/app/outputs/flutter-apk/app-debug.apk | grep '\.so$'

# Logcat Android (filtrar PluginCrypto)
adb logcat | grep -E 'flutter|PluginCrypto|OpenSSL'

# ═══════════════════════════════════════════════════════════════════
# REPRODUTIBILIDADE (atalho rápido)
# ═══════════════════════════════════════════════════════════════════

cd tool
./reproduce_all.sh                     # Completo (requer dispositivo Android)
./reproduce_all.sh --skip-android      # Apenas Linux
./reproduce_all.sh --help              # Ajuda
# Relatório: tool/reports/reproducibility_report_YYYYMMDD_HHMMSS.md
```

---

## 14. Diagrama da Pipeline de Build

Fluxo completo do código fonte até o binário final, com as fases de build
Linux e Android em paralelo.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENTRADA: CÓDIGO FONTE                         │
│                                                                  │
│  plugin_crypto/          tcc_test_app/          OpenSSL .a/.so   │
│  ├── lib/ (Dart)         ├── lib/ (Dart)        (pré-compilado) │
│  ├── linux/ (C++)        ├── linux/ (CMake)                      │
│  └── android/ (Kotlin)   └── android/ (Gradle)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  LINUX BUILD  │  │ ANDROID BUILD │  │  PROVIDERS   │
│               │  │               │  │               │
│ flutter pub   │  │ flutter pub   │  │ default.so    │
│   get         │  │   get         │  │ legacy.so     │
│     │         │  │     │         │  │ fips.so       │
│     ▼         │  │     ▼         │  │ oqsprovider   │
│ cmake config  │  │ Gradle config │  │   .so         │
│     │         │  │     │         │  │               │
│     ▼         │  │     ▼         │  │ Carregados    │
│ ninja build   │  │ Kotlin → DEX  │  │ em runtime    │
│  (C++14, -O3) │  │     │         │  │ via OSSL_     │
│     │         │  │     ▼         │  │ PROVIDER_load │
│     ▼         │  │ jniLibs → APK │  │               │
│ bundle/       │  │     │         │  └──────────────┘
│  ├── bin      │  │     ▼         │
│  ├── lib/     │  │ Flutter AOT   │
│  │   ├── .so  │  │ Dart → kernel │
│  │   └── .so  │  │     │         │
│  └── data/    │  │     ▼         │
│      └── ...  │  │ app-debug.apk │
└──────────────┘  └──────────────┘
```

---

## 15. Referência Rápida de Arquivos de Build

| Arquivo | Localização | Função |
|---|---|---|
| `CMakeLists.txt` | `plugin_crypto/linux/` | Compila o plugin stub C++ (99 linhas) |
| `CMakeLists.txt` | `tcc_test_app/linux/` | Compila o app Linux + bundle (128 linhas) |
| `CMakeLists.txt` | `*/linux/runner/` | Compila o executável runner (26 linhas) |
| `build.gradle.kts` | `plugin_crypto/android/` | Configura plugin Android library (79 linhas) |
| `build.gradle.kts` | `tcc_test_app/android/app/` | Configura app Android (44 linhas) |
| `settings.gradle.kts` | `tcc_test_app/android/` | Gerencia plugins Gradle (26 linhas) |
| `pubspec.yaml` | `plugin_crypto/` | Dependências Dart + metadata Flutter (77 linhas) |
| `pubspec.yaml` | `tcc_test_app/` | Dependências Dart + link local plugin (93 linhas) |
| `analysis_options.yaml` | `plugin_crypto/` | ~190 regras de lint em modo estrito (227 linhas) |
| `native/README.md` | `plugin_crypto/native/` | Instruções de posicionamento das .so (28 linhas) |
| `reproduce_all.sh` | `tool/` | Script de reprodutibilidade completo (981 linhas) |
| `run_fips_tests.sh` | `plugin_crypto/tool/` | Testes FIPS + Pós-Quântico |
| `run_tests_with_coverage.sh` | `plugin_crypto/tool/` | Testes com cobertura lcov (113 linhas) |
| `run_android_tests.sh` | `plugin_crypto/tool/` | Testes de integração Android (39 linhas) |
| `run_android_metrics.sh` | `plugin_crypto/tool/` | Métricas em dispositivo Android (135 linhas) |
