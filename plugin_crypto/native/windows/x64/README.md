# Windows x64 native artifact layout

Windows support remains disabled in `pubspec.yaml` until these pinned OpenSSL
4.x artifacts are built and validated:

- `libcrypto-4-x64.dll`
- `libssl-4-x64.dll`
- provider modules and `openssl.cnf` under `providers/`

When support is activated, CMake must copy these files beside the Flutter
executable. Runtime loading deliberately checks that location before sonames.
