# Dormant iOS plugin setup

iOS is intentionally absent from `pubspec.yaml` until a pinned and validated
`PluginCryptoOpenSSL.xcframework` is placed under `Frameworks/`.

Required slices:

- `ios-arm64`;
- `ios-arm64_x86_64-simulator`.

After artifacts exist, create the active podspec from
`plugin_crypto.podspec.template`, enable the iOS platform declaration, and run
device and simulator integration tests before advertising support.
