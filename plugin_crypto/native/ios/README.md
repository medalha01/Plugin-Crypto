# iOS XCFramework artifact layout

iOS support remains disabled in `pubspec.yaml`. The future
`PluginCryptoOpenSSL.xcframework` must contain pinned OpenSSL 4.x slices for:

- iOS arm64 devices;
- iOS Simulator arm64;
- iOS Simulator x86_64.

Provider modules/configuration and artifact checksums must be recorded beside
the XCFramework before the iOS plugin declaration is enabled.
