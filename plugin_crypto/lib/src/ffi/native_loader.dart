library;

import 'dart:ffi';
import 'dart:io';

final class NativeLibraryLoadException implements Exception {
  final String library;
  final List<String> failures;

  const NativeLibraryLoadException(this.library, this.failures);

  @override
  String toString() =>
      'Unable to load $library. Attempts:\n${failures.map((e) => ' - $e').join('\n')}';
}

List<String> nativeLibraryCandidates(
  String library, {
  required String operatingSystem,
  required String executablePath,
  required String currentDirectory,
  Map<String, String> environment = const {},
}) {
  final executableDirectory = File(executablePath).parent.path;
  final override = environment['PLUGIN_CRYPTO_NATIVE_DIR'];
  final names = switch ((operatingSystem, library)) {
    ('android', 'crypto') => const ['libcrypto.so'],
    ('android', 'ssl') => const ['libssl.so'],
    ('linux', 'crypto') => const ['libcrypto.so.4'],
    ('linux', 'ssl') => const ['libssl.so.4'],
    ('windows', 'crypto') => const ['libcrypto-4-x64.dll'],
    ('windows', 'ssl') => const ['libssl-4-x64.dll'],
    _ => const <String>[],
  };
  final candidates = <String>[];
  for (final name in names) {
    if (override != null && override.isNotEmpty) {
      candidates.add('$override${Platform.pathSeparator}$name');
    }
    candidates.add('$executableDirectory${Platform.pathSeparator}$name');
    if (operatingSystem == 'linux') {
      candidates.add(
        '$currentDirectory${Platform.pathSeparator}native'
        '${Platform.pathSeparator}linux${Platform.pathSeparator}x86_64'
        '${Platform.pathSeparator}$name',
      );
    }
    // Soname lookup is deliberately last and is primarily for Android and
    // development environments with an explicitly configured loader path.
    candidates.add(name);
  }
  return candidates.toSet().toList(growable: false);
}

DynamicLibrary _load(String library) {
  if (Platform.isIOS) return DynamicLibrary.process();
  final candidates = nativeLibraryCandidates(
    library,
    operatingSystem: Platform.operatingSystem,
    executablePath: Platform.resolvedExecutable,
    currentDirectory: Directory.current.path,
    environment: Platform.environment,
  );
  if (candidates.isEmpty) {
    throw UnsupportedError(
      'Platform ${Platform.operatingSystem} is not supported by PluginCrypto.',
    );
  }
  final failures = <String>[];
  for (final candidate in candidates) {
    try {
      return DynamicLibrary.open(candidate);
    } on ArgumentError catch (error) {
      failures.add('$candidate: $error');
    }
  }
  throw NativeLibraryLoadException(library, failures);
}

/// Loads the pinned OpenSSL crypto library for the current platform.
DynamicLibrary loadCrypto() => _load('crypto');

/// Loads the pinned OpenSSL SSL library for the current platform.
DynamicLibrary loadSsl() => _load('ssl');
