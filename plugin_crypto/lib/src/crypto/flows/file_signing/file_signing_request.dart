library;

import 'dart:io';

/// A request to sign a file with a private key.
class FileSigningRequest {
  /// Path to the file to sign.
  final String filePath;

  /// PEM-encoded private key.
  final String privateKeyPem;

  /// Hash algorithm to use (default: 'sha256').
  final String hashAlgorithm;

  /// Optional: chunk size for streaming reads in bytes (default: 65536 = 64 KB).
  final int chunkSize;

  FileSigningRequest({
    required this.filePath,
    required this.privateKeyPem,
    this.hashAlgorithm = 'sha256',
    this.chunkSize = 65536,
  }) {

    if (filePath.isEmpty) {
      throw ArgumentError('filePath must be non-empty');
    }

    if (privateKeyPem.isEmpty) {
      throw ArgumentError('privateKeyPem must be non-empty');
    }

    if (!privateKeyPem.contains('BEGIN') || !privateKeyPem.contains('END')) {
      throw ArgumentError(
        'privateKeyPem must contain valid PEM headers (BEGIN/END)',
      );
    }

    const validHashes = {'sha256', 'sha512', 'sha3_256'};
    if (!validHashes.contains(hashAlgorithm)) {
      throw ArgumentError(
        'Unsupported hash algorithm: "$hashAlgorithm". '
        'Supported: ${validHashes.join(', ')}',
      );
    }

    if (chunkSize < 1024) {
      throw ArgumentError('chunkSize must be >= 1024 bytes, got $chunkSize');
    }
    if (chunkSize > 1048576) {
      throw ArgumentError(
        'chunkSize must be <= 1048576 bytes (1 MiB), got $chunkSize',
      );
    }
  }

  void validateFileExists() {
    if (!File(filePath).existsSync()) {
      throw FileSystemException('File not found', filePath);
    }
  }
}
