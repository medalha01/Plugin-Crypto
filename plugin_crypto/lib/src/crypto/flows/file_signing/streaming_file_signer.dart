library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'dart:io';

import '../../../ffi/openssl_bindings.dart';

import '../../utils/bio_utils.dart';
import '../../utils/openssl_error.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/signing_algorithm.dart';
import 'file_signer.dart';
import 'file_signing_request.dart';

class StreamingFileSigner implements FileSigner {
  final OpenSslBindings _b;

  /// Creates a [StreamingFileSigner] with the given FFI bindings.
  const StreamingFileSigner(this._b);

  @override
  List<SigningAlgorithm> get supportedAlgorithms => const [
    SigningAlgorithm(hash: HashAlgorithm.sha256, keyType: SigningKeyType.rsa),
    SigningAlgorithm(hash: HashAlgorithm.sha256, keyType: SigningKeyType.ec),
    SigningAlgorithm(hash: HashAlgorithm.sha256, keyType: SigningKeyType.ml_dsa),
    SigningAlgorithm(hash: HashAlgorithm.sha512, keyType: SigningKeyType.rsa),
    SigningAlgorithm(hash: HashAlgorithm.sha512, keyType: SigningKeyType.ec),
    SigningAlgorithm(hash: HashAlgorithm.sha512, keyType: SigningKeyType.ml_dsa),
    SigningAlgorithm(hash: HashAlgorithm.sha3_256, keyType: SigningKeyType.rsa),
    SigningAlgorithm(hash: HashAlgorithm.sha3_256, keyType: SigningKeyType.ec),
  ];

  @override
  CryptoResult<Uint8List> sign(FileSigningRequest request) {
    try {
      request.validateFileExists();
    } on FileSystemException catch (e) {
      return CryptoFailure(
        FileSigningError(filePath: request.filePath, reason: e.message),
      );
    }

    if (!request.privateKeyPem.contains('BEGIN') ||
        !request.privateKeyPem.contains('END')) {
      return CryptoFailure(
        FileSigningError(
          filePath: request.filePath,
          reason: 'Invalid private key PEM — missing BEGIN/END markers',
        ),
      );
    }

    final hashAlg = HashAlgorithm.fromName(request.hashAlgorithm);
    final mdPtr = hashAlg != null ? hashAlg.evpMd(_b) : nullptr;

    if (mdPtr == nullptr) {
      return CryptoFailure(
        FileSigningError(
          filePath: request.filePath,
          reason: 'Unsupported hash algorithm: ${request.hashAlgorithm}',
        ),
      );
    }

    final fileUtf8 = request.filePath.toNativeUtf8();
    final modeUtf8 = 'rb'.toNativeUtf8();
    final fileBio = _b.bioNewFile(fileUtf8.cast(), modeUtf8.cast());
    calloc.free(fileUtf8);
    calloc.free(modeUtf8);

    if (fileBio == nullptr) {
      return CryptoFailure(
        FileSigningError(
          filePath: request.filePath,
          reason: 'BIO_new_file failed — file may not exist or be unreadable',
          openSslError: getOpenSslError(_b),
        ),
      );
    }

    try {
      final pkey = _loadPrivateKey(request.privateKeyPem);
      if (pkey == nullptr) {
        return CryptoFailure(
          FileSigningError(
            filePath: request.filePath,
            reason: 'Failed to load private key',
            openSslError: getOpenSslError(_b),
          ),
        );
      }

      try {
        final ctx = _b.evpMdCtxNew();
        if (ctx == nullptr) {
          return CryptoFailure(
            FileSigningError(
              filePath: request.filePath,
              reason: 'EVP_MD_CTX_new returned null',
            ),
          );
        }

        try {
          var initResult = _b.evpDigestSignInit(
            ctx,
            nullptr,
            mdPtr,
            nullptr,
            pkey,
          );
          if (initResult != 1) {
            _b.errClearError();
            initResult = _b.evpDigestSignInit(
              ctx,
              nullptr,
              nullptr,
              nullptr,
              pkey,
            );
          }
          if (initResult != 1) {
            return CryptoFailure(
              FileSigningError(
                filePath: request.filePath,
                reason: 'EVP_DigestSignInit',
                openSslError: getOpenSslError(_b),
              ),
            );
          }

          final chunk = calloc<Uint8>(request.chunkSize);
          try {
            while (true) {
              final n = _b.bioRead(fileBio, chunk.cast(), request.chunkSize);
              if (n < 0) {
                return CryptoFailure(
                  FileSigningError(
                    filePath: request.filePath,
                    reason: 'BIO_read failed during streaming',
                    openSslError: getOpenSslError(_b),
                  ),
                );
              }
              if (n == 0) break; // EOF

              final updateResult = _b.evpDigestSignUpdate(ctx, chunk.cast(), n);
              if (updateResult != 1) {
                return CryptoFailure(
                  FileSigningError(
                    filePath: request.filePath,
                    reason: 'EVP_DigestSignUpdate failed at offset',
                    openSslError: getOpenSslError(_b),
                  ),
                );
              }
            }
          } finally {
            calloc.free(chunk);
          }

          final sigLen = calloc<Size>();
          try {
            final sizeResult = _b.evpDigestSign(
              ctx,
              nullptr,
              sigLen,
              nullptr,
              0,
            );
            if (sizeResult != 1) {
            }

            final len = sigLen.value;
            if (len == 0) {
              return CryptoFailure(
                FileSigningError(
                  filePath: request.filePath,
                  reason: 'EVP_DigestSign returned 0 length',
                  openSslError: getOpenSslError(_b),
                ),
              );
            }

            final sig = calloc<Uint8>(len);
            try {
              sigLen.value = len;
              final signResult = _b.evpDigestSign(ctx, sig, sigLen, nullptr, 0);
              if (signResult != 1) {
                return CryptoFailure(
                  FileSigningError(
                    filePath: request.filePath,
                    reason: 'EVP_DigestSign finalize',
                    openSslError: getOpenSslError(_b),
                  ),
                );
              }

              return CryptoSuccess(
                Uint8List.fromList(sig.asTypedList(sigLen.value)),
              );
            } finally {
              calloc.free(sig);
            }
          } finally {
            calloc.free(sigLen);
          }
        } finally {
          _b.evpMdCtxFree(ctx);
        }
      } finally {
        _b.evpPkeyFree(pkey);
      }
    } finally {
      _b.bioFree(fileBio);
    }
  }


  EVP_PKEY _loadPrivateKey(String pem) {
    final bio = bioFromString(_b, pem);
    if (bio == nullptr) return nullptr;
    final pkey = _b.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
    _b.bioFree(bio);
    return pkey;
  }
}
