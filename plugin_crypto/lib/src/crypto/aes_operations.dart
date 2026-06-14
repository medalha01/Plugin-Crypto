library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'crypto_data.dart';
import 'models/crypto_error.dart';
import 'utils/openssl_error.dart';

/// AES symmetric encryption and decryption operations.
class AesOperations {
  final OpenSslBindings _b;

  AesOperations(this._b);


  /// Criptografa AES-128-CBC. [key] deve ter 16 bytes, [iv] deve ter 16 bytes.
  Uint8List aes128CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext) {
    _validateAesInputs(key, 16, iv);
    return _cipherOp(key, iv, plaintext, _b.evpAes128Cbc(), true);
  }

  /// Descriptografa AES-128-CBC.
  Uint8List aes128CbcDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
  ) {
    _validateAesInputs(key, 16, iv);
    return _cipherOp(key, iv, ciphertext, _b.evpAes128Cbc(), false);
  }

  /// Criptografa AES-256-CBC. [key] deve ter 32 bytes, [iv] deve ter 16 bytes.
  Uint8List aes256CbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext) {
    _validateAesInputs(key, 32, iv);
    return _cipherOp(key, iv, plaintext, _b.evpAes256Cbc(), true);
  }

  /// Descriptografa AES-256-CBC.
  Uint8List aes256CbcDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
  ) {
    _validateAesInputs(key, 32, iv);
    return _cipherOp(key, iv, ciphertext, _b.evpAes256Cbc(), false);
  }


  AesGcmResult aes128GcmEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    _validateAesKeyLength(key, 16);
    return _gcmCipherOp(key, iv, plaintext, _b.evpAes128Gcm(), true, aad: aad);
  }

  /// Descriptografa AES-128-GCM. [tag] deve ter 16 bytes.
  Uint8List aes128GcmDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List tag, {
    Uint8List? aad,
  }) {
    _validateAesKeyLength(key, 16);
    return _gcmCipherOp(
      key,
      iv,
      ciphertext,
      _b.evpAes128Gcm(),
      false,
      tag: tag,
      aad: aad,
    ).ciphertext;
  }

  /// Criptografa AES-256-GCM.
  AesGcmResult aes256GcmEncrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    _validateAesKeyLength(key, 32);
    return _gcmCipherOp(key, iv, plaintext, _b.evpAes256Gcm(), true, aad: aad);
  }

  /// Descriptografa AES-256-GCM.
  Uint8List aes256GcmDecrypt(
    Uint8List key,
    Uint8List iv,
    Uint8List ciphertext,
    Uint8List tag, {
    Uint8List? aad,
  }) {
    _validateAesKeyLength(key, 32);
    return _gcmCipherOp(
      key,
      iv,
      ciphertext,
      _b.evpAes256Gcm(),
      false,
      tag: tag,
      aad: aad,
    ).ciphertext;
  }


  /// Validates AES [key] length is [expectedKeyLen] and [iv] length is 16.
  static void _validateAesInputs(
    Uint8List key,
    int expectedKeyLen,
    Uint8List iv,
  ) {
    _validateAesKeyLength(key, expectedKeyLen);
    if (iv.length != 16) {
      throw ArgumentError('IV must be 16 bytes, got ${iv.length}');
    }
  }

  /// Validates only the AES [key] length (GCM allows variable-length IVs).
  static void _validateAesKeyLength(Uint8List key, int expectedKeyLen) {
    if (key.length != expectedKeyLen) {
      throw ArgumentError(
        'Key must be $expectedKeyLen bytes, got ${key.length}',
      );
    }
  }


  Uint8List _cipherOp(
    Uint8List key,
    Uint8List iv,
    Uint8List data,
    Pointer<Void> cipher,
    bool encrypt,
  ) {
    final ctx = _b.evpCipherCtxNew();
    if (ctx == nullptr) _fail('EVP_CIPHER_CTX_new');
    try {
      final kp = calloc<Uint8>(key.length);
      final ivp = calloc<Uint8>(iv.length);
      kp.asTypedList(key.length).setAll(0, key);
      ivp.asTypedList(iv.length).setAll(0, iv);
      try {
        if (encrypt) {
          _check1(
            _b.evpEncryptInitEx(ctx, cipher, nullptr, kp, ivp),
            'EVP_EncryptInit_ex',
          );
        } else {
          _check1(
            _b.evpDecryptInitEx(ctx, cipher, nullptr, kp, ivp),
            'EVP_DecryptInit_ex',
          );
        }

        final blockSize = 16; // AES block size
        final outLen = data.length + blockSize;
        final out = calloc<Uint8>(outLen);
        final written = calloc<Int>();
        try {
          final dp = calloc<Uint8>(data.length);
          try {
            dp.asTypedList(data.length).setAll(0, data);
            if (encrypt) {
              _check1(
                _b.evpEncryptUpdate(ctx, out, written, dp, data.length),
                'EVP_EncryptUpdate',
              );
            } else {
              _check1(
                _b.evpDecryptUpdate(ctx, out, written, dp, data.length),
                'EVP_DecryptUpdate',
              );
            }
            final totalLen = written.value;
            final finalWritten = calloc<Int>();
            try {
              if (encrypt) {
                _check1(
                  _b.evpEncryptFinalEx(
                    ctx,
                    (out + totalLen).cast(),
                    finalWritten,
                  ),
                  'EVP_EncryptFinal_ex',
                );
              } else {
                _check1(
                  _b.evpDecryptFinalEx(
                    ctx,
                    (out + totalLen).cast(),
                    finalWritten,
                  ),
                  'EVP_DecryptFinal_ex',
                );
              }
              return Uint8List.fromList(
                out.asTypedList(totalLen + finalWritten.value),
              );
            } finally {
              calloc.free(finalWritten);
            }
          } finally {
            calloc.free(dp);
          }
        } finally {
          calloc.free(out);
          calloc.free(written);
        }
      } finally {
        calloc.free(kp);
        calloc.free(ivp);
      }
    } finally {
      _b.evpCipherCtxFree(ctx);
    }
  }

  AesGcmResult _gcmCipherOp(
    Uint8List key,
    Uint8List iv,
    Uint8List data,
    Pointer<Void> cipher,
    bool encrypt, {
    Uint8List? tag,
    Uint8List? aad,
  }) {
    final ctx = _b.evpCipherCtxNew();
    if (ctx == nullptr) _fail('EVP_CIPHER_CTX_new');
    try {
      final kp = calloc<Uint8>(key.length);
      final ivp = calloc<Uint8>(iv.length);
      kp.asTypedList(key.length).setAll(0, key);
      ivp.asTypedList(iv.length).setAll(0, iv);
      try {
        if (encrypt) {
          _check1(
            _b.evpEncryptInitEx(ctx, cipher, nullptr, kp, ivp),
            'EVP_EncryptInit_ex(GCM)',
          );
        } else {
          _check1(
            _b.evpDecryptInitEx(ctx, cipher, nullptr, kp, ivp),
            'EVP_DecryptInit_ex(GCM)',
          );
          if (tag != null) {
            if (tag.length != 16) {
              throw ArgumentError(
                'GCM authentication tag must be 16 bytes (128 bits). '
                'Got ${tag.length} bytes. Tags shorter than 16 bytes weaken '
                'security and are rejected by this API.',
              );
            }
            final tp = calloc<Uint8>(tag.length);
            try {
              tp.asTypedList(tag.length).setAll(0, tag);
              _check1(
                _b.evpCipherCtxCtrl(ctx, 17, tag.length, tp.cast()),
                'EVP_CIPHER_CTX_ctrl(SET_TAG)',
              );
            } finally {
              calloc.free(tp);
            }
          }
        }

        if (aad != null && aad.isNotEmpty) {
          final aadP = calloc<Uint8>(aad.length);
          try {
            aadP.asTypedList(aad.length).setAll(0, aad);
            final aadWritten = calloc<Int>();
            try {
              if (encrypt) {
                _b.evpEncryptUpdate(ctx, nullptr, aadWritten, aadP, aad.length);
              } else {
                _b.evpDecryptUpdate(ctx, nullptr, aadWritten, aadP, aad.length);
              }
            } finally {
              calloc.free(aadWritten);
            }
          } finally {
            calloc.free(aadP);
          }
        }

        final outLen = data.length + 16;
        final out = calloc<Uint8>(outLen);
        final written = calloc<Int>();
        try {
          final dp = calloc<Uint8>(data.length);
          try {
            dp.asTypedList(data.length).setAll(0, data);
            if (encrypt) {
              _check1(
                _b.evpEncryptUpdate(ctx, out, written, dp, data.length),
                'EVP_EncryptUpdate(GCM)',
              );
            } else {
              _check1(
                _b.evpDecryptUpdate(ctx, out, written, dp, data.length),
                'EVP_DecryptUpdate(GCM)',
              );
            }
            final totalLen = written.value;
            final finalWritten = calloc<Int>();
            try {
              if (encrypt) {
                _check1(
                  _b.evpEncryptFinalEx(
                    ctx,
                    (out + totalLen).cast(),
                    finalWritten,
                  ),
                  'EVP_EncryptFinal_ex(GCM)',
                );
              } else {
                _check1(
                  _b.evpDecryptFinalEx(
                    ctx,
                    (out + totalLen).cast(),
                    finalWritten,
                  ),
                  'EVP_DecryptFinal_ex(GCM)',
                );
              }
              final resultLen = totalLen + finalWritten.value;

              if (encrypt) {
                final gcmTag = calloc<Uint8>(16);
                try {
                  _check1(
                    _b.evpCipherCtxCtrl(ctx, 16, 16, gcmTag.cast()),
                    'EVP_CIPHER_CTX_ctrl(GET_TAG)',
                  );
                  final tagValue = Uint8List.fromList(gcmTag.asTypedList(16));
                  return AesGcmResult(
                    Uint8List.fromList(out.asTypedList(resultLen)),
                    tagValue,
                  );
                } finally {
                  calloc.free(gcmTag);
                }
              }
              return AesGcmResult(
                Uint8List.fromList(out.asTypedList(resultLen)),
                Uint8List(0),
              );
            } finally {
              calloc.free(finalWritten);
            }
          } finally {
            calloc.free(dp);
          }
        } finally {
          calloc.free(out);
          calloc.free(written);
        }
      } finally {
        calloc.free(kp);
        calloc.free(ivp);
      }
    } finally {
      _b.evpCipherCtxFree(ctx);
    }
  }

  void _check1(int result, String op) {
    if (result != 1) {
      final err = getOpenSslError(_b);
      _b.errClearError();
      if (op == 'EVP_DecryptFinal_ex(GCM)') {
        throw AesGcmAuthFailure(
          reason: 'AES-GCM authentication failed: '
              '${err ?? "ciphertext or tag corrupted"}',
        );
      }
      throw StateError('$op failed${err != null ? ': $err' : ''}');
    }
  }

  Never _fail(String op) {
    final err = getOpenSslError(_b);
    _b.errClearError();
    throw StateError('$op failed${err != null ? ': $err' : ''}');
  }
}
