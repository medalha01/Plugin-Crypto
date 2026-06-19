library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/openssl_bindings.dart';
import 'crypto_data.dart';
import 'utils/bio_utils.dart';
import 'utils/openssl_error.dart';
import 'utils/secret_memory.dart';

/// RSA/EC key generation and sign/verify/encrypt/decrypt operations.
class AsymmetricOperations {
  final OpenSslBindings _b;

  AsymmetricOperations(this._b);


  /// Gera um par de chaves RSA de tamanho [bits] (ex.: 2048, 4096).
  /// Returns PEM-encoded public and private keys.
  KeyPair generateRsaKeyPair(int bits) {
    final ctx = _b.evpPkeyCtxNewId(6, nullptr); // EVP_PKEY_RSA = 6
    if (ctx == nullptr) _fail('EVP_PKEY_CTX_new_id');
    try {
      _check1(_b.evpPkeyKeygenInit(ctx), 'EVP_PKEY_keygen_init');
      _check1(
        _b.evpPkeyCtxSetRsaKeygenBits(ctx, bits),
        'EVP_PKEY_CTX_set_rsa_keygen_bits',
      );
      final ppkey = calloc<EVP_PKEY>();
      try {
        _check1(_b.evpPkeyKeygen(ctx, ppkey), 'EVP_PKEY_keygen');
        return _extractKeyPair(ppkey.value);
      } finally {
        calloc.free(ppkey);
      }
    } finally {
      _b.evpPkeyCtxFree(ctx);
    }
  }


  /// Gera um par de chaves EC para [curveName] (ex.: "prime256v1", "secp384r1").
  KeyPair generateEcKeyPair(String curveName) {
    final curveUtf8 = curveName.toNativeUtf8();
    final nid = _b.objSn2nid(curveUtf8.cast());
    calloc.free(curveUtf8);
    if (nid == 0) _fail('OBJ_sn2nid($curveName)');
    final ctx = _b.evpPkeyCtxNewId(408, nullptr); // EVP_PKEY_EC = 408
    if (ctx == nullptr) _fail('EVP_PKEY_CTX_new_id');
    try {
      _check1(_b.evpPkeyKeygenInit(ctx), 'EVP_PKEY_keygen_init');
      _check1(
        _b.evpPkeyCtxSetEcKeygenCurveNid(ctx, nid),
        'EVP_PKEY_CTX_set_ec_keygen_curve_nid',
      );
      final ppkey = calloc<EVP_PKEY>();
      try {
        _check1(_b.evpPkeyKeygen(ctx, ppkey), 'EVP_PKEY_keygen');
        return _extractKeyPair(ppkey.value);
      } finally {
        calloc.free(ppkey);
      }
    } finally {
      _b.evpPkeyCtxFree(ctx);
    }
  }


  Uint8List sign(
    Uint8List data,
    Uint8List privateKeyPem, {
    String hashAlgorithm = 'sha256',
  }) {
    final pkey = _loadPrivateKey(privateKeyPem);
    try {
      final md = switch (hashAlgorithm) {
        'sha256' => _b.evpSha256(),
        'sha384' => _b.evpSha384(),
        'sha512' => _b.evpSha512(),
        'sha3_256' => _b.evpSha3_256(),
        _ => throw ArgumentError('Unsupported hash: $hashAlgorithm'),
      };

      final ctx = _b.evpMdCtxNew();
      if (ctx == nullptr) _fail('EVP_MD_CTX_new');
      try {
        final initResult = _b.evpDigestSignInit(ctx, nullptr, md, nullptr, pkey);
        if (initResult != 1) {
          _b.errClearError();
          _check1(
            _b.evpDigestSignInit(ctx, nullptr, nullptr, nullptr, pkey),
            'EVP_DigestSignInit(ML-DSA)',
          );
        }
        final sigLen = calloc<Size>();
        try {
          _b.evpDigestSign(ctx, nullptr, sigLen, nullptr, 0);
          final len = sigLen.value;
          if (len == 0) _fail('EVP_DigestSign(length)');
          final sig = calloc<Uint8>(len);
          try {
            sigLen.value = len;
            withSecretBytes(_b, data, (dp) {
              _check1(
                _b.evpDigestSign(ctx, sig, sigLen, dp, data.length),
                'EVP_DigestSign',
              );
            });
            return Uint8List.fromList(sig.asTypedList(sigLen.value));
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
  }

  /// Verifica [signature] de [data] usando uma chave pública (PEM ou DER).
  bool verify(
    Uint8List data,
    Uint8List publicKeyPem,
    Uint8List signature, {
    String hashAlgorithm = 'sha256',
  }) {
    final pkey = _loadPublicKey(publicKeyPem);
    try {
      final md = switch (hashAlgorithm) {
        'sha256' => _b.evpSha256(),
        'sha384' => _b.evpSha384(),
        'sha512' => _b.evpSha512(),
        'sha3_256' => _b.evpSha3_256(),
        _ => throw ArgumentError('Unsupported hash: $hashAlgorithm'),
      };

      final ctx = _b.evpMdCtxNew();
      if (ctx == nullptr) _fail('EVP_MD_CTX_new');
      try {
        final vInitResult = _b.evpDigestVerifyInit(ctx, nullptr, md, nullptr, pkey);
        if (vInitResult != 1) {
          _b.errClearError();
          _check1(
            _b.evpDigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey),
            'EVP_DigestVerifyInit(ML-DSA)',
          );
        }
        return withSecretBytes(_b, data, (dp) {
          final sig = calloc<Uint8>(signature.length);
          try {
            sig.asTypedList(signature.length).setAll(0, signature);
            final result = _b.evpDigestVerify(
              ctx,
              sig,
              signature.length,
              dp,
              data.length,
            );
            return result == 1;
          } finally {
            calloc.free(sig);
          }
        });
      } finally {
        _b.evpMdCtxFree(ctx);
      }
    } finally {
      _b.evpPkeyFree(pkey);
    }
  }


  /// Criptografa RSA-OAEP com SHA-256. [publicKeyPem] is the recipient's
  /// public key in PEM or DER format.
  Uint8List rsaEncrypt(Uint8List publicKeyPem, Uint8List plaintext) {
    final pkey = _loadPublicKey(publicKeyPem);
    try {
      final ctx = _b.evpPkeyCtxNew(pkey, nullptr);
      if (ctx == nullptr) _fail('EVP_PKEY_CTX_new');
      try {
        _check1(_b.evpPkeyEncryptInit(ctx), 'EVP_PKEY_encrypt_init');
        final outLen = calloc<Size>();
        try {
          return withSecretBytes(_b, plaintext, (dp) {
            _b.evpPkeyEncrypt(ctx, nullptr, outLen, dp, plaintext.length);
            final len = outLen.value;
            if (len == 0) _fail('EVP_PKEY_encrypt(size)');
            final out = calloc<Uint8>(len);
            try {
              outLen.value = len;
              _check1(
                _b.evpPkeyEncrypt(ctx, out, outLen, dp, plaintext.length),
                'EVP_PKEY_encrypt',
              );
              return Uint8List.fromList(out.asTypedList(outLen.value));
            } finally {
              _b.opensslCleanse(out.cast(), len);
              calloc.free(out);
            }
          });
        } finally {
          calloc.free(outLen);
        }
      } finally {
        _b.evpPkeyCtxFree(ctx);
      }
    } finally {
      _b.evpPkeyFree(pkey);
    }
  }

  /// Descriptografa RSA-OAEP com SHA-256.
  Uint8List rsaDecrypt(Uint8List privateKeyPem, Uint8List ciphertext) {
    final pkey = _loadPrivateKey(privateKeyPem);
    try {
      final ctx = _b.evpPkeyCtxNew(pkey, nullptr);
      if (ctx == nullptr) _fail('EVP_PKEY_CTX_new');
      try {
        _check1(_b.evpPkeyDecryptInit(ctx), 'EVP_PKEY_decrypt_init');
        final outLen = calloc<Size>();
        try {
          final dp = calloc<Uint8>(ciphertext.length);
          try {
            dp.asTypedList(ciphertext.length).setAll(0, ciphertext);
            _b.evpPkeyDecrypt(ctx, nullptr, outLen, dp, ciphertext.length);
            final len = outLen.value;
            if (len == 0) _fail('EVP_PKEY_decrypt(size)');
            final out = calloc<Uint8>(len);
            try {
              outLen.value = len;
              _check1(
                _b.evpPkeyDecrypt(ctx, out, outLen, dp, ciphertext.length),
                'EVP_PKEY_decrypt',
              );
              return Uint8List.fromList(out.asTypedList(outLen.value));
            } finally {
              _b.opensslCleanse(out.cast(), len);
              calloc.free(out);
            }
          } finally {
            calloc.free(dp);
          }
        } finally {
          calloc.free(outLen);
        }
      } finally {
        _b.evpPkeyCtxFree(ctx);
      }
    } finally {
      _b.evpPkeyFree(pkey);
    }
  }



  ({Uint8List ciphertext, Uint8List sharedSecret}) mlKemEncapsulate(
    Uint8List publicKeyPem,
  ) {
    final pkey = _loadPublicKey(publicKeyPem);
    try {
      final ctx = _b.evpPkeyCtxNew(pkey, nullptr);
      if (ctx == nullptr) _fail('EVP_PKEY_CTX_new');
      try {
        _check1(
          _b.evpPkeyEncapsulateInit(ctx, nullptr),
          'EVP_PKEY_encapsulate_init',
        );
        final ctLen = calloc<Size>();
        final ssLen = calloc<Size>();
        try {
          _b.evpPkeyEncapsulate(ctx, nullptr, ctLen, nullptr, ssLen);
          if (ctLen.value == 0 || ssLen.value == 0) {
            _fail('EVP_PKEY_encapsulate(sizes)');
          }
          final ct = calloc<Uint8>(ctLen.value);
          final ss = calloc<Uint8>(ssLen.value);
          try {
            ctLen.value = ctLen.value;
            ssLen.value = ssLen.value;
            _check1(
              _b.evpPkeyEncapsulate(ctx, ct, ctLen, ss, ssLen),
              'EVP_PKEY_encapsulate',
            );
            return (
              ciphertext: Uint8List.fromList(
                ct.asTypedList(ctLen.value)),
              sharedSecret: Uint8List.fromList(
                ss.asTypedList(ssLen.value)),
            );
          } finally {
            calloc.free(ct);
            calloc.free(ss);
          }
        } finally {
          calloc.free(ctLen);
          calloc.free(ssLen);
        }
      } finally {
        _b.evpPkeyCtxFree(ctx);
      }
    } finally {
      _b.evpPkeyFree(pkey);
    }
  }

  /// ML-KEM (FIPS 203) decapsulation — recovers the shared secret from
  /// [ciphertext] using [privateKeyPem].
  Uint8List mlKemDecapsulate(
    Uint8List privateKeyPem,
    Uint8List ciphertext,
  ) {
    final pkey = _loadPrivateKey(privateKeyPem);
    try {
      final ctx = _b.evpPkeyCtxNew(pkey, nullptr);
      if (ctx == nullptr) _fail('EVP_PKEY_CTX_new');
      try {
        _check1(
          _b.evpPkeyDecapsulateInit(ctx, nullptr),
          'EVP_PKEY_decapsulate_init',
        );
        final ssLen = calloc<Size>();
        try {
          final ct = calloc<Uint8>(ciphertext.length);
          try {
            ct.asTypedList(ciphertext.length).setAll(0, ciphertext);
            _b.evpPkeyDecapsulate(ctx, nullptr, ssLen, ct, ciphertext.length);
            if (ssLen.value == 0) _fail('EVP_PKEY_decapsulate(size)');
            final ss = calloc<Uint8>(ssLen.value);
            try {
              ssLen.value = ssLen.value;
              _check1(
                _b.evpPkeyDecapsulate(ctx, ss, ssLen, ct, ciphertext.length),
                'EVP_PKEY_decapsulate',
              );
              return Uint8List.fromList(
                ss.asTypedList(ssLen.value));
            } finally {
              calloc.free(ss);
            }
          } finally {
            calloc.free(ct);
          }
        } finally {
          calloc.free(ssLen);
        }
      } finally {
        _b.evpPkeyCtxFree(ctx);
      }
    } finally {
      _b.evpPkeyFree(pkey);
    }
  }



  EVP_PKEY _loadPrivateKey(Uint8List data) {
    return withSecretBytes(_b, data, (pointer) {
      final bio = _b.bioNewMemBuf(pointer.cast(), data.length);
      if (bio == nullptr) _fail('BIO_new_mem_buf(_loadPrivateKey)');
      try {
        final pkey = _b.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
        if (pkey == nullptr) {
          _fail('PEM_read_bio_PrivateKey');
        }
        return pkey;
      } finally {
        _b.bioFree(bio);
      }
    });
  }

  EVP_PKEY _loadPublicKey(Uint8List data) {
    final bio = bioFromData(_b, data);
    if (bio == nullptr) _fail('BIO_new(_loadPublicKey)');
    try {
      final pkey = _b.pemReadBioPubkey(bio, nullptr, nullptr, nullptr);
      if (pkey == nullptr) {
        _fail('PEM_read_bio_PUBKEY');
      }
      return pkey;
    } finally {
      _b.bioFree(bio);
    }
  }

  KeyPair _extractKeyPair(EVP_PKEY pkey) {
    final pubBio = _b.bioNew(_b.bioSMem());
    try {
      _check1(_b.pemWriteBioPubkey(pubBio, pkey), 'PEM_write_bio_PUBKEY');
      final pubPem = bioToString(_b, pubBio);

      final privBio = _b.bioNew(_b.bioSMem());
      try {
        _check1(
          _b.pemWriteBioPrivateKey(
            privBio,
            pkey,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
          ),
          'PEM_write_bio_PrivateKey',
        );
        final privPem = bioToString(_b, privBio);
        return KeyPair(publicKeyPem: pubPem, privateKeyPem: privPem);
      } finally {
        _b.bioFree(privBio);
        _b.evpPkeyFree(pkey);
      }
    } finally {
      _b.bioFree(pubBio);
    }
  }

  void _check1(int result, String op) {
    if (result != 1) {
      final err = getOpenSslError(_b);
      _b.errClearError();
      throw StateError('$op failed${err != null ? ': $err' : ''}');
    }
  }

  Never _fail(String op) {
    final err = getOpenSslError(_b);
    _b.errClearError();
    throw StateError('$op failed${err != null ? ': $err' : ''}');
  }
}
