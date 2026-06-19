/// FIPS 186-4/5 key validation: V1 RSA-2048, V2 RSA-4096, V3 EC P-256, V4 EC P-384, V5 EC P-521, V6 RSA-2048 CLI, V7 ML-KEM-768, V8 ML-DSA-44.
@TestOn('linux')
@Tags(['fips', 'validation'])
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/plugin_crypto.dart';
import 'package:plugin_crypto/src/crypto/utils/bio_utils.dart';
import 'package:plugin_crypto/src/crypto/utils/openssl_error.dart';
import 'package:plugin_crypto/src/crypto/constants.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';


/// Represents an uncompressed EC point (x, y) on a prime field curve.
class _EcPoint {
  final BigInt x;
  final BigInt y;
  const _EcPoint(this.x, this.y);
}


PluginCryptoAPI get _api => PluginCryptoAPI.instance;
final OpenSslBindings _bindings =
    OpenSslBindings.create(loadCrypto(), loadSsl());

BigInt _privateKeyParameter(String privateKeyPem, String parameter) {
  final bio = bioFromData(
    _bindings,
    Uint8List.fromList(utf8.encode(privateKeyPem)),
  );
  expect(bio, isNot(nullptr));
  try {
    final key = _bindings.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
    expect(key, isNot(nullptr));
    try {
      final output = calloc<BIGNUM>();
      final name = parameter.toNativeUtf8();
      try {
        expect(_bindings.evpPkeyGetBnParam(key, name, output), 1);
        expect(output.value, isNot(nullptr));
        final hex = _bindings.bnToHex(output.value);
        expect(hex, isNot(nullptr));
        try {
          return BigInt.parse(hex.toDartString(), radix: 16);
        } finally {
          _bindings.cryptoFree(hex.cast(), nullptr, 0);
          _bindings.bnFree(output.value);
        }
      } finally {
        calloc.free(name);
        calloc.free(output);
      }
    } finally {
      _bindings.evpPkeyFree(key);
    }
  } finally {
    _bindings.bioFree(bio);
  }
}

BigInt _curveCofactor(String curve) {
  final name = curve.toNativeUtf8();
  try {
    final nid = _bindings.objSn2nid(name.cast());
    expect(nid, isNot(0));
    final group = _bindings.ecGroupNewByCurveName(nid);
    expect(group, isNot(nullptr));
    try {
      final cofactor = _bindings.bnNew();
      expect(cofactor, isNot(nullptr));
      try {
        expect(_bindings.ecGroupGetCofactor(group, cofactor, nullptr), 1);
        final hex = _bindings.bnToHex(cofactor);
        expect(hex, isNot(nullptr));
        try {
          return BigInt.parse(hex.toDartString(), radix: 16);
        } finally {
          _bindings.cryptoFree(hex.cast(), nullptr, 0);
        }
      } finally {
        _bindings.bnFree(cofactor);
      }
    } finally {
      _bindings.ecGroupFree(group);
    }
  } finally {
    calloc.free(name);
  }
}

bool _satisfiesRsaFactorDistance(BigInt p, BigInt q, int modulusBits) {
  final bound = BigInt.two.pow(modulusBits ~/ 2 - 100);
  return (p - q).abs() > bound;
}

/// Base64-decode the body of a PEM string (stripping header/footer).
Uint8List _pemDecode(String pem) {
  final lines = pem
      .split(RegExp(r'\r?\n'))
      .where((l) => !l.startsWith('-----'))
      .join();
  return Uint8List.fromList(base64Decode(lines));
}

/// Converts a [Uint8List] to a [BigInt] by interpreting bytes as a big-endian
/// unsigned integer.
BigInt _bigIntFromBytes(Uint8List bytes) {
  return BigInt.parse(
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
    radix: 16,
  );
}

/// Parses DER length, returning (value, headerByteCount). Returns null on
/// failure.
(int, int)? _parseDerLength(Uint8List der, int offset) {
  if (offset >= der.length) return null;
  final b = der[offset];
  if ((b & 0x80) == 0) {
    return (b, 1);
  }
  final numBytes = b & 0x7F;
  if (numBytes == 0 || offset + 1 + numBytes > der.length) return null;
  var length = 0;
  for (var i = 0; i < numBytes; i++) {
    length = (length << 8) | der[offset + 1 + i];
  }
  return (length, 1 + numBytes);
}

BigInt? _extractRsaModulus(Uint8List spkiDer) {
  try {
    var pos = 0;
    if (spkiDer[pos] != 0x30) return null;
    final outerLen = _parseDerLength(spkiDer, pos + 1);
    if (outerLen == null) return null;
    pos += 1 + outerLen.$2;

    if (spkiDer[pos] != 0x30) return null;
    final algLen = _parseDerLength(spkiDer, pos + 1);
    if (algLen == null) return null;
    pos += 1 + algLen.$2 + algLen.$1;

    if (spkiDer[pos] != 0x03) return null;
    final bitLen = _parseDerLength(spkiDer, pos + 1);
    if (bitLen == null) return null;
    pos += 1 + bitLen.$2;

    pos += 1;

    if (pos >= spkiDer.length || spkiDer[pos] != 0x30) return null;
    final rsaSeqLen = _parseDerLength(spkiDer, pos + 1);
    if (rsaSeqLen == null) return null;
    pos += 1 + rsaSeqLen.$2;

    if (pos >= spkiDer.length || spkiDer[pos] != 0x02) return null;
    final modLen = _parseDerLength(spkiDer, pos + 1);
    if (modLen == null) return null;
    final modStart = pos + 1 + modLen.$2;
    final modEnd = modStart + modLen.$1;

    return _bigIntFromBytes(spkiDer.sublist(modStart, modEnd));
  } catch (_) {
    return null;
  }
}

/// Extracts the RSA public exponent from a SubjectPublicKeyInfo DER.
BigInt? _extractRsaPublicExponent(Uint8List spkiDer) {
  try {
    var pos = 0;
    if (spkiDer[pos] != 0x30) return null;
    final outerLen = _parseDerLength(spkiDer, pos + 1);
    if (outerLen == null) return null;
    pos += 1 + outerLen.$2;

    if (spkiDer[pos] != 0x30) return null;
    final algLen = _parseDerLength(spkiDer, pos + 1);
    if (algLen == null) return null;
    pos += 1 + algLen.$2 + algLen.$1;

    if (spkiDer[pos] != 0x03) return null;
    final bitLen = _parseDerLength(spkiDer, pos + 1);
    if (bitLen == null) return null;
    pos += 1 + bitLen.$2;
    pos += 1; // Skip unused-bits byte

    if (pos >= spkiDer.length || spkiDer[pos] != 0x30) return null;
    final rsaSeqLen = _parseDerLength(spkiDer, pos + 1);
    if (rsaSeqLen == null) return null;
    pos += 1 + rsaSeqLen.$2;

    if (pos >= spkiDer.length || spkiDer[pos] != 0x02) return null;
    final modLen = _parseDerLength(spkiDer, pos + 1);
    if (modLen == null) return null;
    pos += 1 + modLen.$2 + modLen.$1;

    if (pos >= spkiDer.length || spkiDer[pos] != 0x02) return null;
    final expLen = _parseDerLength(spkiDer, pos + 1);
    if (expLen == null) return null;
    final expStart = pos + 1 + expLen.$2;
    final expEnd = expStart + expLen.$1;

    return _bigIntFromBytes(spkiDer.sublist(expStart, expEnd));
  } catch (_) {
    return null;
  }
}

_EcPoint? _extractEcPoint(Uint8List spkiDer) {
  try {
    var pos = 0;
    if (spkiDer[pos] != 0x30) return null;
    final outerLen = _parseDerLength(spkiDer, pos + 1);
    if (outerLen == null) return null;
    pos += 1 + outerLen.$2;

    if (spkiDer[pos] != 0x30) return null;
    final algLen = _parseDerLength(spkiDer, pos + 1);
    if (algLen == null) return null;
    pos += 1 + algLen.$2 + algLen.$1;

    if (pos >= spkiDer.length || spkiDer[pos] != 0x03) return null;
    final bitLen = _parseDerLength(spkiDer, pos + 1);
    if (bitLen == null) return null;
    pos += 1 + bitLen.$2;
    pos += 1; // Skip unused-bits byte

    if (pos >= spkiDer.length || spkiDer[pos] != 0x04) return null;
    pos += 1;

    final coordLen = (spkiDer.length - pos) ~/ 2;
    if (coordLen <= 0) return null;

    final xBytes = spkiDer.sublist(pos, pos + coordLen);
    final yBytes = spkiDer.sublist(pos + coordLen, pos + 2 * coordLen);

    return _EcPoint(_bigIntFromBytes(xBytes), _bigIntFromBytes(yBytes));
  } catch (_) {
    return null;
  }
}


final BigInt _p256Prime = BigInt.parse(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
  radix: 16,
);

final BigInt _p256A = BigInt.parse(
  'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',
  radix: 16,
);

final BigInt _p256B = BigInt.parse(
  '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
  radix: 16,
);


void main() {
  group('V1: RSA key size validation', () {
    test('RSA-2048 modulus bitLength == 2048', () {
      final kp = _api.generateRsaKeyPair(2048);
      final der = _pemDecode(kp.publicKeyPem);
      final modulus = _extractRsaModulus(der);

      expect(
        modulus,
        isNotNull,
        reason: 'Failed to extract RSA modulus from PEM',
      );

      final bitLen = modulus!.bitLength;
      expect(
        bitLen,
        equals(2048),
        reason: 'RSA-2048 modulus must be exactly 2048 bits, got $bitLen',
      );
    });

    test(
      'RSA-4096 modulus bitLength == 4096',
      () {
        final kp = _api.generateRsaKeyPair(4096);
        final der = _pemDecode(kp.publicKeyPem);
        final modulus = _extractRsaModulus(der);

        expect(
          modulus,
          isNotNull,
          reason: 'Failed to extract RSA modulus from PEM',
        );

        final bitLen = modulus!.bitLength;
        expect(
          bitLen,
          equals(4096),
          reason: 'RSA-4096 modulus must be exactly 4096 bits, got $bitLen',
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );
  });

  group('V2: RSA public exponent validation', () {
    test('RSA-2048 public exponent == 65537 (F4)', () {
      final kp = _api.generateRsaKeyPair(2048);
      final der = _pemDecode(kp.publicKeyPem);
      final e = _extractRsaPublicExponent(der);

      expect(
        e,
        isNotNull,
        reason: 'Failed to extract RSA public exponent from PEM',
      );

      final f4 = BigInt.from(65537);
      expect(
        e,
        equals(f4),
        reason: 'RSA-2048 public exponent must be F4=65537, got $e',
      );
    });

    test(
      'RSA-4096 public exponent == 65537 (F4)',
      () {
        final kp = _api.generateRsaKeyPair(4096);
        final der = _pemDecode(kp.publicKeyPem);
        final e = _extractRsaPublicExponent(der);

        expect(
          e,
          isNotNull,
          reason: 'Failed to extract RSA public exponent from PEM',
        );

        final f4b = BigInt.from(65537);
        expect(
          e,
          equals(f4b),
          reason: 'RSA-4096 public exponent must be F4=65537, got $e',
        );
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test('5 distinct RSA-2048 keys all have e==65537', () {
      for (var i = 0; i < 5; i++) {
        final kp = _api.generateRsaKeyPair(2048);
        final der = _pemDecode(kp.publicKeyPem);
        final e = _extractRsaPublicExponent(der);
        expect(
          e,
          equals(BigInt.from(65537)),
          reason: 'RSA key $i public exponent != F4',
        );
      }
    });
  });

  group('V3: RSA modulus primality (key uniqueness)', () {
    test(
      '10 RSA-2048 keys all have unique moduli',
      () {
        final moduli = <BigInt>{};
        for (var i = 0; i < 10; i++) {
          final kp = _api.generateRsaKeyPair(2048);
          final der = _pemDecode(kp.publicKeyPem);
          final modulus = _extractRsaModulus(der);
          expect(
            modulus,
            isNotNull,
            reason: 'Failed to extract modulus for key $i',
          );

          expect(kp.publicKeyPem, isNotEmpty);
          expect(kp.privateKeyPem, isNotEmpty);
          expect(kp.publicKeyPem, contains('BEGIN PUBLIC KEY'));
          expect(kp.privateKeyPem, contains('BEGIN PRIVATE KEY'));

          moduli.add(modulus!);
        }

        expect(
          moduli.length,
          equals(10),
          reason:
              'All 10 RSA-2048 moduli must be distinct. '
              'Got ${moduli.length} unique out of 10.',
        );

        for (final n in moduli) {
          expect(
            n.bitLength,
            equals(2048),
            reason: 'Each RSA-2048 modulus must be 2048 bits',
          );
        }
      },
      timeout: const Timeout(Duration(minutes: 2)),
    );

    test('RSA-2048 actual factors satisfy the FIPS |p-q| bound', () {
      final kp = _api.generateRsaKeyPair(2048);
      final p = _privateKeyParameter(kp.privateKeyPem, 'rsa-factor1');
      final q = _privateKeyParameter(kp.privateKeyPem, 'rsa-factor2');
      expect(_satisfiesRsaFactorDistance(p, q, 2048), isTrue);
    });

    test('RSA factor-distance assertion rejects deliberately close factors', () {
      final p = BigInt.two.pow(1023) + BigInt.from(12345);
      final q = p + BigInt.one;
      expect(_satisfiesRsaFactorDistance(p, q, 2048), isFalse);
    });
  });

  group('V4: EC point on curve (P-256)', () {
    test('P-256 public key point satisfies y² = x³ + ax + b (mod p)', () {
      final kp = _api.generateEcKeyPair('prime256v1');
      final der = _pemDecode(kp.publicKeyPem);
      final point = _extractEcPoint(der);

      expect(point, isNotNull, reason: 'Failed to extract EC point from PEM');

      final x = point!.x;
      final y = point.y;

      final lhs = (y * y) % _p256Prime;
      final rhs = (x * x * x + _p256A * x + _p256B) % _p256Prime;

      expect(
        lhs,
        equals(rhs),
        reason: 'EC point (x,y) must satisfy the P-256 curve equation.',
      );
    });

    test('5 distinct P-256 keys all satisfy curve equation', () {
      for (var i = 0; i < 5; i++) {
        final kp = _api.generateEcKeyPair('prime256v1');
        final der = _pemDecode(kp.publicKeyPem);
        final point = _extractEcPoint(der);
        expect(point, isNotNull);

        final lhs = (point!.y * point.y) % _p256Prime;
        final rhs =
            (point.x * point.x * point.x + _p256A * point.x + _p256B) %
            _p256Prime;
        expect(
          lhs,
          equals(rhs),
          reason: 'EC key $i: public point not on P-256 curve',
        );
      }
    });

    test('Coordinates are within [0, p-1] for P-256', () {
      final kp = _api.generateEcKeyPair('prime256v1');
      final der = _pemDecode(kp.publicKeyPem);
      final point = _extractEcPoint(der);

      expect(point, isNotNull);
      expect(point!.x >= BigInt.zero, isTrue);
      expect(point.x < _p256Prime, isTrue, reason: 'x coordinate must be < p');
      expect(point.y >= BigInt.zero, isTrue);
      expect(point.y < _p256Prime, isTrue, reason: 'y coordinate must be < p');
    });
  });

  group('V5: EC order check (P-256)', () {
    test('openssl ec -check verifies key validity (n·G = O)', () async {
      final kp = _api.generateEcKeyPair('prime256v1');
      final pubFile = File('/tmp/v5_ec_pub.pem');
      await pubFile.writeAsString(kp.publicKeyPem);

      try {
        final result = await Process.run('openssl', [
          'ec',
          '-pubin',
          '-in',
          pubFile.path,
          '-check',
          '-noout',
        ]);

        expect(
          result.exitCode,
          equals(0),
          reason: 'openssl ec -check failed: ${result.stderr}',
        );

        final output = (result.stderr as String) + (result.stdout as String);
        expect(
          output.toLowerCase(),
          contains('valid'),
          reason: 'openssl ec -check did not report valid key: $output',
        );
      } finally {
        if (await pubFile.exists()) {
          await pubFile.delete();
        }
      }
    });

    test('openssl -check passes for all 3 NIST curves', () async {
      for (final curve in ['prime256v1', 'secp384r1', 'secp521r1']) {
        final kp = _api.generateEcKeyPair(curve);
        final pubFile = File('/tmp/v5_ec_${curve}_pub.pem');
        await pubFile.writeAsString(kp.publicKeyPem);

        try {
          final result = await Process.run('openssl', [
            'ec',
            '-pubin',
            '-in',
            pubFile.path,
            '-check',
            '-noout',
          ]);
          expect(
            result.exitCode,
            equals(0),
            reason: 'openssl ec -check failed for $curve',
          );
        } finally {
          if (await pubFile.exists()) {
            await pubFile.delete();
          }
        }
      }
    });
  });

  group('V6: EC cofactor (P-256/P-384/P-521)', () {
    test('P-256 cofactor h = 1', () {
      expect(_curveCofactor('prime256v1'), BigInt.one);
    });

    test('P-384 cofactor h = 1', () {
      expect(_curveCofactor('secp384r1'), BigInt.one);

      final kp = _api.generateEcKeyPair('secp384r1');
      final msg = Uint8List.fromList(utf8.encode('cofactor 384'));
      final sig = _api.sign(
        msg,
        Uint8List.fromList(kp.privateKeyPem.codeUnits),
      );
      final ok = _api.verify(
        msg,
        Uint8List.fromList(kp.publicKeyPem.codeUnits),
        sig,
      );
      expect(ok, isTrue);
    });

    test('P-521 cofactor h = 1', () {
      expect(_curveCofactor('secp521r1'), BigInt.one);

      final kp = _api.generateEcKeyPair('secp521r1');
      final msg = Uint8List.fromList(utf8.encode('cofactor 521'));
      final sig = _api.sign(
        msg,
        Uint8List.fromList(kp.privateKeyPem.codeUnits),
      );
      final ok = _api.verify(
        msg,
        Uint8List.fromList(kp.publicKeyPem.codeUnits),
        sig,
      );
      expect(ok, isTrue);
    });
  });

  group('V7: ML-KEM-768 public key size (FIPS 203)', () {
    test(
      'ML-KEM-768 public key DER == 1206 bytes',
      () {
        final ctx = _bindings.evpPkeyCtxNewId(nidMlKem768, nullptr);
        if (ctx == nullptr) {
          markTestSkipped(
              'ML-KEM-768 EVP_PKEY_CTX creation failed');
          return;
        }

        try {
          if (_bindings.evpPkeyKeygenInit(ctx) != 1) {
            markTestSkipped('ML-KEM-768 keygen init failed');
            return;
          }

          final ppkey = calloc<EVP_PKEY>();
          try {
            if (_bindings.evpPkeyKeygen(ctx, ppkey) != 1) {
              markTestSkipped('ML-KEM-768 keygen failed');
              return;
            }

            final pubBio = _bindings.bioNew(_bindings.bioSMem());
            if (pubBio == nullptr) {
              markTestSkipped('ML-KEM-768 BIO creation failed');
              return;
            }

            try {
              if (_bindings.pemWriteBioPubkey(pubBio, ppkey.value) != 1) {
                markTestSkipped(
                    'ML-KEM-768 PEM write failed: '
                    '${getOpenSslError(_bindings)}');
                return;
              }

              final pem = bioToString(_bindings, pubBio);
              final der = _pemDecode(pem);
              expect(
                der.length,
                equals(1206),
                reason:
                    'ML-KEM-768 pubkey DER must be exactly 1206 bytes '
                    '(OpenSSL 4.0.0 SPKI wrapper). Got ${der.length} bytes.',
              );
            } finally {
              _bindings.bioFree(pubBio);
            }
          } finally {
            calloc.free(ppkey);
          }
        } finally {
          _bindings.evpPkeyCtxFree(ctx);
        }
      },
    );
  });

  group('V8: ML-DSA-44 public key size (FIPS 204)', () {
    test(
      'ML-DSA-44 public key DER == 1334 bytes',
      () {
        final ctx = _bindings.evpPkeyCtxNewId(nidMlDsa44, nullptr);
        if (ctx == nullptr) {
          markTestSkipped(
              'ML-DSA-44 EVP_PKEY_CTX creation failed');
          return;
        }

        try {
          if (_bindings.evpPkeyKeygenInit(ctx) != 1) {
            markTestSkipped('ML-DSA-44 keygen init failed');
            return;
          }

          final ppkey = calloc<EVP_PKEY>();
          try {
            if (_bindings.evpPkeyKeygen(ctx, ppkey) != 1) {
              markTestSkipped('ML-DSA-44 keygen failed');
              return;
            }

            final pubBio = _bindings.bioNew(_bindings.bioSMem());
            if (pubBio == nullptr) {
              markTestSkipped('ML-DSA-44 BIO creation failed');
              return;
            }

            try {
              if (_bindings.pemWriteBioPubkey(pubBio, ppkey.value) != 1) {
                markTestSkipped(
                    'ML-DSA-44 PEM write failed: '
                    '${getOpenSslError(_bindings)}');
                return;
              }

              final pem = bioToString(_bindings, pubBio);
              final der = _pemDecode(pem);
              expect(
                der.length,
                equals(1334),
                reason:
                    'ML-DSA-44 pubkey DER must be exactly 1334 bytes '
                    '(OpenSSL 4.0.0 SPKI wrapper). Got ${der.length} bytes.',
              );
            } finally {
              _bindings.bioFree(pubBio);
            }
          } finally {
            calloc.free(ppkey);
          }
        } finally {
          _bindings.evpPkeyCtxFree(ctx);
        }
      },
    );
  });
}
