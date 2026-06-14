library;

import 'metrics_models.dart';



/// NIST P-256 curve order (n).
const _p256OrderHex =
    'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';

/// NIST P-256 field prime (p).
const _p256PrimeHex =
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF';

/// NIST P-256 field size in bits.
const _p256FieldSizeBits = 256;


/// NIST P-384 curve order (n).
const _p384OrderHex =
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973';

/// NIST P-384 field prime (p).
const _p384PrimeHex =
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF';

/// NIST P-384 field size in bits.
const _p384FieldSizeBits = 384;


/// NIST P-521 curve order (n).
const _p521OrderHex =
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409';

/// NIST P-521 field prime (p).
const _p521PrimeHex =
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';

/// NIST P-521 field size in bits.
const _p521FieldSizeBits = 521;


SafeCurveChecklist buildSafeCurveChecklist(String curveName) {
  final config = _curveConfig(curveName);
  if (config == null) {
    return SafeCurveChecklist(
      curveName: curveName,
      fieldSizeBits: 0,
      hasPrimeOrder: false,
      cofactorIsOne: false,
      embeddingDegree: 0,
      embeddingDegreeSafe: false,
      twistSecure: false,
      twistOrderChecked: false,
      notes:
          'Unknown curve: "$curveName". Only NIST P-256 (prime256v1), '
          'P-384 (secp384r1), and P-521 (secp521r1) are supported.',
    );
  }

  final order = BigInt.parse(config.orderHex, radix: 16);
  final prime = BigInt.parse(config.primeHex, radix: 16);
  final fieldSizeBits = config.fieldSizeBits;

  final embeddingDegreeRaw = verifyEmbeddingDegree(
    prime,
    order,
    curveName: curveName,
  );
  final embeddingDegree = embeddingDegreeRaw;
  final embeddingDegreeSafe = embeddingDegree >= 100 || embeddingDegree == 0;

  final notesBuffer = StringBuffer();
  notesBuffer.write(
    'NIST $curveName ($fieldSizeBits-bit): '
    'order is prime 0x${config.orderHex}, '
    'cofactor h=1, '
    'embedding degree k=${embeddingDegree == 0 ? ">500 (astronomically large)" : "$embeddingDegree"}',
  );
  if (embeddingDegreeSafe) {
    notesBuffer.write(' (well above 100 threshold), ');
  } else {
    notesBuffer.write(' (BELOW 100 threshold — MOV/Frey-Rück attack risk!), ');
  }
  notesBuffer.write(
    'twist is secure per Bernstein 2001 and NIST SP 800-186 Appendix D. '
    'Twist order verification requires EC_GROUP_get_curve/EC_POINT '
    'arithmetic not exposed in current FFI bindings.',
  );

  return SafeCurveChecklist(
    curveName: curveName,
    fieldSizeBits: fieldSizeBits,
    hasPrimeOrder: true,
    cofactorIsOne: true,
    embeddingDegree: embeddingDegree,
    embeddingDegreeSafe: embeddingDegreeSafe,
    twistSecure: true,
    twistOrderChecked: false,
    notes: notesBuffer.toString(),
  );
}

int verifyEmbeddingDegree(BigInt prime, BigInt order, {String? curveName}) {
  const maxK = 500;
  for (var k = 1; k <= maxK; k++) {
    final pow = prime.modPow(BigInt.from(k), order);
    if (pow == BigInt.one) {
      return k;
    }
  }
  return 0;
}


/// NIST curve parameter configuration.
class _CurveConfig {
  final String orderHex;
  final String primeHex;
  final int fieldSizeBits;

  const _CurveConfig({
    required this.orderHex,
    required this.primeHex,
    required this.fieldSizeBits,
  });
}

/// Look up the NIST curve configuration by name.
_CurveConfig? _curveConfig(String curveName) {
  switch (curveName) {
    case 'prime256v1':
      return const _CurveConfig(
        orderHex: _p256OrderHex,
        primeHex: _p256PrimeHex,
        fieldSizeBits: _p256FieldSizeBits,
      );
    case 'secp384r1':
      return const _CurveConfig(
        orderHex: _p384OrderHex,
        primeHex: _p384PrimeHex,
        fieldSizeBits: _p384FieldSizeBits,
      );
    case 'secp521r1':
      return const _CurveConfig(
        orderHex: _p521OrderHex,
        primeHex: _p521PrimeHex,
        fieldSizeBits: _p521FieldSizeBits,
      );
    default:
      return null;
  }
}
