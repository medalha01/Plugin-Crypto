library;

import 'dart:typed_data';

import '../../utils/hex_utils.dart';
import '../../models/asn1_data.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../crypto_context.dart';
import 'asn1_parser.dart';

class OpenSslAsn1Parser implements Asn1Parser {
  // ignore: unused_field — reserved for future OpenSSL-backed parsing
  final CryptoContext _ctx;

  /// Creates a parser with the given [CryptoContext].
  const OpenSslAsn1Parser(this._ctx);

  @override
  CryptoResult<Asn1Node> parse(Uint8List derData) {
    if (derData.isEmpty) {
      return CryptoFailure(Asn1Error(reason: 'derData must be non-empty'));
    }

    try {
      final node = _parseNode(derData, 0);
      if (node == null) {
        return CryptoFailure(
          Asn1Error(
            reason:
                'Failed to parse DER root '
                'element',
          ),
        );
      }
      final (parsedNode, trailingOffset) = node;
      if (trailingOffset != derData.length) {
        return CryptoFailure(
          Asn1Error(reason: 'Trailing data after DER root element'),
        );
      }
      return CryptoSuccess(parsedNode);
    } catch (e) {
      return CryptoFailure(Asn1Error(reason: 'Parse error: $e'));
    }
  }


  (Asn1Node, int)? _parseNode(Uint8List data, int offset) {
    if (offset >= data.length) return null;

    final tagResult = _parseTag(data, offset);
    final (tagClass, tagNumber, isConstructed, tagEnd) = tagResult;

    final lengthResult = _parseLength(data, tagEnd);
    if (lengthResult == null) return null;
    final (contentLength, lengthEnd) = lengthResult;

    final valueStart = lengthEnd;
    final valueEnd = valueStart + contentLength;
    if (valueEnd > data.length) return null;

    if (isConstructed) {
      final children = <Asn1Node>[];
      var childOffset = valueStart;
      while (childOffset < valueEnd) {
        final childResult = _parseNode(data, childOffset);
        if (childResult == null) return null;
        final (childNode, nextChildOffset) = childResult;
        children.add(childNode);
        childOffset = nextChildOffset;
      }

      return (
        Asn1Node(
          tagClass: tagClass,
          tagNumber: tagNumber,
          isConstructed: true,
          length: contentLength,
          children: children,
        ),
        valueEnd,
      );
    }

    final value = Uint8List.fromList(data.sublist(valueStart, valueEnd));
    final parsed = _parsePrimitiveValue(tagClass, tagNumber, value);

    return (
      Asn1Node(
        tagClass: tagClass,
        tagNumber: tagNumber,
        isConstructed: false,
        length: contentLength,
        value: value,
        parsedValue: parsed,
      ),
      valueEnd,
    );
  }

  (int, int, bool, int) _parseTag(Uint8List data, int offset) {
    final firstByte = data[offset];
    final tagClass = (firstByte >> 6) & 0x03;
    final isConstructed = (firstByte & 0x20) != 0;

    var tagNumber = firstByte & 0x1F;
    var pos = offset + 1;

    if (tagNumber == 0x1F) {
      tagNumber = 0;
      while (pos < data.length) {
        final b = data[pos];
        pos++;
        tagNumber = (tagNumber << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
      }
    }

    return (tagClass, tagNumber, isConstructed, pos);
  }

  (int, int)? _parseLength(Uint8List data, int offset) {
    if (offset >= data.length) return null;

    final firstByte = data[offset];
    if ((firstByte & 0x80) == 0) {
      return (firstByte, offset + 1);
    }

    final numLengthBytes = firstByte & 0x7F;
    if (numLengthBytes == 0) {
      return null;
    }
    if (numLengthBytes > 4) {
      return null;
    }

    var length = 0;
    for (var i = 0; i < numLengthBytes; i++) {
      final pos = offset + 1 + i;
      if (pos >= data.length) return null;
      length = (length << 8) | data[pos];
    }

    return (length, offset + 1 + numLengthBytes);
  }

  String? _parsePrimitiveValue(int tagClass, int tagNumber, Uint8List value) {
    if (tagClass != Asn1TagClass.universal) return null;

    switch (tagNumber) {
      case Asn1TagNumber.integer:
        return _parseInteger(value);
      case Asn1TagNumber.oid:
        return _parseOid(value);
      case Asn1TagNumber.utf8String:
      case Asn1TagNumber.printableString:
      case Asn1TagNumber.ia5String:
        return String.fromCharCodes(value);
      case Asn1TagNumber.utcTime:
      case Asn1TagNumber.generalizedTime:
        return String.fromCharCodes(value);
      case Asn1TagNumber.boolean:
        return value.isNotEmpty && value[0] != 0 ? 'TRUE' : 'FALSE';
      case Asn1TagNumber.null_:
        return 'NULL';
      default:
        return null;
    }
  }

  /// Parses a DER-encoded INTEGER into a decimal string.
  String _parseInteger(Uint8List value) {
    if (value.isEmpty) return '0';
    if (value.length <= 8) {
      var result = BigInt.zero;
      for (var i = 0; i < value.length; i++) {
        result = (result << 8) | BigInt.from(value[i]);
      }
      if (value[0] & 0x80 != 0) {
        final onesComplement = (BigInt.one << (value.length * 8)) - BigInt.one;
        result = result - onesComplement - BigInt.one;
      }
      return result.toString();
    }
    return '0x${_bytesToCompactHex(value)}';
  }

  /// Parses a DER-encoded OID into a dotted string.
  String _parseOid(Uint8List value) {
    if (value.isEmpty) return '';

    final parts = <int>[];
    parts.add(value[0] ~/ 40);
    parts.add(value[0] % 40);

    var i = 1;
    while (i < value.length) {
      var component = 0;
      while (i < value.length) {
        final b = value[i];
        i++;
        component = (component << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
      }
      parts.add(component);
    }

    return parts.join('.');
  }

  String _bytesToCompactHex(Uint8List bytes) {
    return bytesToHex(bytes);
  }
}
