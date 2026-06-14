library;

import 'dart:typed_data';

import '../utils/hex_utils.dart';

class Asn1TagClass {
  /// Universal class (0) — standardized types (INTEGER, SEQUENCE, etc.).
  static const int universal = 0;

  /// Application class (1) — application-specific types.
  static const int application = 1;

  /// Context-specific class (2) — tagged types within a context.
  static const int contextSpecific = 2;

  /// Private class (3) — organization-specific types.
  static const int private = 3;

  const Asn1TagClass._();
}

/// Common ASN.1 universal tag numbers.
class Asn1TagNumber {
  static const int boolean = 0x01;
  static const int integer = 0x02;
  static const int bitString = 0x03;
  static const int octetString = 0x04;
  static const int null_ = 0x05;
  static const int oid = 0x06;
  static const int utf8String = 0x0C;
  static const int printableString = 0x13;
  static const int ia5String = 0x16;
  static const int utcTime = 0x17;
  static const int generalizedTime = 0x18;
  static const int sequence = 0x10;
  static const int set = 0x11;

  const Asn1TagNumber._();
}

class Asn1Node {
  /// The tag class of this node (0=universal, 1=application,
  /// 2=context-specific, 3=private).
  final int tagClass;

  /// The tag number within the tag class.
  final int tagNumber;

  /// Whether this node is constructed (i.e. its value contains nested
  /// TLV elements).
  final bool isConstructed;

  /// The length of the value in bytes.
  final int length;

  /// Raw value bytes (only meaningful for primitive nodes).
  final Uint8List value;

  /// Child nodes (only meaningful for constructed nodes).
  final List<Asn1Node> children;

  /// Human-readable parsed value for recognized types, or `null` if
  /// the type is unrecognised or the node is constructed.
  final String? parsedValue;

  Asn1Node({
    required this.tagClass,
    required this.tagNumber,
    required this.isConstructed,
    required this.length,
    Uint8List? value,
    List<Asn1Node>? children,
    this.parsedValue,
  }) : value = value ?? Uint8List(0),
       children = children ?? const [];

  /// Returns a human-readable multi-line pretty-print of this node tree.
  String toPrettyString([int indent = 0]) {
    final prefix = ' ' * (indent * 2);
    final typeStr = _tagDescription();
    final buf = StringBuffer('$prefix$typeStr (len=$length)');
    if (parsedValue != null) {
      buf.write(' = $parsedValue');
    }
    if (children.isNotEmpty) {
      buf.write('\n');
      for (final child in children) {
        buf.writeln(child.toPrettyString(indent + 1));
      }
    } else if (value.isNotEmpty && parsedValue == null) {
      buf.write(' = ${_bytesToHex(value)}');
    }
    final result = buf.toString();
    if (result.endsWith('\n')) {
      return result.substring(0, result.length - 1);
    }
    return result;
  }

  /// Returns the tag description including class and number.
  String _tagDescription() {
    final classStr = switch (tagClass) {
      0 => 'UNIVERSAL',
      1 => 'APPLICATION',
      2 => 'CONTEXT',
      3 => 'PRIVATE',
      _ => 'CLASS[$tagClass]',
    };

    final tagStr = tagClass == 0 ? _universalTagName(tagNumber) : null;
    if (tagStr != null) {
      return '$classStr [$tagStr]${isConstructed ? " (constructed)" : ""}';
    }
    return '$classStr [$tagNumber]${isConstructed ? " (constructed)" : ""}';
  }

  /// Returns the human-readable name for a universal tag number.
  String? _universalTagName(int tag) {
    return switch (tag) {
      Asn1TagNumber.boolean => 'BOOLEAN',
      Asn1TagNumber.integer => 'INTEGER',
      Asn1TagNumber.bitString => 'BIT STRING',
      Asn1TagNumber.octetString => 'OCTET STRING',
      Asn1TagNumber.null_ => 'NULL',
      Asn1TagNumber.oid => 'OID',
      Asn1TagNumber.utf8String => 'UTF8String',
      Asn1TagNumber.printableString => 'PrintableString',
      Asn1TagNumber.ia5String => 'IA5String',
      Asn1TagNumber.utcTime => 'UTCTime',
      Asn1TagNumber.generalizedTime => 'GeneralizedTime',
      Asn1TagNumber.sequence => 'SEQUENCE',
      Asn1TagNumber.set => 'SET',
      _ => null,
    };
  }

  /// Converts bytes to a compact hex string (truncated for display).
  String _bytesToHex(Uint8List bytes) {
    return bytesToHex(bytes, truncate: true);
  }
}
