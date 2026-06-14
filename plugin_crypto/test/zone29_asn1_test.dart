@TestOn('linux')
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_result.dart';
import 'package:plugin_crypto/src/crypto/models/crypto_error.dart';
import 'package:plugin_crypto/src/crypto/models/asn1_data.dart';
import 'package:plugin_crypto/src/crypto/flows/asn1/openssl_asn1_parser.dart';
import 'package:plugin_crypto/src/crypto/plugin_crypto_context.dart';
import 'package:plugin_crypto/src/ffi/native_loader.dart';
import 'package:plugin_crypto/src/ffi/openssl_bindings.dart';
import 'package:plugin_crypto/src/metrics/metrics_collector.dart';

void main() {
  final m = MetricsCollector.instance;
  m?.startZone('zone29', 'ASN.1 Parser');

  late OpenSslBindings bindings;
  late OpenSslAsn1Parser parser;

  setUpAll(() {
    bindings = OpenSslBindings.create(loadCrypto(), loadSsl());
    parser = OpenSslAsn1Parser(PluginCryptoContext(bindings));
  });

  group('ASN.1 primitive parsing', () {
    test('Parse simple INTEGER (02 01 2A = 42)', () {
      final der = Uint8List.fromList([0x02, 0x01, 0x2A]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final node = (result as CryptoSuccess<Asn1Node>).value;
      expect(node.tagNumber, equals(Asn1TagNumber.integer));
      expect(node.parsedValue, equals('42'));
    });

    test('Parse SEQUENCE (30 00 = empty SEQUENCE)', () {
      final der = Uint8List.fromList([0x30, 0x00]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final node = (result as CryptoSuccess<Asn1Node>).value;
      expect(node.tagNumber, equals(Asn1TagNumber.sequence));
      expect(node.isConstructed, isTrue);
      expect(node.children, isEmpty);
    });

    test('Parse OID (06 09 2A 86 48 86 F7 0D 01 01 01 = '
        '1.2.840.113549.1.1.1)', () {
      final der = Uint8List.fromList([
        0x06,
        0x09,
        0x2A,
        0x86,
        0x48,
        0x86,
        0xF7,
        0x0D,
        0x01,
        0x01,
        0x01,
      ]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final node = (result as CryptoSuccess<Asn1Node>).value;
      expect(node.tagNumber, equals(Asn1TagNumber.oid));
      expect(node.parsedValue, equals('1.2.840.113549.1.1.1'));
    });

    test('Parse UTF8String (0C 04 74 65 73 74 = "test")', () {
      final der = Uint8List.fromList([0x0C, 0x04, 0x74, 0x65, 0x73, 0x74]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final node = (result as CryptoSuccess<Asn1Node>).value;
      expect(node.tagNumber, equals(Asn1TagNumber.utf8String));
      expect(node.parsedValue, equals('test'));
    });

    test('Parse nested SEQUENCE (30 02 30 00)', () {
      final der = Uint8List.fromList([0x30, 0x02, 0x30, 0x00]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final root = (result as CryptoSuccess<Asn1Node>).value;
      expect(root.tagNumber, equals(Asn1TagNumber.sequence));
      expect(root.isConstructed, isTrue);
      expect(root.children, hasLength(1));

      final child = root.children[0];
      expect(child.tagNumber, equals(Asn1TagNumber.sequence));
      expect(child.isConstructed, isTrue);
      expect(child.children, isEmpty);
    });

    test('Parse NULL (05 00)', () {
      final der = Uint8List.fromList([0x05, 0x00]);
      final result = parser.parse(der);

      expect(result, isA<CryptoSuccess<Asn1Node>>());
      final node = (result as CryptoSuccess<Asn1Node>).value;
      expect(node.tagNumber, equals(Asn1TagNumber.null_));
      expect(node.parsedValue, equals('NULL'));
    });
  });

  group('Error handling', () {
    test('empty DER returns CryptoFailure', () {
      final result = parser.parse(Uint8List(0));

      expect(result, isA<CryptoFailure<Asn1Node>>());
      final error = (result as CryptoFailure<Asn1Node>).error;
      expect(error, isA<Asn1Error>());
      expect(error.message, contains('non-empty'));
    });

    test('garbage data returns CryptoFailure', () {
      final garbage = Uint8List.fromList(
        List.generate(50, (i) => (i * 13) % 256),
      );
      final result = parser.parse(garbage);

      expect(result, isA<CryptoFailure<Asn1Node>>());
      final error = (result as CryptoFailure<Asn1Node>).error;
      expect(error, isA<Asn1Error>());
    });
  });

  group('Output formatting', () {
    test('toPrettyString works for INTEGER', () {
      final der = Uint8List.fromList([0x02, 0x01, 0x2A]);
      final result = parser.parse(der);
      final node = (result as CryptoSuccess<Asn1Node>).value;

      final pretty = node.toPrettyString();
      expect(pretty, isNotEmpty);
      expect(pretty, contains('INTEGER'));
      expect(pretty, contains('42'));
    });

    test('toPrettyString works for nested SEQUENCE', () {
      final der = Uint8List.fromList([
        0x30,
        0x06,
        0x02,
        0x01,
        0x01,
        0x02,
        0x01,
        0x02,
      ]);
      final result = parser.parse(der);
      final node = (result as CryptoSuccess<Asn1Node>).value;

      final pretty = node.toPrettyString();
      expect(pretty, isNotEmpty);
      expect(pretty, contains('SEQUENCE'));
      expect(pretty, contains('INTEGER'));
      expect(pretty, contains('1'));
      expect(pretty, contains('2'));
    });
  });

  m?.endZone();
}
