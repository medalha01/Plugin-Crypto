library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../../ffi/openssl_bindings.dart';
import '../models/certificate_data.dart';

const _kuDigitalSignature = 0x0080;
const _kuNonRepudiation = 0x0040;
const _kuKeyEncipherment = 0x0020;
const _kuDataEncipherment = 0x0010;
const _kuKeyAgreement = 0x0008;
const _kuKeyCertSign = 0x0004;
const _kuCrlSign = 0x0002;
const _kuEncipherOnly = 0x0001;
const _kuDecipherOnly = 0x8000;

const _oidKeyUsage = '2.5.29.15';
const _oidBasicConstraints = '2.5.29.19';
const _oidSubjectAltName = '2.5.29.17';
const _oidCrlDistributionPoints = '2.5.29.31';
const _oidAuthorityInfoAccess = '1.3.6.1.5.5.7.1.1';

class X509ExtensionParser {
  final OpenSslBindings _b;

  X509ExtensionParser(this._b);

  X509ParsedExtensions parseExtensions(Pointer<Void> x509) {
    if (x509 == nullptr) {
      return const X509ParsedExtensions();
    }

    List<String>? keyUsage;
    BasicConstraints? basicConstraints;
    List<String>? subjectAltNames;
    List<String>? crlDistributionPoints;
    List<String>? ocspResponders;

    final extCount = _b.x509GetExtCount(x509);
    for (var i = 0; i < extCount; i++) {
      final ext = _b.x509GetExt(x509, i);
      if (ext == nullptr) continue;
      final oid = _extOid(ext);
      if (oid == null) continue;

      switch (oid) {
        case _oidKeyUsage:
          keyUsage = _parseKeyUsage(x509);
        case _oidBasicConstraints:
          basicConstraints = _parseBasicConstraints(ext);
        case _oidSubjectAltName:
          subjectAltNames = _parseSubjectAltName(ext);
        case _oidCrlDistributionPoints:
          crlDistributionPoints = _parseCrlDistributionPoints(ext);
        case _oidAuthorityInfoAccess:
          ocspResponders = _parseOcspResponders(ext);
      }
    }

    return X509ParsedExtensions(
      keyUsage: keyUsage,
      basicConstraints: basicConstraints,
      subjectAltNames: subjectAltNames,
      crlDistributionPoints: crlDistributionPoints,
      ocspResponders: ocspResponders,
    );
  }


  /// Reads the OID of [ext] as a dotted string (e.g. "2.5.29.19").
  String? _extOid(X509_EXTENSION ext) {
    final obj = _b.x509ExtensionGetObject(ext);
    if (obj == nullptr) return null;
    final buf = calloc<Uint8>(128);
    try {
      final len = _b.objObj2txt(buf.cast(), 128, obj, 1);
      if (len <= 0) return null;
      final str = String.fromCharCodes(buf.asTypedList(len));
      if (str.isEmpty || !str.contains('.')) return null;
      return str;
    } finally {
      calloc.free(buf);
    }
  }

  /// Parses the Key Usage extension using `X509_get_key_usage`.
  List<String> _parseKeyUsage(X509 x509) {
    final flags = _b.x509GetKeyUsage(x509);
    if (flags == -1) return [];
    final usages = <String>[];
    if (flags & _kuDigitalSignature != 0) usages.add('digitalSignature');
    if (flags & _kuNonRepudiation != 0) usages.add('nonRepudiation');
    if (flags & _kuKeyEncipherment != 0) usages.add('keyEncipherment');
    if (flags & _kuDataEncipherment != 0) usages.add('dataEncipherment');
    if (flags & _kuKeyAgreement != 0) usages.add('keyAgreement');
    if (flags & _kuKeyCertSign != 0) usages.add('keyCertSign');
    if (flags & _kuCrlSign != 0) usages.add('cRLSign');
    if (flags & _kuEncipherOnly != 0) usages.add('encipherOnly');
    if (flags & _kuDecipherOnly != 0) usages.add('decipherOnly');
    return usages;
  }

  BasicConstraints? _parseBasicConstraints(X509_EXTENSION ext) {
    final text = _extToText(ext);
    if (text == null || text.isEmpty) return null;

    final isCa = text.contains('CA:TRUE');
    int? pathLen;
    final pathLenMatch = RegExp(r'pathlen:(\d+)').firstMatch(text);
    if (pathLenMatch != null) {
      pathLen = int.tryParse(pathLenMatch.group(1)!);
    }
    return BasicConstraints(isCa: isCa, pathLen: pathLen);
  }

  List<String>? _parseSubjectAltName(X509_EXTENSION ext) {
    final text = _extToText(ext);
    if (text == null || text.isEmpty) return null;
    return text
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  List<String>? _parseCrlDistributionPoints(X509_EXTENSION ext) {
    final text = _extToText(ext);
    if (text == null || text.isEmpty) return null;
    return _extractUris(text);
  }

  List<String>? _parseOcspResponders(X509_EXTENSION ext) {
    final text = _extToText(ext);
    if (text == null || text.isEmpty) return null;
    final urls = <String>[];
    for (final line in text.split('\n')) {
      final trimmed = line.trim();
      if (trimmed.startsWith('OCSP') && trimmed.contains('URI:')) {
        final uri = trimmed.split('URI:').last.trim();
        if (uri.isNotEmpty) urls.add(uri);
      }
    }
    return urls.isNotEmpty ? urls : null;
  }

  /// Renders [ext] to a human-readable string via `X509V3_EXT_print`.
  String? _extToText(X509_EXTENSION ext) {
    final bio = _b.bioNew(_b.bioSMem());
    if (bio == nullptr) return null;
    try {
      final result = _b.x509V3ExtPrint(bio, ext, 0, 0);
      if (result != 1) return null;
      return _bioToDartString(bio);
    } finally {
      _b.bioFree(bio);
    }
  }

  /// Reads all data from a memory [bio] into a Dart [String].
  String _bioToDartString(BIO bio) {
    final buf = calloc<Uint8>(4096);
    try {
      final n = _b.bioRead(bio, buf.cast(), 4096);
      if (n <= 0) return '';
      return String.fromCharCodes(buf.asTypedList(n));
    } finally {
      calloc.free(buf);
    }
  }

  List<String>? _extractUris(String text) {
    final uris = <String>[];
    final uriPattern = RegExp(r'URI\s*:\s*(\S+)', caseSensitive: false);
    for (final match in uriPattern.allMatches(text)) {
      final uri = match.group(1);
      if (uri != null && uri.isNotEmpty) {
        uris.add(uri);
      }
    }
    return uris.isNotEmpty ? uris : null;
  }
}
