library;

import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../../ffi/openssl_bindings.dart';
import '../models/distinguished_name.dart';

class X509NameBuilder {
  final OpenSslBindings _b;

  const X509NameBuilder(this._b);

  X509_NAME build(DistinguishedName dn) {
    dn.validate();

    final name = _b.x509NameNew();
    if (name == nullptr) {
      throw StateError('X509_NAME_new failed');
    }

    const encoding = 0x1000; // MBSTRING_ASC (= MBSTRING_UTF8 in OpenSSL)

    for (final (shortName, value) in dn.entries) {
      if (value.isEmpty) continue;
      final sn = shortName.toNativeUtf8();
      final val = value.toNativeUtf8();
      try {
        final result = _b.x509NameAddEntryByTxt(
          name,
          sn.cast(),
          encoding,
          val.cast<Uint8>(),
          value.length,
          -1,
          0,
        );
        if (result != 1) {
          _b.x509NameFree(name);
          throw StateError(
            'X509_NAME_add_entry_by_txt failed for $shortName=$value',
          );
        }
      } finally {
        calloc.free(sn);
        calloc.free(val);
      }
    }

    return name;
  }
}
