/// Shared ASN1_TIME parsing utility.
library;

import 'dart:ffi';

import '../../ffi/openssl_bindings.dart';
import 'bio_utils.dart';

/// Parses an [ASN1_TIME] pointer into a [DateTime], or `null` on failure.
DateTime? parseAsn1Time(OpenSslBindings b, Pointer<Void> asn1Time) {
  if (asn1Time == nullptr) return null;

  final bio = b.bioNew(b.bioSMem());
  if (bio == nullptr) return null;
  try {
    final result = b.asn1TimePrint(bio, asn1Time);
    if (result != 1) return null;
    final str = bioToString(b, bio).trim();
    if (str.isEmpty) return null;
    return _parseAsn1TimeString(str);
  } finally {
    b.bioFree(bio);
  }
}

DateTime? _parseAsn1TimeString(String s) {
  try {
    final parts = s.split(' ');
    if (parts.length < 5) return null;

    const months = {
      'Jan': 1,
      'Feb': 2,
      'Mar': 3,
      'Apr': 4,
      'May': 5,
      'Jun': 6,
      'Jul': 7,
      'Aug': 8,
      'Sep': 9,
      'Oct': 10,
      'Nov': 11,
      'Dec': 12,
    };

    final month = months[parts[0]];
    if (month == null) return null;

    final day = int.tryParse(parts[1]);
    if (day == null) return null;

    final timeParts = parts[2].split(':');
    if (timeParts.length != 3) return null;
    final hour = int.tryParse(timeParts[0]);
    final minute = int.tryParse(timeParts[1]);
    final second = int.tryParse(timeParts[2]);
    if (hour == null || minute == null || second == null) return null;

    final year = int.tryParse(parts[3]);
    if (year == null) return null;

    return DateTime.utc(year, month, day, hour, minute, second);
  } catch (_) {
    return null;
  }
}
