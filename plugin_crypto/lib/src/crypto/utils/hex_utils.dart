/// Shared hex encoding utilities.
library;

import 'dart:typed_data';

String bytesToHex(
  Uint8List bytes, {
  bool truncate = false,
  int maxLen = 16,
  bool skipLeadingZero = false,
}) {
  const hexChars = '0123456789ABCDEF';
  final effective = skipLeadingZero && bytes.isNotEmpty && bytes[0] == 0
      ? bytes.sublist(1)
      : bytes;
  final buffer = StringBuffer();
  for (var i = 0; i < effective.length; i++) {
    if (truncate && i >= maxLen) {
      buffer.write('... (${effective.length - maxLen} more bytes)');
      break;
    }
    final b = effective[i];
    buffer.write(hexChars[b >> 4]);
    buffer.write(hexChars[b & 0x0F]);
  }
  return buffer.toString();
}
