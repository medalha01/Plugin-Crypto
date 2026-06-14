library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:plugin_crypto/plugin_crypto.dart';


String hex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Uint8List pem(String s) => Uint8List.fromList(utf8.encode(s));


PluginCryptoAPI api() => PluginCryptoAPI.instance;


/// Returns [n] cryptographically secure random bytes using the API.
Uint8List randomBytes(int n) => api().randomBytes(n);

Uint8List garbageKey() => pem(
  '-----BEGIN GARBAGE KEY-----\n'
  'VGhpcyBpcyBub3QgYSB2YWxpZCBrZXkgZm9ybWF0Lg==\n'
  '-----END GARBAGE KEY-----\n',
);


Uint8List? _oneMbDataCache;

Uint8List oneMbData() {
  if (_oneMbDataCache != null) return _oneMbDataCache!;
  _oneMbDataCache = api().randomBytes(1024 * 1024);
  return _oneMbDataCache!;
}
