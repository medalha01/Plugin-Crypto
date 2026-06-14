library;

import 'dart:io';
import 'dart:typed_data';

import 'package:plugin_crypto/plugin_crypto.dart';

import 'helpers.dart';


const String testCertPem = '''-----BEGIN CERTIFICATE-----
MIIBzDCCAXOgAwIBAgIUH54hr75+amZlGPVbIOu9q5sI+EcwCgYIKoZIzj0EAwIw
PDEWMBQGA1UEAwwNVENDIFRlc3QgQ2VydDEVMBMGA1UECgwMUGx1Z2luQ3J5cHRv
MQswCQYDVQQGEwJCUjAeFw0yNjA0MzAyMTIxMzhaFw0yNzA0MzAyMTIxMzhaMDwx
FjAUBgNVBAMMDVRDQyBUZXN0IENlcnQxFTATBgNVBAoMDFBsdWdpbkNyeXB0bzEL
MAkGA1UEBhMCQlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQB66E/jM6bhlxJ
mr2CxRGmAhjqkWoV+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oH
Ut6+DVYto1MwUTAdBgNVHQ4EFgQUtpQurNbwHoYUVW7AI1xr4+2IdRYwHwYDVR0j
BBgwFoAUtpQurNbwHoYUVW7AI1xr4+2IdRYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNHADBEAiBQxobhr3wdWEFsVLDv2IeI/NFKw/O3W3nf0jYm9kDRsAIg
fy6XTViHpFXzM0Rgfl1sJ7i26Haehg32D3x11tzBbMg=
-----END CERTIFICATE-----
''';

/// Private key corresponding to [testCertPem] (PEM, unencrypted).
const String testKeyPem = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuXtpWM2SqBrFzQj
/4wlOs6BJb1WzvA8uLnjdlWoWAehRANCAAQB66E/jM6bhlxJmr2CxRGmAhjqkWoV
+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oHUt6+DVYt
-----END PRIVATE KEY-----
''';

const String rsaTestCertPem = '''-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUalF3MeImADUqNkPL/5JKQUSJc0kwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwaUGx1Z2luQ3J5cHRvUlNBVGVzdEZpeHR1cmUwHhcNMjYw
NTI1MTIwMTE1WhcNMzYwNTIyMTIwMTE1WjAlMSMwIQYDVQQDDBpQbHVnaW5Dcnlw
dG9SU0FUZXN0Rml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALlg9lg8oVdt6R0VAXmtLTCjxz7KkD/bSYgmCUy1vejLfXM7S+QCmessb4NHnW3K
yVXafCsOsI8VFAnUv4UX/W69wTmCh/dENP80fht3p226YUrh7MKs5Npb0CEwkO0Q
4ANV8O4DPxRq5k3b8B+btBGNw3KPdDaG3zNKataogk5HSD9sOTqMN8dNfUuQJCcC
zLR7CfZMdUQgLGVIe/D+TICtJraYGay73ltc7c+PY5fqVUyzYfZUIxxF2x4qssCU
badCM0eTqo//9fOxCt4kX8a67pDECcYfiLXnASeL/R6qeBsHMgggeWyJdwMKoL7k
uFdCffNXJWe6H3xcK6b9nDECAwEAAaNTMFEwHQYDVR0OBBYEFJeEKZ/IViIQRae/
sIOblMjb+NBNMB8GA1UdIwQYMBaAFJeEKZ/IViIQRae/sIOblMjb+NBNMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGBx97/EA+A6p6f2D/AiZZ1n
O2f3FqCOw90AOiniGLaH1MkAYA8igv5S+SbwxArbRUL8fOfaD7JviToP+arPIAAv
MSk9SbYNBI/wusypWneuESCrWA6JyH9AU96/d6Db/BkXXP4Hm+EurGbjLPLBvLk2
Mli6NRqmaxh5rTlzhb8YASij8LViJhz+RSw+tVIbyIzr7Zvd42hfyc1cafPQV8bj
aaJfVDsLP011ZaGik2914r2i9XFBYMIp0o7JOsP1I95VpDIxJ5+65zi42cRJ1aEK
hpKxp+2MEc73aAb/ZKBibMFJe6kvjxF9vs4hCpK8bggOFYCLIUCX/WXSeBwN3RA=
-----END CERTIFICATE-----
''';

/// Private key corresponding to [rsaTestCertPem] (PEM, unencrypted).
const String rsaTestKeyPem = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5YPZYPKFXbekd
FQF5rS0wo8c+ypA/20mIJglMtb3oy31zO0vkApnrLG+DR51tyslV2nwrDrCPFRQJ
1L+FF/1uvcE5gof3RDT/NH4bd6dtumFK4ezCrOTaW9AhMJDtEOADVfDuAz8UauZN
2/Afm7QRjcNyj3Q2ht8zSmrWqIJOR0g/bDk6jDfHTX1LkCQnAsy0ewn2THVEICxl
SHvw/kyArSa2mBmsu95bXO3Pj2OX6lVMs2H2VCMcRdseKrLAlG2nQjNHk6qP//Xz
sQreJF/Guu6QxAnGH4i15wEni/0eqngbBzIIIHlsiXcDCqC+5LhXQn3zVyVnuh98
XCum/ZwxAgMBAAECggEACUjCJbKpqPGMAIUeDQw/jGVTdAFcnpoasWsoQZODlp5k
YspIN3vq3gScdCB40bgbg8V8vQJQFOZrGb/yNJX6PxrZS8pOCXP8zIBCRZllRQFV
4JR2kVxr3MTG5Hakd38GHRyng6Adf2YIMUOP3+FiMBPfw0PMf/Oax5yVQ7luR0HE
M2KsLm03xGa5TWVKIEAKRn3HSBX7k4thNmhmRJpTYuXMNCWujt27DNrKFUmTD56z
6FjW+I9f5vNEQQ7iciRjxUnbb3OILU6E6T8Fo4IoMYxkp37AVVYwSFbdhAiod7fB
ONeR8gb+pixWDR2CDBZStsN5lkOIKO6hXqMl1+tQAQKBgQD1EX8rWrNNKTb5WSH9
6ocj47aTptnuoS0DrVyUG6QvHPBRHFoSCcVK00DVMik9y8r9Qf2kpEN8OBXfL5Nu
R8Aiu/vZhcNTy+MikufhjOE+Uy5Klp0b2aOckWH4HBg44hGIP3WdrMT6xxL32CbS
dQZPTXXthb48uHv/BGSLkdd8AQKBgQDBpdqGbYia76H5fv12yGTEDYqChvWalOoD
eQdxl6aDE/kd6I75ETTcr0Gi3/6j5orRuubGFVaY3aljJyVp3l9YdPItHqZ3B5oq
p1F3lVQ8IRUE2yMGBHdFvNA77M5WpL4lN+lrNO4NtzA+l1twGhFbUueo4Wk4g/i+
+SBIKD7gMQKBgQClg0mmGD3csSdFxKMmgI0A+jxHAHtTpVtnjmBmTzzV7O+JeGKE
qECtRnwVASnFaKwR283YsnA5pw9uiw1BgAgN7XQs9yByqdMfeKRPOvytQTSUf6Bg
PN85UR8fmKnrUROSN3nSIetvi6AN79hYb1zxllk9MATJsbddBrR5ZuhoAQKBgDjZ
oBXnAju6Lis5BOBiZHLKJue7B0+ieDEczvqiMtg4fOIy7AZi7sn7CaHvcKpdfFOm
MynkCdBHAvuA+pLiHcuySYbFgMlhCfmLtXcN9/TPIYSTcOzLUti+XcO5+bmmE8yJ
ZZV7rIeKSDeX59g5Tu8on6oMwv88f0JRkRCeABeBAoGANb2yRAh6t5YkXF38dIu4
EYirs4LfkMGrEVZU/S4N8ml6z5QUb8bsnwZ/y9u+tBiPlwWLcYAoP73FjnB6tqY1
tsew1Zg0wcz/kZTAewc0Xk82bIBU9M5wnrjVDIf5qkCGK51JBy06mBXAaK8k94Sx
4oIbaR1gOAQvBoWVjwOxjDU=
-----END PRIVATE KEY-----
''';


/// [testCertPem] as a [Uint8List].
Uint8List get testCertBytes => _testCertBytes;
final Uint8List _testCertBytes = pem(testCertPem);

/// [testKeyPem] as a [Uint8List].
Uint8List get testKeyBytes => _testKeyBytes;
final Uint8List _testKeyBytes = pem(testKeyPem);


KeyPair? _ecKeyPairCache;

/// Returns a prime256v1 EC [KeyPair], materialising it once per process.
KeyPair getTestEcKeyPair() {
  if (_ecKeyPairCache != null) return _ecKeyPairCache!;
  _ecKeyPairCache = api().generateEcKeyPair('prime256v1');
  return _ecKeyPairCache!;
}

/// [getTestEcKeyPair]'s private key as a [Uint8List].
Uint8List getTestEcKeyPairPrivateBytes() =>
    pem(getTestEcKeyPair().privateKeyPem);

/// [getTestEcKeyPair]'s public key as a [Uint8List].
Uint8List getTestEcKeyPairPublicBytes() => pem(getTestEcKeyPair().publicKeyPem);


KeyPair? _rsaKeyPairCache2048;

/// Returns a 2048-bit RSA [KeyPair], materialising it once per process.
KeyPair getTestRsaKeyPair() {
  if (_rsaKeyPairCache2048 != null) return _rsaKeyPairCache2048!;
  _rsaKeyPairCache2048 = api().generateRsaKeyPair(2048);
  return _rsaKeyPairCache2048!;
}

/// [getTestRsaKeyPair]'s private key as a [Uint8List].
Uint8List getTestRsaKeyPairPrivateBytes() =>
    pem(getTestRsaKeyPair().privateKeyPem);

/// [getTestRsaKeyPair]'s public key as a [Uint8List].
Uint8List getTestRsaKeyPairPublicBytes() =>
    pem(getTestRsaKeyPair().publicKeyPem);


/// Cached result of [getTestRsaCertAndKey].
(Uint8List, Uint8List)? _rsaCertAndKeyCache;

(Uint8List, Uint8List) getTestRsaCertAndKey() {
  if (_rsaCertAndKeyCache != null) return _rsaCertAndKeyCache!;

  if (Platform.isAndroid) {
    throw UnsupportedError(
      'Shell-based certificate generation is not available on Android. '
      'Use getTestRsaKeyPair() instead.',
    );
  }

  const certPath = '/tmp/plugin_crypto_test_rsa_cert.pem';
  const keyPath = '/tmp/plugin_crypto_test_rsa_key.pem';

  final result = Process.runSync('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-keyout',
    keyPath,
    '-out',
    certPath,
    '-days',
    '365',
    '-nodes',
    '-subj',
    '/CN=PluginCryptoRSAFixture',
  ]);

  if (result.exitCode != 0) {
    throw StateError(
      'Failed to generate RSA test certificate: ${result.stderr}',
    );
  }

  final certBytes = File(certPath).readAsBytesSync();
  final keyBytes = File(keyPath).readAsBytesSync();

  File(certPath).deleteSync();
  File(keyPath).deleteSync();

  _rsaCertAndKeyCache = (certBytes, keyBytes);
  return _rsaCertAndKeyCache!;
}

/// Convenience: RSA cert bytes.
Uint8List getTestRsaCertBytes() => getTestRsaCertAndKey().$1;

/// Convenience: RSA key bytes.
Uint8List getTestRsaKeyBytes() => getTestRsaCertAndKey().$2;


(Uint8List, Uint8List)? _ecCertAndKeyCache;

(Uint8List, Uint8List) getTestEcCert() {
  if (_ecCertAndKeyCache != null) return _ecCertAndKeyCache!;

  if (Platform.isAndroid) {
    throw UnsupportedError(
      'Shell-based certificate generation is not available on Android. '
      'Use getTestEcKeyPair() instead.',
    );
  }

  const keyPath = '/tmp/plugin_crypto_test_ec_cert_key.pem';
  const certPath = '/tmp/plugin_crypto_test_ec_cert.pem';

  final paramResult = Process.runSync('openssl', [
    'ecparam',
    '-genkey',
    '-name',
    'prime256v1',
    '-out',
    keyPath,
  ]);

  if (paramResult.exitCode != 0) {
    throw StateError('Failed to generate EC key: ${paramResult.stderr}');
  }

  final certResult = Process.runSync('openssl', [
    'req',
    '-x509',
    '-key',
    keyPath,
    '-out',
    certPath,
    '-days',
    '365',
    '-subj',
    '/CN=PluginCryptoECFixture',
  ]);

  if (certResult.exitCode != 0) {
    File(keyPath).deleteSync();
    throw StateError(
      'Failed to create EC self-signed certificate: ${certResult.stderr}',
    );
  }

  final keyBytes = File(keyPath).readAsBytesSync();
  final certBytes = File(certPath).readAsBytesSync();

  File(keyPath).deleteSync();
  File(certPath).deleteSync();

  _ecCertAndKeyCache = (certBytes, keyBytes);
  return _ecCertAndKeyCache!;
}

/// Convenience: EC cert bytes.
Uint8List getTestEcCertBytes() => getTestEcCert().$1;

/// Convenience: EC key bytes.
Uint8List getTestEcKeyBytes() => getTestEcCert().$2;
