library;

import 'dart:typed_data';

import '../../crypto_context.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/ts_data.dart';
import '../../cms_operations.dart';
import 'timestamp_client.dart';

class OpenSslTimestampClient implements TimestampClient {
  final CryptoContext _ctx;

  /// Creates an [OpenSslTimestampClient] with the given [CryptoContext].
  const OpenSslTimestampClient(this._ctx);

  @override
  CryptoResult<Uint8List> createRequest(
    Uint8List data, {
    String hashAlgorithm = 'sha256',
    Uint8List? nonce,
  }) {
    if (data.isEmpty) {
      return CryptoFailure(
        TimestampError(reason: 'data must be non-empty'),
      );
    }

    final hash = _hashData(data, hashAlgorithm);
    final algId = TsHashAlgorithm.derForAlgorithm(hashAlgorithm);


    final messageImprint = _encodeSequence([
      ...algId, // AlgorithmIdentifier (pre-encoded DER)
      ..._encodeOctetString(hash), // OCTET STRING(hash)
    ]);

    final version = [0x02, 0x01, 0x01]; // INTEGER(1)

    final parts = <int>[
      ...version,
      ...messageImprint,
    ];

    if (nonce != null && nonce.isNotEmpty) {
      parts.addAll(_encodeIntegerFromBytes(nonce));
    }


    return CryptoSuccess(
      Uint8List.fromList(_encodeSequence(parts)),
    );
  }

  @override
  CryptoResult<TimestampResponse> verifyResponse(
    Uint8List responseData, {
    Uint8List? cert,
  }) {
    if (responseData.isEmpty) {
      return CryptoFailure(
        TimestampError(reason: 'responseData must be non-empty'),
      );
    }

    final parsed = _parseTimestampResponse(responseData);
    return parsed;
  }

  @override
  CryptoResult<bool> verify(Uint8List tokenData, Uint8List data) {
    if (tokenData.isEmpty) {
      return CryptoFailure(
        TimestampError(reason: 'tokenData must be non-empty'),
      );
    }
    if (data.isEmpty) {
      return CryptoFailure(
        TimestampError(reason: 'data must be non-empty'),
      );
    }

    try {
      final cms = CmsOperations(_ctx.bindings);
      final verified = cms.cmsVerify(tokenData);
      if (!verified) {
        return CryptoFailure(
          TimestampError(reason: 'Timestamp token signature verification failed'),
        );
      }

      final tstInfo = _extractTstInfo(tokenData);
      if (tstInfo == null) {
        return CryptoSuccess(true);
      }

      final expectedHash = _hashData(data, 'sha256');
      if (tstInfo.messageImprint != null) {
        if (!_bytesEqual(expectedHash, tstInfo.messageImprint!)) {
          return CryptoFailure(
            TimestampError(
              reason: 'Message imprint does not match the original data',
            ),
          );
        }
      }

      return CryptoSuccess(true);
    } catch (e) {
      return CryptoFailure(
        TimestampError(reason: e.toString()),
      );
    }
  }


  /// Encodes a SEQUENCE from component parts.
  List<int> _encodeSequence(List<int> content) {
    final lenBytes = _encodeLength(content.length);
    return [0x30, ...lenBytes, ...content];
  }

  /// Encodes an OCTET STRING.
  List<int> _encodeOctetString(List<int> bytes) {
    final lenBytes = _encodeLength(bytes.length);
    return [0x04, ...lenBytes, ...bytes];
  }

  /// Encodes an INTEGER from arbitrary bytes (for nonce).
  List<int> _encodeIntegerFromBytes(List<int> bytes) {
    var start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    final trimmed = bytes.sublist(start);
    final lenBytes = _encodeLength(trimmed.length);
    return [0x02, ...lenBytes, ...trimmed];
  }

  /// Encodes a DER length.
  List<int> _encodeLength(int length) {
    if (length < 128) {
      return [length];
    }
    final temp = <int>[];
    var remaining = length;
    while (remaining > 0) {
      temp.insert(0, remaining & 0xFF);
      remaining >>= 8;
    }
    return [0x80 | temp.length, ...temp];
  }


  Uint8List _hashData(Uint8List data, String algorithm) {
    switch (algorithm) {
      case 'sha256':
        return _ctx.operations.sha256(data);
      case 'sha384':
        return _ctx.operations.sha384(data);
      case 'sha512':
        return _ctx.operations.sha512(data);
      default:
        return _ctx.operations.sha256(data);
    }
  }


  /// Parses a TimeStampResp from DER bytes.
  CryptoResult<TimestampResponse> _parseTimestampResponse(
    Uint8List responseData,
  ) {
    try {

      if (responseData.length < 3 || responseData[0] != 0x30) {
        return CryptoFailure(
          TimestampError(reason: 'Invalid TimeStampResp: not a SEQUENCE'),
        );
      }

      var offset = 1;
      final contentEnd = _readLength(responseData, offset);
      offset = contentEnd[0];

      if (offset >= responseData.length || responseData[offset] != 0x30) {
        return CryptoFailure(
          TimestampError(reason: 'Invalid PKIStatusInfo'),
        );
      }
      offset++;
      final pkiEnd = _readLength(responseData, offset);
      offset = pkiEnd[0];
      final pkiData = responseData.sublist(1, pkiEnd[0] + pkiEnd[1]);

      final statusInfo = _parsePkiStatusInfo(pkiData);
      final status = statusInfo.status;
      final statusString = statusInfo.statusString;

      Uint8List? tokenData;
      DateTime? genTime;
      String? serialNumber;
      String? hashAlgorithmOid;
      Uint8List? messageImprint;
      int? nonce;
      String? policyOid;
      TimestampAccuracy? accuracy;

      if (offset < responseData.length && responseData[offset] == 0x30) {
        final tokenStart = offset;
        offset++;
        final tstEnd = _readLength(responseData, offset);
        final tokenEnd = tstEnd[0] + tstEnd[1];
        tokenData = Uint8List.fromList(responseData.sublist(
          tokenStart,
          tokenEnd + 1,
        ));

        final parsed = _extractTstInfo(tokenData);
        if (parsed != null) {
          genTime = parsed.genTime;
          serialNumber = parsed.serialNumber;
          hashAlgorithmOid = parsed.hashAlgorithmOid;
          messageImprint = parsed.messageImprint;
          nonce = parsed.nonce;
          policyOid = parsed.policyOid;
          accuracy = parsed.accuracy;
        }
      }

      return CryptoSuccess(
        TimestampResponse(
          status: status,
          statusString: statusString,
          tokenData: tokenData,
          genTime: genTime,
          serialNumber: serialNumber,
          hashAlgorithmOid: hashAlgorithmOid,
          messageImprint: messageImprint,
          nonce: nonce,
          policyOid: policyOid,
          accuracy: accuracy,
        ),
      );
    } catch (e) {
      return CryptoFailure(
        TimestampError(reason: 'Failed to parse timestamp response: $e'),
      );
    }
  }

  ({TimestampStatus status, String? statusString}) _parsePkiStatusInfo(
    Uint8List data,
  ) {
    var offset = 0;
    if (data[offset] != 0x02) {
      return (status: TimestampStatus.rejection, statusString: null);
    }
    offset++;
    final statLen = _readLength(data, offset);
    offset = statLen[0];
    var statusValue = 0;
    for (var i = 0; i < statLen[1]; i++) {
      statusValue = (statusValue << 8) | data[offset + i];
    }
    offset += statLen[1];

    String? statusString;
    if (offset < data.length && (data[offset] == 0x0C || data[offset] == 0x16)) {
      offset++;
      final strLen = _readLength(data, offset);
      offset = strLen[0];
      statusString = String.fromCharCodes(
        data.sublist(offset, offset + strLen[1]),
      );
    }

    final status = switch (statusValue) {
      0 => TimestampStatus.granted,
      1 => TimestampStatus.grantedWithMods,
      2 => TimestampStatus.rejection,
      3 => TimestampStatus.waiting,
      4 => TimestampStatus.revocationWarning,
      5 => TimestampStatus.revocationNotification,
      _ => TimestampStatus.rejection,
    };

    return (status: status, statusString: statusString);
  }

  /// Reads a DER length. Returns [newOffset, length].
  List<int> _readLength(Uint8List data, int offset) {
    if (offset >= data.length) return [offset, 0];
    final first = data[offset];
    if (first < 128) {
      return [offset + 1, first];
    }
    final numBytes = first & 0x7F;
    var length = 0;
    for (var i = 0; i < numBytes; i++) {
      length = (length << 8) | data[offset + 1 + i];
    }
    return [offset + 1 + numBytes, length];
  }

  /// Attempts to parse TSTInfo from a timestamp token (CMS SignedData).
  _ParsedTstInfo? _extractTstInfo(Uint8List tokenData) {
    try {
      return _ParsedTstInfo(
        genTime: _findGenTime(tokenData),
        serialNumber: _findSerialNumber(tokenData),
        hashAlgorithmOid: null,
        messageImprint: _findMessageImprint(tokenData),
        nonce: null,
        policyOid: null,
        accuracy: null,
      );
    } catch (_) {
      return null;
    }
  }

  DateTime? _findGenTime(Uint8List data) {
    for (var i = 0; i < data.length - 15; i++) {
      if (data[i] == 0x17) {
        final len = data[i + 1];
        if (len == 13 && i + 15 <= data.length) {
          final str = String.fromCharCodes(data.sublist(i + 2, i + 15));
          return _parseUtcTime(str);
        }
      } else if (data[i] == 0x18) {
        final len = data[i + 1];
        if (len >= 14 && i + 2 + len <= data.length) {
          final str = String.fromCharCodes(data.sublist(i + 2, i + 2 + len));
          return _parseGeneralizedTime(str);
        }
      }
    }
    return null;
  }

  String? _findSerialNumber(Uint8List data) {
    for (var i = 2; i < data.length - 3; i++) {
      if (data[i] == 0x02) {
        final len = data[i + 1];
        if (len >= 1 && len <= 20 && i + 2 + len <= data.length) {
          final bytes = data.sublist(i + 2, i + 2 + len);
          return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        }
      }
    }
    return null;
  }

  Uint8List? _findMessageImprint(Uint8List data) {
    for (var i = 0; i < data.length - 4; i++) {
      if (data[i] == 0x04) {
        final len = data[i + 1];
        if ((len == 32 || len == 48 || len == 64) &&
            i + 2 + len <= data.length) {
          return Uint8List.fromList(data.sublist(i + 2, i + 2 + len));
        }
      }
    }
    return null;
  }

  DateTime? _parseUtcTime(String str) {
    try {
      final year = int.parse(str.substring(0, 2));
      final month = int.parse(str.substring(2, 4));
      final day = int.parse(str.substring(4, 6));
      final hour = int.parse(str.substring(6, 8));
      final minute = int.parse(str.substring(8, 10));
      final second = int.parse(str.substring(10, 12));
      final fullYear = year >= 50 ? 1900 + year : 2000 + year;
      return DateTime.utc(fullYear, month, day, hour, minute, second);
    } catch (_) {
      return null;
    }
  }

  DateTime? _parseGeneralizedTime(String str) {
    try {
      final year = int.parse(str.substring(0, 4));
      final month = int.parse(str.substring(4, 6));
      final day = int.parse(str.substring(6, 8));
      final hour = int.parse(str.substring(8, 10));
      final minute = int.parse(str.substring(10, 12));
      final second = int.parse(str.substring(12, 14));
      return DateTime.utc(year, month, day, hour, minute, second);
    } catch (_) {
      return null;
    }
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class _ParsedTstInfo {
  final DateTime? genTime;
  final String? serialNumber;
  final String? hashAlgorithmOid;
  final Uint8List? messageImprint;
  final int? nonce;
  final String? policyOid;
  final TimestampAccuracy? accuracy;

  _ParsedTstInfo({
    this.genTime,
    this.serialNumber,
    this.hashAlgorithmOid,
    this.messageImprint,
    this.nonce,
    this.policyOid,
    this.accuracy,
  });
}
