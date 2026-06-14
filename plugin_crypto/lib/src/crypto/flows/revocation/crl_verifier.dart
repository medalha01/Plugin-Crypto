library;

import 'dart:ffi';
import 'dart:typed_data';

import '../../models/crl_data.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../utils/asn1_time.dart';
import '../../utils/bio_utils.dart';
import '../../utils/openssl_error.dart';
import '../../utils/hex_utils.dart';
import '../../utils/x509_loader.dart';
import '../../crypto_context.dart';
import '../../../ffi/openssl_bindings.dart' show X509_CRL, EVP_PKEY;
import 'revocation_verifier.dart';

class OpenSslCrlVerifier implements CrlVerifier {
  final CryptoContext _ctx;

  /// Creates a CRL verifier with the given [CryptoContext].
  const OpenSslCrlVerifier(this._ctx);


  @override
  CryptoResult<CrlInfo> parseCrl(Uint8List crlData) {
    if (crlData.isEmpty) {
      return CryptoFailure(CrlError(reason: 'crlData must be non-empty'));
    }

    final crl = _loadCrl(crlData);
    if (crl == nullptr) {
      return _fail<CrlInfo>(
        CrlError(
          reason: 'Failed to parse CRL data',
          openSslError: getOpenSslError(_ctx.bindings),
        ),
      );
    }
    try {
      return _doParseCrl(crl);
    } finally {
      _ctx.bindings.x509CrlFree(crl);
    }
  }

  CryptoResult<CrlInfo> _doParseCrl(X509_CRL crl) {
    final lastUpdatePtr = _ctx.bindings.x509CrlGet0LastUpdate(crl);
    final nextUpdatePtr = _ctx.bindings.x509CrlGet0NextUpdate(crl);

    final lastUpdate =
        parseAsn1Time(_ctx.bindings, lastUpdatePtr.cast<Void>()) ??
        DateTime(1970);
    final nextUpdate =
        parseAsn1Time(_ctx.bindings, nextUpdatePtr.cast<Void>()) ??
        DateTime(1970);
    final issuer = _getCrlIssuer(crl);

    final revoked = _getRevokedEntries(crl);

    return CryptoSuccess(
      CrlInfo(
        lastUpdate: lastUpdate,
        nextUpdate: nextUpdate,
        issuer: issuer,
        revoked: revoked,
      ),
    );
  }


  @override
  CryptoResult<bool> verifyCrlSignature(Uint8List crlData, Uint8List caCert) {
    if (crlData.isEmpty) {
      return CryptoFailure(CrlError(reason: 'crlData must be non-empty'));
    }
    if (caCert.isEmpty) {
      return CryptoFailure(CrlError(reason: 'caCert must be non-empty'));
    }

    final crl = _loadCrl(crlData);
    if (crl == nullptr) {
      final err = getOpenSslError(_ctx.bindings);
      _ctx.bindings.errClearError();
      return CryptoFailure(
        CrlError(
          reason: 'Failed to parse CRL for signature verification',
          openSslError: err,
        ),
      );
    }
    try {
      final caPkey = _loadCaPublicKey(caCert);
      if (caPkey == nullptr) {
        final err = getOpenSslError(_ctx.bindings);
        _ctx.bindings.errClearError();
        return CryptoFailure(
          CrlError(
            reason: 'Failed to load CA certificate public key',
            openSslError: err,
          ),
        );
      }
      try {
        return _doVerifySignature(crl, caPkey);
      } finally {
        _ctx.bindings.evpPkeyFree(caPkey);
      }
    } finally {
      _ctx.bindings.x509CrlFree(crl);
    }
  }

  CryptoResult<bool> _doVerifySignature(X509_CRL crl, EVP_PKEY caPkey) {
    final result = _ctx.bindings.x509CrlVerify(crl, caPkey);
    if (result < 0) {
      final err = getOpenSslError(_ctx.bindings);
      _ctx.bindings.errClearError();
      return CryptoFailure(
        CrlError(reason: 'X509_CRL_verify error', openSslError: err),
      );
    }
    return CryptoSuccess(result == 1);
  }


  @override
  CryptoResult<CertificateRevocationStatus> checkRevocation(
    Uint8List certData,
    Uint8List crlData,
  ) {
    if (certData.isEmpty) {
      return CryptoFailure(CrlError(reason: 'certData must be non-empty'));
    }
    if (crlData.isEmpty) {
      return CryptoFailure(CrlError(reason: 'crlData must be non-empty'));
    }

    final crlResult = parseCrl(crlData);
    if (crlResult is CryptoFailure<CrlInfo>) {
      return CryptoFailure(crlResult.error);
    }
    final crlInfo = (crlResult as CryptoSuccess<CrlInfo>).value;

    final certSerial = _getCertSerial(certData);
    if (certSerial == null) {
      final err = getOpenSslError(_ctx.bindings);
      _ctx.bindings.errClearError();
      return CryptoFailure(
        CrlError(
          reason: 'Failed to extract certificate serial number',
          openSslError: err,
        ),
      );
    }

    for (final entry in crlInfo.revoked) {
      if (entry.serialNumber == certSerial) {
        return CryptoSuccess(
          CertificateRevocationStatus(
            isRevoked: true,
            revocationDate: entry.revocationDate,
            reasonCode: entry.reason,
          ),
        );
      }
    }

    return CryptoSuccess(CertificateRevocationStatus.notRevoked);
  }


  /// Loads a CRL from PEM or DER data.
  X509_CRL _loadCrl(Uint8List data) {
    return loadCrl(_ctx.bindings, data);
  }

  /// Loads the CA certificate's public key.
  EVP_PKEY _loadCaPublicKey(Uint8List caCert) {
    final bio = bioFromData(_ctx.bindings, caCert);
    if (bio == nullptr) return nullptr;
    try {
      final x509 = _ctx.bindings.pemReadBioX509(bio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) return nullptr;
      try {
        return _ctx.bindings.x509GetPubkey(x509);
      } finally {
        _ctx.bindings.x509Free(x509);
      }
    } finally {
      _ctx.bindings.bioFree(bio);
    }
  }

  /// Extracts the CRL issuer name as an oneline string.
  String _getCrlIssuer(X509_CRL crl) {
    return '(CRL)';
  }

  /// Extracts revoked entries from a CRL.
  List<RevokedEntry> _getRevokedEntries(X509_CRL crl) {
    final revoked = <RevokedEntry>[];
    final stack = _ctx.bindings.x509CrlGetRevoked(crl);
    if (stack == nullptr) return revoked;

    final count = _ctx.bindings.osslSkNum(stack);
    for (var i = 0; i < count; i++) {
      final entryPtr = _ctx.bindings.osslSkValue(stack, i);
      if (entryPtr == nullptr) continue;

      final revokedEntry = entryPtr.cast<Void>();
      final serialAsn1 = _ctx.bindings.x509RevokedGet0SerialNumber(
        revokedEntry,
      );
      final dateAsn1 = _ctx.bindings.x509RevokedGet0RevocationDate(
        revokedEntry,
      );

      final serial = _asn1StringToHex(serialAsn1);
      final date =
          parseAsn1Time(_ctx.bindings, dateAsn1.cast<Void>()) ??
          DateTime(1970);
      revoked.add(RevokedEntry(serialNumber: serial, revocationDate: date));
    }

    return revoked;
  }

  /// Extracts the serial number from a certificate.
  String? _getCertSerial(Uint8List certData) {
    final bio = bioFromData(_ctx.bindings, certData);
    if (bio == nullptr) return null;
    try {
      final x509 = _ctx.bindings.pemReadBioX509(bio, nullptr, nullptr, nullptr);
      if (x509 == nullptr) return null;
      try {
        final serialPtr = _ctx.bindings.x509GetSerialNumber(x509);
        return _asn1StringToHex(serialPtr);
      } finally {
        _ctx.bindings.x509Free(x509);
      }
    } finally {
      _ctx.bindings.bioFree(bio);
    }
  }

  /// Converts an ASN1_STRING (hex serial) to a hex string.
  String _asn1StringToHex(Pointer<Void> asn1Str) {
    if (asn1Str == nullptr) return '';
    final data = _ctx.bindings.asn1StringGet0Data(asn1Str);
    final len = _ctx.bindings.asn1StringLength(asn1Str);
    if (data == nullptr || len <= 0) return '';
    final bytes = data.asTypedList(len);
    final result = bytesToHex(Uint8List.fromList(bytes), skipLeadingZero: true);
    return result.isEmpty ? '0' : result;
  }

  CryptoFailure<T> _fail<T>(CryptoError error) {
    _ctx.bindings.errClearError();
    return CryptoFailure<T>(error);
  }
}
