library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../../ffi/openssl_bindings.dart';
import '../../crypto_api.dart';
import '../../models/certificate_data.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/distinguished_name.dart';
import '../../models/key_types.dart';
import '../../models/signing_algorithm.dart';
import '../key_creation/key_creator.dart';
import 'certificate_builder.dart';
import 'certificate_creator.dart';
import 'certificate_request.dart';

import '../../utils/asn1_time.dart';
import '../../utils/certificate_serializer.dart';
import '../../utils/openssl_error.dart';

class SelfSignedCertCreator implements CertificateCreator {
  final OpenSslBindings _bindings;
  final KeyCreator? _keyCreator;

  const SelfSignedCertCreator(this._bindings, [this._keyCreator]);

  @override
  CryptoResult<CertificateData> create(CertificateRequest request) {
    try {
      request.subject.validate();
      request.issuer.validate();
    } on ArgumentError catch (e) {
      return CryptoFailure(
        ValidationError(
          field: 'CertificateRequest.DistinguishedName',
          reason: (e.message as String?) ?? 'Invalid distinguished name',
        ),
      );
    }

    final builder = CertificateBuilder(_bindings)
        .subjectDn(request.subject)
        .issuerDn(request.issuer)
        .publicKey(request.subjectPublicKey)
        .notBefore(request.notBefore)
        .notAfter(request.notAfter)
        .signWith(request.issuerPrivateKey)
        .signingAlgorithm(request.signingAlgorithm);

    for (final ext in request.extensions) {
      builder.addExtension(ext, '');
    }

    final derResult = builder.build();
    switch (derResult) {
      case CryptoSuccess(:final value):
        return _buildCertificateData(
          value,
          request.subject,
          request.issuer,
          request.notBefore,
          request.notAfter,
        );
      case CryptoFailure(:final error):
        return CryptoFailure(error);
    }
  }

  CryptoResult<CertificateData> createNew({
    required DistinguishedName commonName,
    required Duration validity,
    SigningAlgorithm signingAlgorithm = const SigningAlgorithm(
      hash: HashAlgorithm.sha256,
      keyType: SigningKeyType.rsa,
    ),
  }) {
    if (_keyCreator == null) {
      return CryptoFailure(
        ValidationError(
          field: 'keyCreator',
          reason:
              'SelfSignedCertCreator was constructed without a KeyCreator. '
              'Call create() with an explicit CertificateRequest instead.',
        ),
      );
    }

    final keySpec = switch (signingAlgorithm.keyType) {
      SigningKeyType.rsa => RsaKeySpec(2048),
      SigningKeyType.ec => EcKeySpec('prime256v1'),
      SigningKeyType.ml_dsa => const MlDsaKeySpec(MlDsaParameterSet.mlDsa44),
    };

    final keyResult = _keyCreator.create(keySpec);
    switch (keyResult) {
      case CryptoSuccess(:final value):
        final keyPair = value;
        final now = DateTime.now();
        final request = CertificateRequest(
          subject: commonName,
          issuer: commonName,
          subjectPublicKey: keyPair,
          issuerPrivateKey: keyPair,
          notBefore: now,
          notAfter: now.add(validity),
          signingAlgorithm: signingAlgorithm,
        );
        return create(request);
      case CryptoFailure(:final error):
        return CryptoFailure(error);
    }
  }

  /// Builds the complete [CertificateData] output from DER bytes and metadata.
  CryptoResult<CertificateData> _buildCertificateData(
    Uint8List derBytes,
    DistinguishedName subject,
    DistinguishedName issuer,
    DateTime notBefore,
    DateTime notAfter,
  ) {
    final result = _derToPemBytes(derBytes);
    switch (result) {
      case CryptoSuccess(:final value):
        final (:x509, :pemString) = value;
        try {
          return _parseX509Fields(
            x509,
            derBytes,
            pemString,
            subject,
            issuer,
            notBefore,
            notAfter,
          );
        } finally {
          _bindings.x509Free(x509);
        }
      case CryptoFailure(:final error):
        return CryptoFailure(error);
    }
  }

  /// Converts DER-encoded certificate bytes to PEM format.
  CryptoResult<({X509 x509, String pemString})> _derToPemBytes(
    Uint8List derBytes,
  ) {
    final derBio = _bindings.bioNew(_bindings.bioSMem());
    if (derBio == nullptr) {
      return CryptoFailure(CertificateError(reason: 'BIO_new for DER input'));
    }

    final dp = calloc<Uint8>(derBytes.length);
    try {
      dp.asTypedList(derBytes.length).setAll(0, derBytes);
      _bindings.bioWrite(derBio, dp.cast(), derBytes.length);
    } finally {
      calloc.free(dp);
    }

    final x509 = _bindings.d2iX509Bio(derBio, nullptr);
    _bindings.bioFree(derBio);

    if (x509 == nullptr) {
      final errMsg = getOpenSslError(_bindings);
      return CryptoFailure(
        CertificateError(
          reason: 'Failed to re-parse DER certificate',
          openSslError: errMsg,
        ),
      );
    }

    final pemResult = derToPem(_bindings, derBytes);
    switch (pemResult) {
      case CryptoSuccess(:final value):
        return CryptoSuccess((x509: x509, pemString: value));
      case CryptoFailure(:final error):
        _bindings.x509Free(x509);
        return CryptoFailure(error);
    }
  }

  /// Parses X509 fields from the certificate and builds the [CertificateData].
  CryptoResult<CertificateData> _parseX509Fields(
    X509 x509,
    Uint8List derBytes,
    String pemString,
    DistinguishedName subject,
    DistinguishedName issuer,
    DateTime notBefore,
    DateTime notAfter,
  ) {
    final subjName = _bindings.x509GetSubjectName(x509);
    final issName = _bindings.x509GetIssuerName(x509);
    final sn = _bindings.x509GetSerialNumber(x509);
    final nb = _bindings.x509GetNotBefore(x509);
    final na = _bindings.x509GetNotAfter(x509);

    String nameOneLine(X509_NAME name) {
      if (name == nullptr) return '(unknown)';
      final ptr = _bindings.x509NameOneline(name, nullptr, 0);
      if (ptr == nullptr) return '(unknown)';
      try {
        return ptr.toDartString();
      } finally {
        _bindings.cryptoFree(ptr.cast(), nullptr, 0);
      }
    }

    final subjectOneline = nameOneLine(subjName);
    final issuerOneline = nameOneLine(issName);

    final parsedNb =
        parseAsn1Time(_bindings, nb) ?? DateTime(1970);
    final parsedNa =
        parseAsn1Time(_bindings, na) ?? DateTime(1970);

    final parsed = X509Certificate(
      subject: subjectOneline,
      issuer: issuerOneline,
      serialNumber: sn != nullptr ? 'present' : '(unavailable)',
      notBefore: parsedNb,
      notAfter: parsedNa,
      rawDer: derBytes,
    );

    return CryptoSuccess(
      CertificateData(
        derBytes: derBytes,
        pemString: pemString,
        parsed: parsed,
        subjectDn: subjectOneline,
        issuerDn: issuerOneline,
        notBefore: notBefore,
        notAfter: notAfter,
      ),
    );
  }
}
