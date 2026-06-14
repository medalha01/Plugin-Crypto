library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../../../ffi/openssl_bindings.dart';
import '../../crypto_api.dart';
import '../../models/crypto_error.dart';
import '../../models/crypto_result.dart';
import '../../models/distinguished_name.dart';
import '../../models/signing_algorithm.dart';
import '../../utils/bio_utils.dart';
import '../../utils/certificate_serializer.dart';
import '../../utils/openssl_error.dart';
import '../../constants.dart';
import '../../utils/x509_name_builder.dart';

class CertificateBuilder {
  final OpenSslBindings _b;

  DistinguishedName? _subjectDn;
  DistinguishedName? _issuerDn;
  KeyPair? _publicKey;
  KeyPair? _issuerKey;
  DateTime? _notBefore;
  DateTime? _notAfter;
  SigningAlgorithm _signingAlgorithm = const SigningAlgorithm(
    hash: HashAlgorithm.sha256,
    keyType: SigningKeyType.rsa,
  );

  final List<_ExtDescriptor> _extensions = [];

  /// Creates a [CertificateBuilder] with injected FFI bindings.
  CertificateBuilder(this._b);


  /// Sets the subject Distinguished Name.
  CertificateBuilder subjectDn(DistinguishedName dn) {
    dn.validate();
    _subjectDn = dn;
    return this;
  }

  CertificateBuilder issuerDn(DistinguishedName dn) {
    dn.validate();
    _issuerDn = dn;
    return this;
  }

  /// Sets the subject's public key pair.
  CertificateBuilder publicKey(KeyPair keyPair) {
    _publicKey = keyPair;
    return this;
  }

  /// Sets a validity period starting from now.
  CertificateBuilder validityPeriod(Duration duration) {
    _notBefore = DateTime.now();
    _notAfter = _notBefore!.add(duration);
    return this;
  }

  /// Sets the validity start date.
  CertificateBuilder notBefore(DateTime dt) {
    _notBefore = dt;
    return this;
  }

  /// Sets the validity end date.
  CertificateBuilder notAfter(DateTime dt) {
    _notAfter = dt;
    return this;
  }

  CertificateBuilder addBasicConstraints({bool ca = false, int? pathLen}) {
    final value = ca
        ? (pathLen != null
              ? 'critical,CA:TRUE,pathlen:$pathLen'
              : 'critical,CA:TRUE')
        : 'critical,CA:FALSE';
    _extensions.add(_ExtDescriptor(nidName: 'basicConstraints', value: value));
    return this;
  }

  /// Adds the KeyUsage extension.
  CertificateBuilder addKeyUsage({
    bool digitalSignature = true,
    bool keyEncipherment = false,
    bool dataEncipherment = false,
  }) {
    final usages = <String>[];
    if (digitalSignature) usages.add('digitalSignature');
    if (keyEncipherment) usages.add('keyEncipherment');
    if (dataEncipherment) usages.add('dataEncipherment');
    _extensions.add(
      _ExtDescriptor(nidName: 'keyUsage', value: usages.join(',')),
    );
    return this;
  }

  /// Adds the SubjectAltName extension.
  CertificateBuilder addSubjectAltName({
    List<String>? dnsNames,
    List<String>? ipAddresses,
  }) {
    final parts = <String>[];
    if (dnsNames != null) {
      for (final dns in dnsNames) {
        parts.add('DNS:$dns');
      }
    }
    if (ipAddresses != null) {
      for (final ip in ipAddresses) {
        parts.add('IP:$ip');
      }
    }
    if (parts.isNotEmpty) {
      _extensions.add(
        _ExtDescriptor(nidName: 'subjectAltName', value: parts.join(',')),
      );
    }
    return this;
  }

  /// Adds a custom extension by OID or name.
  CertificateBuilder addExtension(
    String oidOrName,
    String value, {
    bool critical = false,
  }) {
    final prefix = critical ? 'critical,' : '';
    _extensions.add(_ExtDescriptor(nidName: oidOrName, value: '$prefix$value'));
    return this;
  }

  CertificateBuilder signWith(KeyPair issuerKey) {
    _issuerKey = issuerKey;
    return this;
  }

  /// Sets the signing algorithm.
  CertificateBuilder signingAlgorithm(SigningAlgorithm alg) {
    _signingAlgorithm = alg;
    return this;
  }


  /// Builds the certificate and returns DER-encoded bytes wrapped in
  /// [CryptoResult].
  CryptoResult<Uint8List> build() {
    final validationError = _validate();
    if (validationError != null) return CryptoFailure(validationError);

    return _buildDer();
  }

  /// Builds the certificate and returns a PEM string wrapped in
  /// [CryptoResult].
  CryptoResult<String> buildPem() {
    final derResult = build();
    switch (derResult) {
      case CryptoSuccess(:final value):
        return _derToPem(value);
      case CryptoFailure(:final error):
        return CryptoFailure(error);
    }
  }


  CryptoError? _validate() {
    if (_subjectDn == null) {
      return ValidationError(
        field: 'subjectDn',
        reason: 'must call subjectDn() before build()',
      );
    }
    if (_issuerDn == null) {
      return ValidationError(
        field: 'issuerDn',
        reason: 'must call issuerDn() before build()',
      );
    }
    if (_publicKey == null) {
      return ValidationError(
        field: 'publicKey',
        reason: 'must call publicKey() before build()',
      );
    }
    if (_issuerKey == null) {
      return ValidationError(
        field: 'issuerKey',
        reason: 'must call signWith() before build()',
      );
    }
    if (_notBefore == null) {
      return ValidationError(
        field: 'notBefore',
        reason: 'must call notBefore() or validityPeriod() before build()',
      );
    }
    if (_notAfter == null) {
      return ValidationError(
        field: 'notAfter',
        reason: 'must call notAfter() or validityPeriod() before build()',
      );
    }

    if (_notBefore!.isAfter(_notAfter!) ||
        _notBefore!.isAtSameMomentAs(_notAfter!)) {
      return ValidationError(
        field: 'validity',
        reason:
            'notBefore ($_notBefore) must be strictly before '
            'notAfter ($_notAfter)',
      );
    }

    return null;
  }


  CryptoResult<Uint8List> _buildDer() {
    final cert = _b.x509New();
    if (cert == nullptr) {
      return _fail<Uint8List>(
        CertificateError(reason: 'X509_new returned null'),
      );
    }

    try {
      final verErr = _setCertVersion(cert);
      if (verErr != null) return verErr;

      final pubErr = _setCertPublicKey(cert, _publicKey!);
      if (pubErr != null) return pubErr;

      final namesErr = _setCertNames(cert, _subjectDn!, _issuerDn!);
      if (namesErr != null) return namesErr;

      final validErr = _setCertValidity(cert, _notBefore!, _notAfter!);
      if (validErr != null) return validErr;

      if (_extensions.isNotEmpty) {
        final addExtResult = _addExtensions(cert);
        if (addExtResult != null) return addExtResult;
      }

      final signErr = _signCert(cert, _issuerKey!);
      if (signErr != null) return signErr;

      return _serializeCertToDer(cert);
    } finally {
      _b.errClearError();
      _b.x509Free(cert);
    }
  }

  /// Sets X.509 version to v3 (OpenSSL uses 0-indexed, so v3 == 2).
  /// Returns null on success, or a failure to propagate.
  CryptoResult<Uint8List>? _setCertVersion(X509 cert) {
    final verResult = _b.x509SetVersion(cert, 2);
    if (verResult != 1) {
      return _fail<Uint8List>(
        CertificateError(
          reason: 'X509_set_version',
          openSslError: getOpenSslError(_b),
        ),
      );
    }
    return null;
  }

  /// Loads [keyPair]'s public key and sets it on [cert].
  /// Returns null on success, or a failure to propagate.
  CryptoResult<Uint8List>? _setCertPublicKey(X509 cert, KeyPair keyPair) {
    final subjPubKey = _loadPublicKey(keyPair.publicKeyPem);
    if (subjPubKey == nullptr) {
      return _fail<Uint8List>(
        CertificateError(
          reason: 'Failed to load subject public key',
          openSslError: getOpenSslError(_b),
        ),
      );
    }
    try {
      final pubResult = _b.x509SetPubkey(cert, subjPubKey);
      if (pubResult != 1) {
        return _fail<Uint8List>(
          CertificateError(
            reason: 'X509_set_pubkey',
            openSslError: getOpenSslError(_b),
          ),
        );
      }
    } finally {
      _b.evpPkeyFree(subjPubKey);
    }
    return null;
  }

  /// Builds and sets the [subject] and [issuer] Distinguished Names on [cert].
  /// Returns null on success, or a failure to propagate.
  CryptoResult<Uint8List>? _setCertNames(
    X509 cert,
    DistinguishedName subject,
    DistinguishedName issuer,
  ) {
    final subjName = _buildX509Name(subject);
    if (subjName == nullptr) {
      return _fail<Uint8List>(
        CertificateError(reason: 'Failed to build subject X509_NAME'),
      );
    }
    try {
      final setSubjResult = _b.x509SetSubjectName(cert, subjName);
      if (setSubjResult != 1) {
        return _fail<Uint8List>(
          CertificateError(
            reason: 'X509_set_subject_name',
            openSslError: getOpenSslError(_b),
          ),
        );
      }
    } finally {
      _b.x509NameFree(subjName);
    }

    final issName = _buildX509Name(issuer);
    if (issName == nullptr) {
      return _fail<Uint8List>(
        CertificateError(reason: 'Failed to build issuer X509_NAME'),
      );
    }
    try {
      final setIssResult = _b.x509SetIssuerName(cert, issName);
      if (setIssResult != 1) {
        return _fail<Uint8List>(
          CertificateError(
            reason: 'X509_set_issuer_name',
            openSslError: getOpenSslError(_b),
          ),
        );
      }
    } finally {
      _b.x509NameFree(issName);
    }
    return null;
  }

  /// Sets the [notBefore] and [notAfter] validity times on [cert].
  /// Returns null on success, or a failure to propagate.
  CryptoResult<Uint8List>? _setCertValidity(
    X509 cert,
    DateTime notBefore,
    DateTime notAfter,
  ) {
    final nbTime = _dateTimeToAsn1Time(notBefore);
    if (nbTime != nullptr) {
      _b.x509SetNotBefore(cert, nbTime);
    } else {
      return _fail<Uint8List>(
        CertificateError(reason: 'Failed to set notBefore time'),
      );
    }

    final naTime = _dateTimeToAsn1Time(notAfter);
    if (naTime != nullptr) {
      _b.x509SetNotAfter(cert, naTime);
    } else {
      return _fail<Uint8List>(
        CertificateError(reason: 'Failed to set notAfter time'),
      );
    }
    return null;
  }

  /// Signs [cert] using [issuerKey]'s private key and the selected
  /// [SigningAlgorithm].  Returns null on success, or a failure to propagate.
  CryptoResult<Uint8List>? _signCert(X509 cert, KeyPair issuerKey) {
    final issuerPkey = _loadPrivateKey(issuerKey.privateKeyPem);
    if (issuerPkey == nullptr) {
      return _fail<Uint8List>(
        CertificateError(
          reason: 'Failed to load issuer private key',
          openSslError: getOpenSslError(_b),
        ),
      );
    }
    try {
      final md = _signingAlgorithm.keyType == SigningKeyType.ml_dsa
          ? nullptr
          : _signingAlgorithm.hash.evpMd(_b);

      final signResult = _b.x509Sign(cert, issuerPkey, md);
      if (signResult <= 0) {
        return _fail<Uint8List>(
          CertificateError(
            reason: 'X509_sign',
            openSslError: getOpenSslError(_b),
          ),
        );
      }
    } finally {
      _b.evpPkeyFree(issuerPkey);
    }
    return null;
  }

  /// Serializes [cert] to DER bytes via a memory BIO.
  CryptoResult<Uint8List> _serializeCertToDer(X509 cert) {
    final derBio = _b.bioNew(_b.bioSMem());
    if (derBio == nullptr) {
      return _fail<Uint8List>(
        CertificateError(reason: 'BIO_new for DER serialization'),
      );
    }
    try {
      final writeResult = _b.i2dX509Bio(derBio, cert);
      if (writeResult != 1) {
        return _fail<Uint8List>(
          CertificateError(
            reason: 'i2d_X509_bio',
            openSslError: getOpenSslError(_b),
          ),
        );
      }
      return CryptoSuccess(bioToBytes(_b, derBio));
    } finally {
      _b.bioFree(derBio);
    }
  }


  X509_NAME _buildX509Name(DistinguishedName dn) {
    try {
      return X509NameBuilder(_b).build(dn);
    } on StateError {
      return nullptr;
    }
  }


  CryptoFailure<Uint8List>? _addExtensions(X509 cert) {
    final ctx = calloc<Int8>(
      x509v3CtxAllocSize,
    ); // Conservative sizeof(X509V3_CTX)
    try {
      _b.x509V3SetCtx(ctx.cast(), cert, cert, nullptr, nullptr, 0);

      for (final ext in _extensions) {
        final nidUtf8 = ext.nidName.toNativeUtf8();
        final nid = _b.objTxt2nid(nidUtf8.cast());
        calloc.free(nidUtf8);

        if (nid == 0) {
          return _fail<Uint8List>(
            CertificateError(reason: 'Unknown extension: ${ext.nidName}'),
          );
        }

        final valueUtf8 = ext.value.toNativeUtf8();
        final extension = _b.x509V3ExtConfNid(
          nullptr,
          ctx.cast<Void>(),
          nid,
          valueUtf8.cast(),
        );
        calloc.free(valueUtf8);

        if (extension == nullptr) {
          return _fail<Uint8List>(
            CertificateError(
              reason: 'X509V3_EXT_conf_nid(${ext.nidName})',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        final addResult = _b.x509AddExt(cert, extension, -1);
        if (addResult != 1) {
          _b.x509ExtensionFree(extension);
          return _fail<Uint8List>(
            CertificateError(
              reason: 'X509_add_ext(${ext.nidName})',
              openSslError: getOpenSslError(_b),
            ),
          );
        }

        _b.x509ExtensionFree(extension);
      }
    } finally {
      calloc.free(ctx);
    }

    return null;
  }


  EVP_PKEY _loadPublicKey(String pem) {
    final bio = bioFromString(_b, pem);
    if (bio == nullptr) return nullptr;
    try {
      return _b.pemReadBioPubkey(bio, nullptr, nullptr, nullptr);
    } finally {
      _b.bioFree(bio);
    }
  }

  EVP_PKEY _loadPrivateKey(String pem) {
    final bio = bioFromString(_b, pem);
    if (bio == nullptr) return nullptr;
    try {
      return _b.pemReadBioPrivateKey(bio, nullptr, nullptr, nullptr);
    } finally {
      _b.bioFree(bio);
    }
  }


  ASN1_TIME _dateTimeToAsn1Time(DateTime dt) {
    final epoch = dt.toUtc().millisecondsSinceEpoch ~/ 1000;
    return _b.asn1TimeSet(nullptr, epoch);
  }


  CryptoResult<String> _derToPem(Uint8List derBytes) {
    return derToPem(_b, derBytes);
  }


  CryptoFailure<T> _fail<T>(CryptoError error) => CryptoFailure<T>(error);
}

/// Internal extension descriptor.
class _ExtDescriptor {
  final String nidName;
  final String value;
  const _ExtDescriptor({required this.nidName, required this.value});
}
