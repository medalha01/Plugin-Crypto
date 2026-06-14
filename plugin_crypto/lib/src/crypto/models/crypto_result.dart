library;

import 'crypto_error.dart';

/// Base sealed class for all crypto operation results.
sealed class CryptoResult<T> {
  const CryptoResult._();
}

/// Successful result containing a value of type [T].
class CryptoSuccess<T> extends CryptoResult<T> {
  final T value;

  const CryptoSuccess(this.value) : super._();
}

/// Failed result containing a [CryptoError] with full diagnostic context.
class CryptoFailure<T> extends CryptoResult<T> {
  final CryptoError error;

  const CryptoFailure(this.error) : super._();
}
