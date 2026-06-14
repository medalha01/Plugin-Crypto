library;

import '../../../ffi/openssl_bindings.dart';
import '../../models/key_types.dart';
import 'key_creator.dart';
import 'rsa_key_creator.dart';
import 'ec_key_creator.dart';
import 'ml_kem_key_creator.dart';
import 'ml_dsa_key_creator.dart';

class KeyCreatorFactory {
  final OpenSslBindings _bindings;

  /// Registry mapping [Type] → [KeyCreator] factory function.
  final Map<Type, KeyCreator Function()> _registry;

  KeyCreatorFactory(this._bindings) : _registry = {} {
    _registry[RsaKeySpec] = () => RsaKeyCreator(_bindings);
    _registry[EcKeySpec] = () => EcKeyCreator(_bindings);
    _registry[MlKemKeySpec] = () => MlKemKeyCreator(_bindings);
    _registry[MlDsaKeySpec] = () => MlDsaKeyCreator(_bindings);
  }

  KeyCreator? create(KeySpec spec) {
    final ctor = _registry[spec.runtimeType];
    if (ctor == null) return null;
    return ctor();
  }

  /// Returns a [KeyCreator] for [spec], throwing [StateError] if none is
  /// registered.
  KeyCreator createOrThrow(KeySpec spec) {
    final creator = create(spec);
    if (creator == null) {
      throw StateError(
        'No KeyCreator registered for ${spec.runtimeType}. '
        'Call register() before createOrThrow().',
      );
    }
    return creator;
  }

  void register(Type type, KeyCreator Function() creator) {
    _registry[type] = creator;
  }

  /// Removes the registration for [type].
  void unregister(Type type) {
    _registry.remove(type);
  }

  /// Returns the list of all registered spec types.
  List<Type> get registeredTypes => _registry.keys.toList();
}
