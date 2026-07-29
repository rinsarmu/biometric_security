/// The hardware key-vault abstraction and its platform implementation.
library;

import 'dart:typed_data';

import '../exceptions.dart';
import '../platform/platform_interface.dart';
import '../policy.dart';

/// Stores and retrieves per-secret data-encryption keys (DEKs) under hardware
/// protection.
///
/// The DEK is the only key that ever transits Dart, and only transiently; at
/// rest it is held by secure hardware (Android Keystore / iOS Keychain +
/// Secure Enclave), gated by biometrics when the policy requires it. The KEK/
/// hardware key itself never crosses this boundary.
///
/// Implementations must throw [KeyInvalidatedException] (never return a wrong or
/// empty key) when the protecting hardware key was invalidated by an enrollment
/// or lock change.
abstract class KeyVault {
  /// Stores [dek] for [id] under [policy]. Overwrites any existing entry.
  Future<void> storeDek({
    required String id,
    required Uint8List dek,
    required SecurityPolicy policy,
    String? reason,
  });

  /// Retrieves the DEK for [id], prompting when the entry is biometric-gated.
  ///
  /// Throws [KeyInvalidatedException] if the protecting key was invalidated, and
  /// [SecureStorageException] if the entry is missing (i.e. no DEK for [id]).
  Future<Uint8List> loadDek({required String id, String? reason});

  /// Destroys the DEK for [id], making the associated secret unrecoverable.
  Future<void> destroyDek({required String id});

  /// Destroys every DEK in the namespace.
  Future<void> destroyAll();
}

/// Production [KeyVault] backed by the native secure storage of the platform.
///
/// DEK entries are namespaced with a `dek:` prefix so they never collide with
/// anything else. Retrieval of a gated DEK triggers the platform biometric
/// prompt.
class PlatformKeyVault implements KeyVault {
  PlatformKeyVault(this._platform);

  final BiometricSecurityPlatform _platform;

  String _key(String id) => 'dek:$id';

  @override
  Future<void> storeDek({
    required String id,
    required Uint8List dek,
    required SecurityPolicy policy,
    String? reason,
  }) {
    return _platform.write(
      key: _key(id),
      value: dek,
      policy: policy,
      reason: reason,
    );
  }

  @override
  Future<Uint8List> loadDek({required String id, String? reason}) async {
    final dek = await _platform.read(key: _key(id), reason: reason);
    if (dek == null) {
      throw const SecureStorageException('No key material for this secret.');
    }
    return dek;
  }

  @override
  Future<void> destroyDek({required String id}) {
    return _platform.revoke(key: _key(id));
  }

  @override
  Future<void> destroyAll() {
    return _platform.revokeAll();
  }
}
