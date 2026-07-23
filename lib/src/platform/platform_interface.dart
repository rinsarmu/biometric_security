/// The platform interface contract for `biometric_security`.
///
/// This is the single audit boundary between Dart and native code (INV-2): only
/// serializable data crosses it, never key material. It is a
/// [PlatformInterface] so the plugin can later be split into a federated set of
/// packages (`_platform_interface`, `_android`, `_darwin`) without changing the
/// app-facing API.
library;

import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import '../models.dart';
import '../policy.dart';
import '../results.dart';
import 'method_channel.dart';

/// The interface every platform implementation must satisfy.
///
/// The foundation wires only the read-only probes ([initialize],
/// [getAvailability], [getSecurityStatus], [lifecycleEvents]). Security
/// operations (authentication, storage, key management) are defined as
/// contracts on the [BiometricSecurity] facade and are not yet implemented.
abstract class BiometricSecurityPlatform extends PlatformInterface {
  /// Constructs a platform implementation.
  BiometricSecurityPlatform() : super(token: _token);

  static final Object _token = Object();

  static BiometricSecurityPlatform _instance = MethodChannelBiometricSecurity();

  /// The active platform implementation.
  static BiometricSecurityPlatform get instance => _instance;

  /// Overrides the active implementation. Used by federated platform packages
  /// and by tests (via a mock that `extends` this class).
  static set instance(BiometricSecurityPlatform value) {
    PlatformInterface.verifyToken(value, _token);
    _instance = value;
  }

  /// Prepares the platform layer. Idempotent.
  Future<void> initialize(BiometricSecurityConfig config) {
    throw UnimplementedError('initialize() has not been implemented.');
  }

  /// Returns the current biometric availability snapshot.
  Future<BiometricAvailability> getAvailability() {
    throw UnimplementedError('getAvailability() has not been implemented.');
  }

  /// Returns a one-call health snapshot of the protection subsystem.
  Future<SecurityStatus> getSecurityStatus() {
    throw UnimplementedError('getSecurityStatus() has not been implemented.');
  }

  /// A broadcast stream of key lifecycle events.
  Stream<KeyLifecycleEvent> lifecycleEvents() {
    throw UnimplementedError('lifecycleEvents() has not been implemented.');
  }

  /// Runs a biometric-gated key operation and returns a verified session.
  Future<AuthSession> authenticate({
    required String reason,
    required SecurityPolicy policy,
    String? cancelLabel,
    String scope = 'default',
  }) {
    throw UnimplementedError('authenticate() has not been implemented.');
  }

  /// Encrypts [value] under [key] according to [policy].
  Future<void> write({
    required String key,
    required Uint8List value,
    required SecurityPolicy policy,
    String? reason,
  }) {
    throw UnimplementedError('write() has not been implemented.');
  }

  /// Decrypts and returns the value for [key], or `null` if absent.
  Future<Uint8List?> read({required String key, String? reason}) {
    throw UnimplementedError('read() has not been implemented.');
  }

  /// Deletes one secret's ciphertext and metadata.
  Future<void> delete({required String key}) {
    throw UnimplementedError('delete() has not been implemented.');
  }

  /// Deletes all secrets in the current namespace.
  Future<void> deleteAll() {
    throw UnimplementedError('deleteAll() has not been implemented.');
  }

  /// Whether a value exists for [key].
  Future<bool> contains({required String key}) {
    throw UnimplementedError('contains() has not been implemented.');
  }

  /// All stored secret keys.
  Future<Set<String>> keys() {
    throw UnimplementedError('keys() has not been implemented.');
  }

  /// Deletes a secret and destroys its dedicated key material.
  Future<void> revoke({required String key}) {
    throw UnimplementedError('revoke() has not been implemented.');
  }

  /// Destroys all keys in the namespace, then wipes all secrets.
  Future<void> revokeAll() {
    throw UnimplementedError('revokeAll() has not been implemented.');
  }

  /// Clears invalidated key material for a [scope] so it can be reprovisioned.
  Future<void> resetInvalidated({String? scope}) {
    throw UnimplementedError('resetInvalidated() has not been implemented.');
  }

  // --- Opaque ciphertext-blob persistence (non-gated; no key material) ---

  /// Stores an opaque encrypted [blob] under [key].
  Future<void> blobPut({required String key, required Uint8List blob}) {
    throw UnimplementedError('blobPut() has not been implemented.');
  }

  /// Returns the opaque blob for [key], or `null` if absent.
  Future<Uint8List?> blobGet({required String key}) {
    throw UnimplementedError('blobGet() has not been implemented.');
  }

  /// Deletes the blob for [key].
  Future<void> blobDelete({required String key}) {
    throw UnimplementedError('blobDelete() has not been implemented.');
  }

  /// All blob keys.
  Future<Set<String>> blobKeys() {
    throw UnimplementedError('blobKeys() has not been implemented.');
  }

  /// Deletes all blobs.
  Future<void> blobClear() {
    throw UnimplementedError('blobClear() has not been implemented.');
  }
}
