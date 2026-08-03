/// The app-facing facade for the `biometric_security` package.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'enums.dart';
import 'exceptions.dart';
import 'models.dart';
import 'platform/platform_interface.dart';
import 'policy.dart';
import 'results.dart';
import 'secret_key.dart';
import 'storage/blob_store.dart';
import 'storage/key_vault.dart';
import 'storage/secure_storage.dart';

/// Thrown by API surface that is declared but not implemented in this release.
Never _notYetImplemented(String api) => throw UnimplementedError(
  '$api is part of the public API but is not implemented in this release.',
);

/// The single entry point to the biometric security layer.
///
/// Most apps import only `package:biometric_security/biometric_security.dart`
/// and use this class plus [SecurityPolicy].
///
/// ```dart
/// final security = BiometricSecurity();
/// await security.initialize();
/// final availability = await security.getAvailability();
/// ```
class BiometricSecurity {
  /// Creates a facade. Construction is cheap and performs no I/O until
  /// [initialize] is called.
  BiometricSecurity({
    BiometricSecurityConfig config = const BiometricSecurityConfig(),
    BiometricSecurityPlatform? platform,
    SecureStorage? storage,
  }) : _config = config,
       _platform = platform ?? BiometricSecurityPlatform.instance {
    _storage =
        storage ??
        SecureStorage(
          keyVault: PlatformKeyVault(_platform),
          blobStore: PlatformBlobStore(_platform),
        );
    appLock = AppLock._(this);
    features = FeatureProtection._(this);
  }

  final BiometricSecurityConfig _config;
  final BiometricSecurityPlatform _platform;
  late final SecureStorage _storage;
  bool _initialized = false;

  /// The app-lock sub-API.
  late final AppLock appLock;

  /// The feature-protection sub-API.
  late final FeatureProtection features;

  /// The configured default policy, applied when a call omits its own.
  SecurityPolicy get defaultPolicy => _config.defaultPolicy;

  // ------------------------------------------------------------------------
  // Initialization
  // ------------------------------------------------------------------------

  /// Prepares the platform layer. Idempotent — safe to call more than once.
  ///
  /// Throws [UnsupportedPlatformException] where there is no implementation.
  Future<void> initialize() async {
    if (_initialized) return;
    await _platform.initialize(_config);
    _initialized = true;
  }

  /// Whether [initialize] has completed.
  bool get isInitialized => _initialized;

  void _requireInitialized() {
    if (!_initialized) throw const NotInitializedException();
  }

  // ------------------------------------------------------------------------
  // Availability / status
  // ------------------------------------------------------------------------

  /// Returns the full "supported / enrolled / available" snapshot.
  Future<BiometricAvailability> getAvailability() {
    _requireInitialized();
    return _platform.getAvailability();
  }

  /// Convenience: whether the user can authenticate right now.
  Future<bool> get canAuthenticate async =>
      (await getAvailability()).canAuthenticate;

  /// Returns a one-call health snapshot of the protection subsystem.
  Future<SecurityStatus> getSecurityStatus() {
    _requireInitialized();
    return _platform.getSecurityStatus();
  }

  // ------------------------------------------------------------------------
  // Authentication
  // ------------------------------------------------------------------------

  /// Performs a cryptographically-backed authentication and returns a verified
  /// [AuthSession] on success.
  Future<AuthSession> authenticate({
    required String reason,
    SecurityPolicy? policy,
    String? cancelLabel,
    String scope = 'default',
  }) {
    _requireInitialized();
    return _platform.authenticate(
      reason: reason,
      policy: policy ?? defaultPolicy,
      cancelLabel: cancelLabel,
      scope: scope,
    );
  }

  /// Signs a server-provided [challenge] with a biometric-gated hardware key.
  Future<SignatureResult> signChallenge({
    required Uint8List challenge,
    required String reason,
    SecurityPolicy? policy,
  }) {
    _requireInitialized();
    return _notYetImplemented('signChallenge()');
  }

  // ------------------------------------------------------------------------
  // Storage
  // ------------------------------------------------------------------------

  /// Encrypts and stores [value] under [key].
  Future<void> write({
    required SecretKey key,
    required String value,
    SecurityPolicy? policy,
    String? reason,
  }) {
    return writeBytes(
      key: key,
      value: Uint8List.fromList(utf8.encode(value)),
      policy: policy,
      reason: reason,
    );
  }

  /// Binary variant of [write].
  Future<void> writeBytes({
    required SecretKey key,
    required Uint8List value,
    SecurityPolicy? policy,
    String? reason,
  }) {
    _requireInitialized();
    return _storage.write(
      key: key.value,
      value: value,
      policy: policy ?? defaultPolicy,
      reason: reason,
    );
  }

  /// Decrypts and returns the value for [key], or `null` if absent.
  Future<String?> read({required SecretKey key, String? reason}) async {
    final bytes = await readBytes(key: key, reason: reason);
    return bytes == null ? null : utf8.decode(bytes);
  }

  /// Binary variant of [read].
  Future<Uint8List?> readBytes({required SecretKey key, String? reason}) {
    _requireInitialized();
    return _storage.read(key: key.value, reason: reason);
  }

  /// Whether a value exists for [key]. Does not decrypt and does not prompt.
  Future<bool> contains({required SecretKey key}) {
    _requireInitialized();
    return _storage.containsKey(key.value);
  }

  /// Whether the biometric-bound key protecting [key] has been **invalidated**
  /// (e.g. by a biometric-enrollment change or the device lock being removed).
  ///
  /// This is a lightweight, **non-prompting** check — it never shows a biometric
  /// dialog and never returns the secret. Returns `false` when [key] does not
  /// exist or was stored without a biometric gate (`SecurityPolicy.encryptedOnly`).
  ///
  /// Use it to decide, before showing a login prompt, whether the user must
  /// re-enable biometric protection:
  ///
  /// ```dart
  /// if (await security.isInvalidated(key: pin)) {
  ///   await security.revoke(key: pin); // clear the dead secret
  ///   // ...ask the user to enable biometric login again
  /// }
  /// ```
  Future<bool> isInvalidated({required SecretKey key}) {
    _requireInitialized();
    return _storage.isInvalidated(key.value);
  }

  /// All stored keys (metadata only; no decryption, no prompt). Internal
  /// bookkeeping keys (e.g. the app-lock marker) are excluded.
  Future<Set<SecretKey>> keys() async {
    _requireInitialized();
    final raw = await _storage.keys();
    return raw.where((k) => !k.startsWith('__')).map(SecretKey.new).toSet();
  }

  /// Rotates the key material protecting [key]: re-keys and re-encrypts the
  /// stored value under a fresh DEK. Prompts once when the secret is gated.
  ///
  /// The new DEK is protected under [policy] (or the configured default); pass
  /// the same policy the secret was written with to preserve its protection.
  Future<void> rotateKey({
    required SecretKey key,
    SecurityPolicy? policy,
    String? reason,
  }) {
    _requireInitialized();
    return _storage.rotate(
      key: key.value,
      policy: policy ?? defaultPolicy,
      reason: reason,
    );
  }

  // ------------------------------------------------------------------------
  // Enable / disable protection (contract only)
  // ------------------------------------------------------------------------

  /// Upgrades an existing secret to a biometric-gated [policy].
  Future<void> enableProtection({
    required SecretKey key,
    required SecurityPolicy policy,
    String? reason,
  }) {
    _requireInitialized();
    return _notYetImplemented('enableProtection()');
  }

  /// Downgrades a secret to encrypted-only, removing the biometric gate.
  Future<void> disableProtection({required SecretKey key, String? reason}) {
    _requireInitialized();
    return _notYetImplemented('disableProtection()');
  }

  /// The policy currently protecting a stored secret, or `null` if absent.
  Future<SecurityPolicy?> policyOf({required SecretKey key}) {
    _requireInitialized();
    return _notYetImplemented('policyOf()');
  }

  // ------------------------------------------------------------------------
  // Revocation / deletion (contract only)
  // ------------------------------------------------------------------------

  /// Deletes one secret's ciphertext and its DEK. Idempotent.
  Future<void> delete({required SecretKey key}) {
    _requireInitialized();
    return _storage.delete(key.value);
  }

  /// Deletes all secrets in this namespace. Idempotent.
  Future<void> deleteAll() {
    _requireInitialized();
    return _storage.deleteAll();
  }

  /// Deletes one secret and destroys its dedicated key material, making it
  /// cryptographically unrecoverable.
  Future<void> revoke({required SecretKey key}) {
    _requireInitialized();
    return _storage.revoke(key.value);
  }

  /// Destroys all keys in this namespace (a hard kill-switch), then wipes all
  /// secrets.
  Future<void> revokeAll() {
    _requireInitialized();
    return _storage.revokeAll();
  }

  // ------------------------------------------------------------------------
  // Lifecycle events / invalidation recovery
  // ------------------------------------------------------------------------

  /// A broadcast stream of key lifecycle events (enrollment changed, key
  /// invalidated, reprovision required, integrity risk). Advisory only.
  Stream<KeyLifecycleEvent> get lifecycleEvents => _platform.lifecycleEvents();

  /// Clears dead key material for a [scope] after a [KeyInvalidatedException],
  /// so fresh secrets can be provisioned. Does not touch unrelated scopes.
  Future<void> resetInvalidated({String? scope}) {
    _requireInitialized();
    return _platform.resetInvalidated(scope: scope);
  }
}

/// The app-lock sub-API, obtained from [BiometricSecurity.appLock].
///
/// "Unlocked" means a real authentication happened, not a flag a hooked
/// process can flip.
class AppLock {
  AppLock._(this._owner);

  final BiometricSecurity _owner;

  static const SecretKey _marker = SecretKey('__bsec_app_lock__');
  static const String _scope = 'app_lock';

  SecurityPolicy? _policy;

  /// Enables app-lock with the given [policy]. Persists an enabled marker; the
  /// unlock key is provisioned lazily on the first [unlock].
  Future<void> enable({SecurityPolicy? policy, required String reason}) async {
    _owner._requireInitialized();
    _policy = policy ?? _owner.defaultPolicy;
    // The marker only records that app-lock is on; it is not itself sensitive.
    await _owner.write(
      key: _marker,
      value: '1',
      policy: const SecurityPolicy.encryptedOnly(),
    );
  }

  /// Disables app-lock and destroys its key material.
  Future<void> disable() async {
    _owner._requireInitialized();
    _policy = null;
    await _owner.delete(key: _marker);
    await _owner.resetInvalidated(scope: _scope);
  }

  /// Whether app-lock is currently enabled.
  Future<bool> isEnabled() {
    _owner._requireInitialized();
    return _owner.contains(key: _marker);
  }

  /// Prompts the user and returns a verified session, or throws.
  Future<AuthSession> unlock({required String reason}) {
    _owner._requireInitialized();
    return _owner.authenticate(
      reason: reason,
      policy: _policy ?? _owner.defaultPolicy,
      scope: _scope,
    );
  }
}

/// The feature-protection sub-API, obtained from
/// [BiometricSecurity.features].
class FeatureProtection {
  FeatureProtection._(this._owner);

  final BiometricSecurity _owner;
  final Map<String, SecurityPolicy> _policies = {};

  /// Registers or replaces the policy guarding [featureId].
  ///
  /// Note: registered policies are held in memory for the lifetime of this
  /// instance, so register them at startup. They are not persisted across
  /// app launches.
  Future<void> setPolicy({
    required String featureId,
    required SecurityPolicy policy,
  }) async {
    _owner._requireInitialized();
    _policies[featureId] = policy;
  }

  /// Runs the gate for [featureId]. Returns a session on success; throws on
  /// denial. Succeeds without prompting if no policy is registered.
  Future<AuthSession> guard({
    required String featureId,
    required String reason,
  }) {
    _owner._requireInitialized();
    final policy = _policies[featureId];
    if (policy == null) {
      // No gate registered: succeed trivially without a prompt.
      return Future.value(
        AuthSession(
          token: '',
          authenticatedAt: DateTime.now(),
          securityLevel: SecurityLevel.none,
        ),
      );
    }
    return _owner.authenticate(
      reason: reason,
      policy: policy,
      scope: 'feature.$featureId',
    );
  }

  /// Removes a feature's protection.
  Future<void> clearPolicy({required String featureId}) async {
    _owner._requireInitialized();
    _policies.remove(featureId);
  }
}
