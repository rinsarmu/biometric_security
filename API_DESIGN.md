# `biometric_security` — Public Dart API Design

> Status: **API design only. No production functionality.**
> Date: 2026-07-23
> Sources: [`RESEARCH.md`](RESEARCH.md), [`ARCHITECTURE.md`](ARCHITECTURE.md)
> Scope: the complete public Dart surface of the app-facing `biometric_security` package.

The signatures below are the **contract**; method bodies are intentionally omitted (`// designed, not implemented`). Everything honors the architecture invariants — especially **INV-1** (security gate is a key, not a boolean), **INV-3** (never silently destroy secrets), and **INV-4** (no forced modality).

### Table of Contents
- [0. Design principles](#0-design-principles)
- [1. The five-way biometric distinction](#1-the-five-way-biometric-distinction-read-this-first)
- [2. Enums](#2-enums)
- [3. Policy types](#3-policy-types)
- [4. Models & status objects](#4-models--status-objects)
- [5. Results](#5-results)
- [6. Exceptions](#6-exceptions)
- [7. The facade & its APIs](#7-the-facade-biometricsecurity) (initialization → error handling)
- [8. Complete usage examples](#8-complete-usage-examples) (11 scenarios)
- [9. Simplification review](#9-simplification-review)
- [10. API cheat-sheet](#10-api-cheat-sheet)

---

## 0. Design principles

| Principle | How it shows up |
|---|---|
| **Simplicity** | One facade `BiometricSecurity`. Convenience methods for the 90% case; policy objects only when you need control. |
| **Type safety** | No stringly-typed flags. Sealed results, typed exceptions, enums everywhere. |
| **Null safety** | No nullable returns where an exception is the honest answer. Optionals are truly optional. |
| **Async** | Everything I/O- or prompt-bearing returns `Future`; lifecycle is a `Stream`. |
| **Clear naming** | `enrolledModalities` ≠ `supportedModalities`; `preferredModality` (advisory) ≠ any guarantee. |
| **Predictable** | Same policy ⇒ same behavior across platforms; failures are typed, never silent (INV-3). |
| **DX** | Preset policies (`SecurityPolicy.strong()`), copy-paste examples, one import. |
| **Platform independence** | Zero Android/iOS types leak into the API. No method promises what an OS can't do (INV-4/INV-5). |

**Import surface**

```dart
import 'package:biometric_security/biometric_security.dart';
// One import exposes: BiometricSecurity, SecurityPolicy, all enums, models, results, exceptions.
```

---

## 1. The five-way biometric distinction (read this first)

The brief demands these be kept distinct. They are **five different questions** and the API answers each with a different member. Conflating them is the #1 biometric bug.

| # | Concept | API member | Meaning | Can the app rely on it? |
|---|---|---|---|---|
| 1 | **Supported** biometric types | `BiometricAvailability.supportedModalities` | Hardware sensors exist on this device | Yes — factual |
| 2 | **Enrolled** biometric types | `BiometricAvailability.enrolledModalities` | The user has actually set up these biometrics | Yes — factual (but can change any time) |
| 3 | **Available** authentication | `BiometricAvailability.canAuthenticate` + `.status` | Can authenticate *right now* (enrolled, not locked out, lock screen set) | Yes — factual at call time |
| 4 | **Requested** biometric preference | `SecurityPolicy.preferredModality` | What the app would *like* the OS to use | **No — advisory only.** The OS may ignore it. |
| 5 | **Guaranteed** biometric modality | *(deliberately absent)* | "Force Face ID / fingerprint only" | **Impossible on Android & iOS.** No such API exists — see `EnforceableGuarantees`. |

```dart
/// What the platform CAN actually enforce (honest capability report).
/// There is intentionally no `guaranteedModality` field anywhere in this API,
/// because neither Android nor iOS can promise a specific modality (INV-4).
class EnforceableGuarantees {
  /// Android: can require BIOMETRIC_STRONG (Class 3). iOS: biometrics are strong by default.
  final bool canEnforceStrength;
  /// True on both platforms: a key can be made physically unusable without auth (INV-1).
  final bool canBindKeyToAuthentication;
  /// Android only: can require enrollment-invalidation. iOS: via biometryCurrentSet.
  final bool canInvalidateOnEnrollmentChange;
  /// Always false — documented so callers never build UX on a false promise.
  final bool canForceSpecificModality; // == false, always.
  const EnforceableGuarantees({ /* ... */ });
}
```

---

## 2. Enums

```dart
/// A biometric hardware family. Informational for UX; NOT selectable/enforceable (INV-4).
enum BiometricModality { face, fingerprint, iris, unknown }

/// Android strength classes. iOS has no weak tier ⇒ reported as `strong`.
/// Only `strong` can gate a cryptographic key (RESEARCH.md §3.2).
enum BiometricStrength { strong, weak, none }

/// Why authentication is not currently possible. Distinguishes the states apps confuse.
enum BiometricStatus {
  ready,                 // enrolled, not locked out — good to go
  noHardware,            // device has no biometric sensors
  hardwareUnavailable,   // sensors temporarily unavailable
  notEnrolled,           // hardware present, nothing enrolled
  noDeviceCredential,    // no PIN/pattern/passcode set → OS can't secure keys
  lockedOut,             // too many attempts, temporary
  lockedOutPermanently,  // needs device-credential unlock to reset
  unknown,
}

/// Whether device PIN/pattern/passcode may satisfy a biometric gate.
/// `allow` is weaker and NOT invalidated by enrollment changes (documented trade-off).
enum DeviceCredentialFallback { disallow, allow }

/// Enrollment-change binding. `invalidateOnChange` defends against coerced enrollment.
/// Maps to Android setInvalidatedByBiometricEnrollment / iOS biometryCurrentSet vs biometryAny.
enum EnrollmentBinding { invalidateOnChange, persistAcrossEnrollment }

/// How long an authentication authorizes key use.
/// `perOperation` = fresh prompt every use (strongest). `window` = reuse for a duration.
enum AuthValidity { perOperation, window }

/// Whether secure hardware (StrongBox/TEE/Secure Enclave) is required.
enum HardwareRequirement { preferStrongestAvailable, requireSecureHardware }

/// When encrypted data may be decrypted, relative to device unlock.
/// `thisDeviceOnly*` variants are excluded from backups/migration (INV-5).
enum StorageAccessibility { whenUnlockedThisDeviceOnly, afterFirstUnlockThisDeviceOnly }

/// Actual security level achieved for a key (reported honestly, never assumed).
enum SecurityLevel { strongBox, trustedExecutionEnvironment, secureEnclave, software, none }

/// Kinds of lifecycle events emitted on `BiometricSecurity.lifecycleEvents`.
enum KeyLifecycleEventType {
  enrollmentChanged,    // biometric set changed (advisory)
  keyInvalidated,       // a key became permanently unusable
  reprovisionRequired,  // caller must re-create + re-seal affected secrets
  integrityRisk,        // root/jailbreak signal (advisory only)
}
```

---

## 3. Policy types

One policy type drives auth *and* storage, so developers learn it once (mirrors `ARCHITECTURE.md` DR-2). Presets cover the common cases; the full constructor covers the rest.

```dart
/// The single, platform-independent expression of security intent.
/// Secure-by-default: the default constructor is the strongest sensible policy (INV-6).
@immutable
class SecurityPolicy {
  /// Minimum biometric strength. `strong` is required to cryptographically gate a key.
  final BiometricStrength minimumStrength;

  /// Whether device PIN/pattern/passcode may satisfy the gate.
  final DeviceCredentialFallback deviceCredentialFallback;

  /// What happens to protected data when the enrolled biometrics change.
  final EnrollmentBinding enrollmentBinding;

  /// Per-operation auth (default) vs a reuse window.
  final AuthValidity authValidity;
  /// Only used when [authValidity] == window.
  final Duration authWindow;

  /// Whether to require secure hardware or degrade-and-report.
  final HardwareRequirement hardwareRequirement;

  /// Backup/migration exposure of encrypted data at rest.
  final StorageAccessibility accessibility;

  /// ADVISORY hint only. The OS may ignore it entirely (INV-4). UX use only.
  final BiometricModality? preferredModality;

  /// Require an explicit confirm tap after biometric match (Android setConfirmationRequired).
  final bool requireConfirmation;

  /// Secure-by-default: strong · no fallback · invalidate-on-enrollment ·
  /// per-operation · prefer strongest hardware · this-device-only.
  const SecurityPolicy({
    this.minimumStrength = BiometricStrength.strong,
    this.deviceCredentialFallback = DeviceCredentialFallback.disallow,
    this.enrollmentBinding = EnrollmentBinding.invalidateOnChange,
    this.authValidity = AuthValidity.perOperation,
    this.authWindow = const Duration(seconds: 0),
    this.hardwareRequirement = HardwareRequirement.preferStrongestAvailable,
    this.accessibility = StorageAccessibility.whenUnlockedThisDeviceOnly,
    this.preferredModality,
    this.requireConfirmation = false,
  });

  // ---- Presets (DX) ----

  /// Maximum security. Identical to the default constructor. Use for high-value secrets.
  factory SecurityPolicy.strong() = /* const default */;

  /// Slightly more forgiving: keeps strong biometrics but survives new enrollments and
  /// allows a short reuse window. Good for frequently-accessed, medium-value data.
  factory SecurityPolicy.balanced();

  /// Allows device-credential (PIN/passcode) fallback so users are never hard-locked out.
  /// Weaker: such keys are not enrollment-invalidated. Documented trade-off.
  factory SecurityPolicy.convenient();

  /// Encryption-at-rest only, no biometric gate. For non-sensitive config.
  /// (No prompt on read/write.)
  factory SecurityPolicy.encryptedOnly();

  SecurityPolicy copyWith({ /* every field */ });
}
```

> **Naming honesty:** there is no `SecurityPolicy.faceIdOnly()` or `.fingerprintOnly()`. Those cannot be honored (INV-4). `preferredModality` exists only to help the OS/UX, never to guarantee.

---

## 4. Models & status objects

```dart
/// One-time configuration for the whole package.
@immutable
class BiometricSecurityConfig {
  /// Default policy applied when a call omits its own.
  final SecurityPolicy defaultPolicy;
  /// Namespace so multiple logical stores / apps don't collide (maps to key-alias scope).
  final String namespace;
  /// Emit `integrityRisk` events from root/jailbreak heuristics (advisory).
  final bool enableIntegritySignals;
  const BiometricSecurityConfig({
    this.defaultPolicy = const SecurityPolicy(),
    this.namespace = 'default',
    this.enableIntegritySignals = false,
  });
}

/// Answers questions 1–3 of the five-way distinction (§1).
@immutable
class BiometricAvailability {
  /// Device has biometric hardware at all.
  final bool isSupported;
  /// (1) SUPPORTED: sensor families physically present.
  final Set<BiometricModality> supportedModalities;
  /// (2) ENROLLED: modalities the user has actually set up.
  final Set<BiometricModality> enrolledModalities;
  /// Strongest class currently enrolled (Android). iOS enrolled biometrics ⇒ strong.
  final BiometricStrength strength;
  /// (3) AVAILABLE: true iff authentication can succeed right now.
  final bool canAuthenticate;
  /// Precise reason when [canAuthenticate] is false.
  final BiometricStatus status;
  /// What this device can actually enforce (§1). Never promises a modality.
  final EnforceableGuarantees guarantees;
  /// Secure-hardware presence — informs achievable [SecurityLevel].
  final bool hasStrongBox;      // Android
  final bool hasSecureEnclave;  // iOS
  const BiometricAvailability({ /* ... */ });
}

/// Snapshot of the protection subsystem (question 17: security status).
@immutable
class SecurityStatus {
  final BiometricAvailability availability;
  /// Highest security level the device can back keys with.
  final SecurityLevel achievableSecurityLevel;
  /// True if any known key/scope is currently invalidated and awaiting reprovision.
  final bool reprovisionRequired;
  /// Advisory device-integrity assessment (best-effort; never a guarantee).
  final bool integrityRisk;
  const SecurityStatus({ /* ... */ });
}

/// Logical identifier for a stored secret. A thin, type-safe wrapper over a string key
/// so keys can't be accidentally swapped with arbitrary strings elsewhere.
extension type const SecretKey(String value) {}

/// Emitted on the lifecycle stream. Advisory — the package never acts destructively (INV-3).
@immutable
class KeyLifecycleEvent {
  final KeyLifecycleEventType type;
  /// The protection scope / app-lock / feature affected, if applicable.
  final String? scope;
  final String message;
  const KeyLifecycleEvent({ /* ... */ });
}
```

---

## 5. Results

Success paths return typed results; failure paths **throw** typed exceptions (§6). Where a "user said no" outcome is expected control-flow rather than an error, it is modeled as a result variant so callers aren't forced into `try/catch` for the normal case.

```dart
/// Proof that a real, key-backed authentication succeeded (INV-1 — not a bare bool).
@immutable
class AuthSession {
  /// Opaque, non-forgeable marker that a hardware key operation ran under this auth.
  final String token;
  final DateTime authenticatedAt;
  /// Which modality the OS actually used, if it reported one (informational).
  final BiometricModality? usedModality;
  /// Security level of the key that backed this auth.
  final SecurityLevel securityLevel;
  const AuthSession({ /* ... */ });
}

/// Result of a challenge-signing operation for backend-verifiable auth.
@immutable
class SignatureResult {
  final Uint8List signature;
  final Uint8List publicKey; // DER/SPKI — send once at enrollment
  final SecurityLevel securityLevel;
  const SignatureResult({ /* ... */ });
}
```

> **Design note on `authenticate`:** it **returns `AuthSession` on success** and **throws** on every failure (cancel, fail, lockout, unavailable, invalidated). Cancellation is a `BiometricAuthCanceledException` — expected and easy to catch — rather than a nullable return, so a successful call is never ambiguous. Rationale in §9.

---

## 6. Exceptions

One sealed root so callers can `catch (BiometricSecurityException)` broadly or match precisely. Covers every error type the brief lists.

```dart
/// Root of all failures thrown by this package.
sealed class BiometricSecurityException implements Exception {
  final String message;
  final Object? platformDetail; // opaque, for logging only — never platform types in the API
  const BiometricSecurityException(this.message, {this.platformDetail});
}

// --- Authentication ---
/// User dismissed/canceled the prompt. Expected control flow.
class BiometricAuthCanceledException extends BiometricSecurityException { /* ... */ }
/// Biometric presented but did not match; may be retryable.
class BiometricAuthFailedException extends BiometricSecurityException { /* ... */ }
/// Too many attempts — temporarily locked. Includes optional retry hint.
class BiometricLockedOutException extends BiometricSecurityException {
  final bool isPermanent; // true ⇒ needs device-credential unlock
}

// --- Availability / enrollment ---
class BiometricUnavailableException extends BiometricSecurityException {
  final BiometricStatus status; // noHardware / hardwareUnavailable / noDeviceCredential
}
class BiometricNotEnrolledException extends BiometricSecurityException { /* ... */ }

// --- Key / enrollment lifecycle ---
/// A key was permanently invalidated (enrollment change / lock disabled). INV-3: never auto-fixed.
class KeyInvalidatedException extends BiometricSecurityException {
  final String? scope;
}
/// Enrolled biometrics changed since data was stored. Advisory-driven.
class EnrollmentChangedException extends BiometricSecurityException { /* ... */ }

// --- Storage / crypto ---
class SecureStorageException extends BiometricSecurityException { /* ... */ }
/// AEAD tag mismatch / decryption failure. No plaintext is ever returned on this path.
class CryptographicException extends BiometricSecurityException { /* ... */ }

// --- Configuration / platform ---
class UnsupportedPlatformException extends BiometricSecurityException { /* ... */ }
/// The requested SecurityPolicy cannot be expressed on this device (e.g. requireSecureHardware
/// on a device without it, or a strength the device can't provide).
class PolicyUnsupportedException extends BiometricSecurityException { /* ... */ }
/// A method was called before initialize().
class NotInitializedException extends BiometricSecurityException { /* ... */ }
```

**Mapping to the brief's requested error list:**

| Brief error | Exception |
|---|---|
| Authentication cancelled | `BiometricAuthCanceledException` |
| Authentication failed | `BiometricAuthFailedException` |
| Authentication locked out | `BiometricLockedOutException` |
| Biometric unavailable | `BiometricUnavailableException` |
| Biometric not enrolled | `BiometricNotEnrolledException` |
| Key invalidated | `KeyInvalidatedException` |
| Enrollment changed | `EnrollmentChangedException` |
| Secure storage failure | `SecureStorageException` |
| Cryptographic failure | `CryptographicException` |
| Unsupported platform | `UnsupportedPlatformException` |

---

## 7. The facade: `BiometricSecurity`

A single class. Grouped below by the 18 required API areas.

```dart
class BiometricSecurity {
  /// Construct with optional config. Cheap; does no I/O until [initialize].
  BiometricSecurity({BiometricSecurityConfig config = const BiometricSecurityConfig()});
```

### 7.1 Initialization

```dart
  /// Prepares the platform layer. Idempotent — safe to call more than once.
  /// Must complete before any other method (else [NotInitializedException]).
  /// Throws [UnsupportedPlatformException] on platforms with no implementation.
  Future<void> initialize();

  /// True once [initialize] has completed.
  bool get isInitialized;
```

*Example:* see [Example 1](#example-1--simple-authentication).

### 7.2 Availability detection · 7.3 Supported types · 7.4 Enrollment status

```dart
  /// Full snapshot answering "supported / enrolled / available" (§1, questions 1–3).
  Future<BiometricAvailability> getAvailability();

  /// Convenience: can the user authenticate right now?
  Future<bool> get canAuthenticate; // == (await getAvailability()).canAuthenticate
```

`supportedModalities`, `enrolledModalities`, and `status` on the returned object cover requirements 3, 4, and 5 respectively. *Example:* [Example 2](#example-2--check-availability).

### 7.5 Biometric policy

The `SecurityPolicy` type (§3) is the policy API. Any method that authenticates or protects data takes an optional `SecurityPolicy`; omit it to use the configured default. No separate "set policy" call is needed — policies are values, passed where used, which keeps behavior predictable and local.

### 7.6 Authentication

```dart
  /// Perform a cryptographically-backed authentication (INV-1: runs a real key op,
  /// not a bare boolean). Returns an [AuthSession] on success.
  ///
  /// Throws: [BiometricAuthCanceledException], [BiometricAuthFailedException],
  /// [BiometricLockedOutException], [BiometricUnavailableException],
  /// [BiometricNotEnrolledException], [KeyInvalidatedException].
  Future<AuthSession> authenticate({
    required String reason,          // shown in the system prompt
    SecurityPolicy? policy,          // defaults to config.defaultPolicy
    String? cancelLabel,             // custom cancel button text
  });

  /// Sign a server-provided challenge with a hardware key gated by biometrics.
  /// The gold-standard for backend-verifiable auth (beats trusting a boolean).
  Future<SignatureResult> signChallenge({
    required Uint8List challenge,
    required String reason,
    SecurityPolicy? policy,
  });
```

### 7.7 Secure storage · 7.8 Biometric-protected storage

The *same* methods serve both. The **policy** decides whether a read requires biometrics:
`SecurityPolicy.encryptedOnly()` ⇒ silent encrypted-at-rest; any biometric policy ⇒ read/write prompt.

```dart
  /// Encrypt and store [value] under [key]. If [policy] requires biometrics,
  /// the OS prompt is shown. Overwrites any existing value.
  Future<void> write({
    required SecretKey key,
    required String value,          // convenience for text
    SecurityPolicy? policy,
    String? reason,                 // required if the policy prompts
  });

  /// Binary variant.
  Future<void> writeBytes({ required SecretKey key, required Uint8List value,
                            SecurityPolicy? policy, String? reason });

  /// Decrypt and return the value for [key]. Prompts if the stored item is biometric-gated.
  /// Returns null if [key] does not exist.
  /// Throws [KeyInvalidatedException] if the protecting key was invalidated (INV-3),
  /// and [CryptographicException] on tamper/decrypt failure (no plaintext returned).
  Future<String?> read({ required SecretKey key, String? reason });
  Future<Uint8List?> readBytes({ required SecretKey key, String? reason });

  /// True if a value exists for [key] (no decryption, no prompt).
  Future<bool> contains({ required SecretKey key });

  /// All stored keys (metadata only; no decryption, no prompt).
  Future<Set<SecretKey>> keys();
```

*Examples:* [3](#example-3--store-a-secret), [4](#example-4--retrieve-a-secret), [6](#example-6--biometric-protected-secret).

### 7.9 Enable protection · 7.10 Disable protection

Change a secret's protection **in place** without the caller re-reading/re-writing plaintext manually.

```dart
  /// Upgrade an existing secret to a biometric-gated policy (re-wraps under a gated key).
  /// May prompt to unwrap the current value. Throws [PolicyUnsupportedException]
  /// if the device can't satisfy [policy].
  Future<void> enableProtection({ required SecretKey key, required SecurityPolicy policy,
                                  String? reason });

  /// Downgrade a secret to encrypted-only (removes the biometric gate). Prompts once to unwrap.
  Future<void> disableProtection({ required SecretKey key, String? reason });

  /// Current policy protecting a stored secret (no prompt).
  Future<SecurityPolicy?> policyOf({ required SecretKey key });
```

### 7.11 App lock

```dart
  /// App-lock sub-API. Backed by a dedicated key op, so "unlocked" means a real
  /// authentication happened (INV-1), not a flag a hooked process can flip.
  AppLock get appLock;
}

class AppLock {
  /// Turn on app-lock with the given policy. Provisions the app-lock key.
  Future<void> enable({ SecurityPolicy? policy, required String reason });
  /// Turn off app-lock and destroy its key.
  Future<void> disable();
  /// Whether app-lock is currently enabled.
  Future<bool> isEnabled();
  /// Prompt the user and return a verified session, or throw (cancel/fail/lockout/invalidated).
  Future<AuthSession> unlock({ required String reason });
}
```

*Example:* [7](#example-7--app-lock).

### 7.12 Feature-level protection

```dart
// (on BiometricSecurity)
  /// Sub-API to gate individual app features behind a policy.
  FeatureProtection get features;
}

class FeatureProtection {
  /// Register/replace the policy that guards [featureId].
  Future<void> setPolicy({ required String featureId, required SecurityPolicy policy });
  /// Run the gate for [featureId]. Returns a session on success; throws on denial.
  /// If no policy is registered for [featureId], this succeeds without prompting.
  Future<AuthSession> guard({ required String featureId, required String reason });
  /// Remove a feature's protection.
  Future<void> clearPolicy({ required String featureId });
}
```

*Example:* [8](#example-8--feature-protection).

### 7.13 Revocation · 7.14 Delete · 7.15 Delete all

The brief lists *revoke*, *delete*, and *delete all* separately — they mean different things, so they are different methods:

```dart
  /// DELETE one secret: removes its ciphertext + metadata. The protecting key may be
  /// reused by other secrets, so it is NOT destroyed. Idempotent.
  Future<void> delete({ required SecretKey key });

  /// DELETE ALL secrets in this namespace. Keys backing them are NOT destroyed unless
  /// no longer referenced. Idempotent.
  Future<void> deleteAll();

  /// REVOKE one secret: delete it AND destroy its dedicated protecting key material,
  /// making it cryptographically unrecoverable even if ciphertext were restored (INV-5).
  Future<void> revoke({ required SecretKey key });

  /// REVOKE EVERYTHING: destroy all keys in this namespace (a hard kill-switch), then wipe
  /// all secrets. On iOS this also purges Keychain items that survive uninstall (ARCH §16).
  Future<void> revokeAll();
```

> **`delete` vs `revoke`:** delete removes *data*; revoke removes *data and the ability to ever decrypt it*. Use `revoke*` for logout/wipe/compromise; `delete` for ordinary removal.

*Examples:* [5](#example-5--delete-a-secret), [10](#example-10--revocation).

### 7.16 Key invalidation (detection & recovery)

Invalidation is **observed**, never caused by the package (INV-3). Two ways to learn about it:

```dart
  /// Reactive: broadcast stream of lifecycle events (enrollment changed, key invalidated,
  /// reprovision required, integrity risk). Advisory — you decide what to do.
  Stream<KeyLifecycleEvent> get lifecycleEvents;

  /// Imperative: after catching a [KeyInvalidatedException], clear the dead key material
  /// for a scope so fresh secrets can be provisioned. Does not touch unrelated scopes.
  Future<void> resetInvalidated({ String? scope });
```

*Example:* [11](#example-11--recovery-after-key-invalidation).

### 7.17 Security status

```dart
  /// One-call health snapshot: availability + achievable security level + reprovision/integrity
  /// flags. Cheap; no prompt.
  Future<SecurityStatus> getSecurityStatus();
```

### 7.18 Error handling

All errors are subtypes of `BiometricSecurityException` (§6). Catch the root for coarse handling, or match specific subtypes. Dart's sealed hierarchy enables exhaustive `switch` on caught errors. See every example below.

---

## 8. Complete usage examples

### Example 1 — Simple authentication

```dart
final security = BiometricSecurity();
await security.initialize();

try {
  final session = await security.authenticate(
    reason: 'Authenticate to continue',
  );
  print('Authenticated at ${session.authenticatedAt} via ${session.usedModality}');
} on BiometricAuthCanceledException {
  // User backed out — normal control flow, not an error to surface loudly.
} on BiometricLockedOutException catch (e) {
  showBanner(e.isPermanent ? 'Use your PIN to unlock' : 'Too many attempts, try later');
} on BiometricSecurityException catch (e) {
  showBanner('Authentication unavailable: ${e.message}');
}
```

### Example 2 — Check availability (and the five-way distinction)

```dart
final a = await security.getAvailability();

if (!a.isSupported) {
  // Question 1: no sensors at all.
  return showPasswordOnlyUi();
}
print('Supported: ${a.supportedModalities}');  // (1) hardware present
print('Enrolled:  ${a.enrolledModalities}');   // (2) actually set up
print('Ready:     ${a.canAuthenticate} (${a.status})'); // (3) usable right now

if (a.status == BiometricStatus.notEnrolled) {
  promptUserToEnrollInSettings();
}

// (4) preference is advisory only; (5) there is no guarantee:
if (!a.guarantees.canForceSpecificModality) {
  // Always true — never build a "Face ID only" flow.
}
```

### Example 3 — Store a secret (encrypted-at-rest, no prompt)

```dart
await security.write(
  key: const SecretKey('api_token'),
  value: token,
  policy: SecurityPolicy.encryptedOnly(), // silent, no biometric gate
);
```

### Example 4 — Retrieve a secret

```dart
final token = await security.read(key: const SecretKey('api_token'));
if (token == null) {
  // Not stored yet (or deleted).
}
```

### Example 5 — Delete a secret

```dart
await security.delete(key: const SecretKey('api_token')); // idempotent
```

### Example 6 — Biometric-protected secret

```dart
const pin = SecretKey('payment_pin');

// Store behind a strong biometric gate (prompts to seal).
await security.write(
  key: pin,
  value: '123456',
  policy: SecurityPolicy.strong(),
  reason: 'Confirm to secure your payment PIN',
);

// Reading prompts the user (INV-1: a real key op runs).
try {
  final value = await security.read(key: pin, reason: 'Unlock your payment PIN');
  usePin(value!);
} on BiometricAuthCanceledException {
  // user declined
} on KeyInvalidatedException {
  await recoverPaymentPin(); // see Example 11
}
```

### Example 7 — App lock

```dart
// During setup:
await security.appLock.enable(
  policy: SecurityPolicy.balanced(),
  reason: 'Enable app lock',
);

// On resume / cold start:
if (await security.appLock.isEnabled()) {
  try {
    await security.appLock.unlock(reason: 'Unlock MyApp');
    navigateToHome();
  } on BiometricAuthCanceledException {
    exitToLockScreen();
  }
}
```

### Example 8 — Feature protection

```dart
// Register once (e.g. at startup):
await security.features.setPolicy(
  featureId: 'export_private_keys',
  policy: SecurityPolicy.strong(),
);

// At the call site:
Future<void> onExportTap() async {
  try {
    await security.features.guard(
      featureId: 'export_private_keys',
      reason: 'Authenticate to export your keys',
    );
    performExport();
  } on BiometricSecurityException {
    showBanner('Authentication required to export.');
  }
}
```

### Example 9 — Enrollment change handling

```dart
late final StreamSubscription sub;
sub = security.lifecycleEvents.listen((event) async {
  switch (event.type) {
    case KeyLifecycleEventType.enrollmentChanged:
      showBanner('Your biometrics changed. Some protected data may need re-authentication.');
    case KeyLifecycleEventType.keyInvalidated:
    case KeyLifecycleEventType.reprovisionRequired:
      await handleReprovision(event.scope); // Example 11
    case KeyLifecycleEventType.integrityRisk:
      logSecurityEvent('integrity risk on device'); // advisory only
  }
});
```

### Example 10 — Revocation (logout / wipe)

```dart
// Log out this user: make every protected secret permanently unrecoverable.
await security.revokeAll();

// Or revoke a single high-value secret on suspicion of compromise:
await security.revoke(key: const SecretKey('payment_pin'));
```

### Example 11 — Recovery after key invalidation

```dart
Future<void> handleReprovision([String? scope]) async {
  // INV-3: the package never silently regenerated anything — the old secrets are gone by design.
  await security.resetInvalidated(scope: scope); // clears the dead key material

  // Re-fetch the real secret from your source of truth (server) and re-seal it.
  final freshToken = await api.reissueToken();       // server is source of truth (INV-5)
  await security.write(
    key: const SecretKey('api_token'),
    value: freshToken,
    policy: SecurityPolicy.strong(),
    reason: 'Re-secure your account after a device change',
  );
}
```

---

## 9. Simplification review

I went back over the surface and cut/merged where complexity didn't earn its place:

| Considered | Decision | Reason |
|---|---|---|
| Separate `SecureStorage`, `BiometricStorage` classes | **Merged** into `write/read` + policy | Two storage APIs would force users to pick up front and migrate later. One method set, behavior chosen by policy, is simpler and matches the brief's example ergonomics. |
| A `setPolicy()` global mutable setter | **Removed** | Policies are values passed at call sites (+ one default in config). No hidden global state ⇒ predictable behavior. |
| `tryAuthenticate()` returning a sealed `AuthResult` **and** throwing `authenticate()` | **Kept only** throwing `authenticate()` | One idiom. Cancellation is a typed, easy-to-catch exception; a successful return is unambiguously an `AuthSession`. Two parallel idioms is more surface for no real gain. |
| `guaranteedModality` / `SecurityPolicy.faceIdOnly()` | **Never added** | Honesty (INV-4). Replaced by advisory `preferredModality` + `EnforceableGuarantees`. |
| Distinct `KeyManager`, `CryptoService` public types | **Kept internal** | Architecture layers, not app concerns. The facade is the whole public surface. |
| `getAvailability()` vs `getSecurityStatus()` overlap | **Kept both, layered** | `SecurityStatus` *contains* `BiometricAvailability` and adds subsystem health. Availability is the common call; status is the diagnostic one. No duplication of concepts. |
| Nullable `read()` returning null for missing vs throwing | **Null for "absent," throw for "can't decrypt"** | "Not there" is normal; "there but unreadable" is exceptional. Matches developer intuition. |
| Separate `delete` and `revoke` (could collapse to one) | **Kept both** | They have genuinely different security semantics (data vs data-and-key). Collapsing would hide a security-relevant choice — the opposite of INV-6. |
| `SecretKey` extension type vs raw `String` keys | **Kept the wrapper** | Zero runtime cost (extension type), prevents accidentally passing the wrong string. Small, high-value type-safety win. |

Net public surface: **one facade class + two small sub-APIs (`AppLock`, `FeatureProtection`) + one policy type + a handful of enums/models/exceptions.** Nothing platform-specific leaks. That is about as small as it gets while still covering all 18 required areas.

---

## 10. API cheat-sheet

```dart
final security = BiometricSecurity(config: BiometricSecurityConfig(/* defaultPolicy, namespace */));
await security.initialize();

// Detection
BiometricAvailability a = await security.getAvailability();
SecurityStatus s        = await security.getSecurityStatus();

// Authentication
AuthSession session     = await security.authenticate(reason: '…', policy: SecurityPolicy.strong());
SignatureResult sig     = await security.signChallenge(challenge: c, reason: '…');

// Storage (policy decides if it's biometric-gated)
await security.write(key: SecretKey('k'), value: 'v', policy: SecurityPolicy.strong(), reason: '…');
String? v = await security.read(key: SecretKey('k'), reason: '…');
await security.enableProtection(key: SecretKey('k'), policy: SecurityPolicy.strong());
await security.disableProtection(key: SecretKey('k'));

// App lock & features
await security.appLock.enable(reason: '…');  await security.appLock.unlock(reason: '…');
await security.features.setPolicy(featureId: 'f', policy: SecurityPolicy.strong());
await security.features.guard(featureId: 'f', reason: '…');

// Lifecycle & teardown
StreamSubscription sub = security.lifecycleEvents.listen(handle);
await security.resetInvalidated(scope: '…');
await security.delete(key: SecretKey('k'));      await security.deleteAll();
await security.revoke(key: SecretKey('k'));      await security.revokeAll();
```

*End of API_DESIGN.md — contract only, no production functionality.*
