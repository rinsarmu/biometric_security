# biometric_security

Unified biometric security for Flutter — hardware-backed key management,
biometric-gated encrypted storage, app-lock, and honest availability detection
for **Android** and **iOS**.

> **Status: 0.1.0 — public beta, not yet production-ready.**
> The cryptographic design is sound and unit-tested, and an independent security
> review fixed all high-risk findings — but
> the biometric/Keystore/Secure-Enclave paths have **not yet been validated on
> physical hardware**, and a few features are still stubs. Use it for pilots and
> non-critical data; read [Platform limitations](#23-platform-limitations) and
> the audit before protecting real user secrets.

---

## Table of contents

1. [Package overview](#1-package-overview) · 2. [Why this package exists](#2-why-this-package-exists) · 3. [Key features](#3-key-features) · 4. [Installation](#4-installation) · 5. [Quick start](#5-quick-start) · 6. [Authentication](#6-authentication) · 7. [Availability detection](#7-availability-detection) · 8. [Biometric types](#8-biometric-types) · 9. [Biometric policies](#9-biometric-policies) · 10. [Secure storage](#10-secure-storage) · 11. [Biometric-protected storage](#11-biometric-protected-storage) · 12. [App lock](#12-app-lock) · 13. [Feature-level protection](#13-feature-level-protection) · 14. [Enable/disable protection](#14-enabledisable-protection) · 15. [Enrollment changes](#15-enrollment-changes) · 16. [Key invalidation](#16-key-invalidation) · 17. [Revocation](#17-revocation) · 18. [Recovery](#18-recovery) · 19. [Security architecture](#19-security-architecture) · 20. [Threat model](#20-threat-model) · 21. [Android details](#21-android-details) · 22. [iOS details](#22-ios-details) · 23. [Platform limitations](#23-platform-limitations) · 24. [Error handling](#24-error-handling) · 25. [Testing](#25-testing) · 26. [FAQ](#26-faq) · 27. [Security recommendations](#27-security-recommendations) · 28. [License](#28-license)

---

## 1. Package overview

`biometric_security` gives Flutter apps one small API for the whole biometric
security chain: detect what the device can do, authenticate the user against a
**hardware key** (not a forgeable boolean), and store secrets encrypted with
**AES-256-GCM** under a key that is physically unusable without a successful
biometric check. It normalizes the very different Android and iOS behaviors —
strength classes, enrollment-change invalidation, device-credential fallback —
into one `SecurityPolicy`.

## 2. Why this package exists

The common Flutter pattern — `local_auth` returns `true`, so unlock the data — is
**not a security boundary**. On a rooted or hooked device that boolean is
trivially forged. The real boundary is a key in the Android Keystore / iOS
Secure Enclave whose *use* requires biometric authentication. Assembling that
correctly (enrollment invalidation, strong-vs-weak biometrics, `biometryCurrentSet`
vs `biometryAny`, key rotation, safe failure) is where bugs and data loss live.
This package makes the cryptographic binding the **default**, and fails loudly
instead of silently returning plaintext.

## 3. Key features

- ✅ Biometric availability, strength, and enrolled-modality detection.
- ✅ Hardware-backed authentication (`BiometricPrompt` + `CryptoObject` / Secure Enclave signing).
- ✅ AES-256-GCM envelope encrypted storage; per-secret data-encryption keys.
- ✅ Biometric-gated reads; encryption-at-rest for non-sensitive data.
- ✅ One normalized, secure-by-default `SecurityPolicy`.
- ✅ App-lock and feature-level gating.
- ✅ Key rotation, revocation, enrollment-change invalidation, migration.
- ✅ Typed error model — never returns plaintext on failure.

## 4. Installation

```yaml
dependencies:
  biometric_security: ^0.1.0
```

**Android** — set `minSdkVersion 24` (or higher) and make your activity a
`FlutterFragmentActivity` (required by `BiometricPrompt`):

```kotlin
// android/app/src/main/kotlin/.../MainActivity.kt
import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity : FlutterFragmentActivity()
```

**iOS** — set the deployment target to **13.0+** and add a Face ID usage string
(the app crashes without it):

```xml
<!-- ios/Runner/Info.plist -->
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to protect and unlock your secured data.</string>
```

## 5. Quick start

```dart
import 'package:biometric_security/biometric_security.dart';

final security = BiometricSecurity();

Future<void> main() async {
  await security.initialize();

  final availability = await security.getAvailability();
  if (!availability.canAuthenticate) {
    // Fall back to password, or ask the user to enrol a biometric.
    return;
  }

  // Store a secret behind a strong biometric gate.
  await security.write(
    key: const SecretKey('payment_pin'),
    value: '4321',
    policy: SecurityPolicy.strong(),
    reason: 'Confirm to secure your PIN',
  );

  // Reading prompts the user (a real key operation runs).
  final pin = await security.read(
    key: const SecretKey('payment_pin'),
    reason: 'Unlock your PIN',
  );
  print(pin); // "4321"
}
```

## 6. Authentication

`authenticate()` runs a real hardware key operation and returns a verified
`AuthSession` on success, or throws a typed exception.

```dart
try {
  final session = await security.authenticate(
    reason: 'Verify it is you',
  );
  print('Authenticated via ${session.securityLevel}');
} on BiometricAuthCanceledException {
  // User backed out — normal control flow.
} on BiometricLockedOutException catch (e) {
  showBanner(e.isPermanent ? 'Unlock with your device PIN' : 'Try again later');
} on BiometricSecurityException catch (e) {
  showBanner(e.message);
}
```

> For server-verifiable authentication (a signed challenge), `signChallenge()`
> is planned but **not yet implemented** in 0.1.0. `authenticate()` is a *local*
> gate; check `session.securityLevel` before trusting it for high-value flows.

## 7. Availability detection

```dart
final a = await security.getAvailability();
print(a.isSupported);          // device has biometric hardware
print(a.supportedModalities);  // {fingerprint, face, ...} — hardware present
print(a.enrolledModalities);   // what the user actually set up (empty on Android — see below)
print(a.strength);             // strong | weak | none
print(a.canAuthenticate);      // usable right now?
print(a.status);               // ready | notEnrolled | lockedOut | ...
print(a.hasStrongBox);         // Android StrongBox
print(a.hasSecureEnclave);     // iOS Secure Enclave
```

## 8. Biometric types

The API keeps five distinct concepts separate — conflating them is the #1
biometric bug:

| Concept | Where | Reliable? |
|---|---|---|
| **Supported** (hardware present) | `supportedModalities` | Yes |
| **Enrolled** (user set up) | `enrolledModalities` | Yes (Android can't enumerate — always empty) |
| **Available** (usable now) | `canAuthenticate` / `status` | Yes |
| **Requested** preference | `SecurityPolicy.preferredModality` | **Advisory only** |
| **Guaranteed** modality | *does not exist* | **Impossible** on both OSes |

You **cannot force Face ID or fingerprint** — the OS decides.
`EnforceableGuarantees.canForceSpecificModality` is always `false`.

## 9. Biometric policies

One `SecurityPolicy` expresses intent; the plugin maps it to each platform.
The default is the strongest sensible configuration.

```dart
SecurityPolicy.strong();        // strong biometric, per-use, invalidate on enrollment change (default)
SecurityPolicy.balanced();      // survives new enrollments, short reuse window
SecurityPolicy.convenient();    // allows device PIN/passcode fallback (weaker)
SecurityPolicy.encryptedOnly(); // encryption at rest, no prompt

// Or fully custom:
const SecurityPolicy(
  minimumStrength: BiometricStrength.strong,
  deviceCredentialFallback: DeviceCredentialFallback.disallow,
  enrollmentBinding: EnrollmentBinding.invalidateOnChange,
  authValidity: AuthValidity.perOperation,
  hardwareRequirement: HardwareRequirement.requireSecureHardware,
  accessibility: StorageAccessibility.whenUnlockedThisDeviceOnly,
);
```

## 10. Secure storage

Non-sensitive data — encrypted at rest, no prompt:

```dart
await security.write(
  key: const SecretKey('api_token'),
  value: token,
  policy: SecurityPolicy.encryptedOnly(),
);
final token = await security.read(key: const SecretKey('api_token'));
```

## 11. Biometric-protected storage

Sensitive data — the read prompts and is backed by a hardware-gated key:

```dart
const pin = SecretKey('payment_pin');

await security.write(
  key: pin,
  value: '4321',
  policy: SecurityPolicy.strong(),
  reason: 'Secure your PIN',
);

final value = await security.read(key: pin, reason: 'Unlock your PIN');
```

## 12. App lock

```dart
// Setup:
await security.appLock.enable(
  policy: SecurityPolicy.balanced(),
  reason: 'Enable app lock',
);

// On resume:
if (await security.appLock.isEnabled()) {
  try {
    await security.appLock.unlock(reason: 'Unlock MyApp');
    goHome();
  } on BiometricAuthCanceledException {
    stayLocked();
  }
}
```

## 13. Feature-level protection

```dart
await security.features.setPolicy(
  featureId: 'export_keys',
  policy: SecurityPolicy.strong(),
);

Future<void> onExport() async {
  await security.features.guard(
    featureId: 'export_keys',
    reason: 'Authenticate to export',
  );
  performExport();
}
```

## 14. Enable/disable protection

```dart
await security.enableProtection(
  key: const SecretKey('note'),
  policy: SecurityPolicy.strong(),
);
await security.disableProtection(key: const SecretKey('note'));
```

> `enableProtection` / `disableProtection` are declared but not yet implemented
> in 0.1.0. To change protection today, `read` then `write` with the new policy.

## 15. Enrollment changes

When the user adds/removes a fingerprint or face, a `SecurityPolicy` with
`EnrollmentBinding.invalidateOnChange` (the default) makes protected data
inaccessible — defending against a coerced new enrollment.

```dart
security.lifecycleEvents.listen((event) {
  if (event.type == KeyLifecycleEventType.keyInvalidated) {
    // Prompt the user to re-provision (see Recovery).
  }
});
```

> Lifecycle-event **emission** is not wired in 0.1.0; today you learn of
> invalidation from a `KeyInvalidatedException` on the next `read`.

### Testing biometric enrollment changes

Enrollment-change behavior is **native and can only be verified on a physical
device** — emulators/simulators cannot enroll real biometrics. The example app
has a **Biometric Enrollment** section that drives this test.

**What the package actually does (default `SecurityPolicy.strong()`):** the key
protecting a secret is bound to the enrolled biometric set. When that set
changes, the key is invalidated and the next `read()` throws
`KeyInvalidatedException` — the package does *not* silently return stale data.
Three distinct things collapse into that one observable:

1. *The biometric set changed* — the OS-level cause.
2. *The cryptographic key was invalidated* — the platform consequence.
3. *The protected data can no longer be decrypted* — what your app observes.

You detect all three by attempting `read()` and catching `KeyInvalidatedException`.
There is intentionally no separate "has the set changed?" probe — the key state
is the source of truth.

**Android** (`setInvalidatedByBiometricEnrollment(true)`, default):
1. Store, then read the protected PIN (succeeds).
2. Settings → Security → add a **new** fingerprint/face.
3. Return to the app → **Read Protected PIN** → `KeyInvalidatedException`.
   Detection happens at cipher init, *before* any prompt is shown.
> Note: Android invalidates on **new enrollment**; behavior on *removal* varies
> by OEM.

**iOS** (`.biometryCurrentSet`, default):
1. Store, then read the protected PIN (succeeds).
2. Settings → Face ID & Passcode → **add or remove** a face/fingerprint.
3. Return to the app → **Read Protected PIN** → `KeyInvalidatedException`.
   iOS detects the change via the biometric domain-state, *without* a prompt.

**Expected result:** "Secure key valid" → `INVALIDATED`, "Protected PIN
accessible" → `false`.

**Limitation:** a policy with `EnrollmentBinding.persistAcrossEnrollment`
(Android `setInvalidatedByBiometricEnrollment(false)` / iOS `biometryAny`)
**survives** new enrollments by design — do not expect invalidation there.

**Recovery:** call `resetInvalidated()` to clear the dead key, then re-`write()`
the secret from your source of truth (the server). The old ciphertext is
unrecoverable by design.

## 16. Key invalidation

If the protecting key is invalidated (enrollment change or the device lock being
disabled), reads **fail loudly** — the package never returns plaintext and never
silently regenerates the key:

```dart
try {
  await security.read(key: const SecretKey('payment_pin'), reason: 'Unlock');
} on KeyInvalidatedException {
  await recover(); // see below
}
```

## 17. Revocation

```dart
await security.revoke(key: const SecretKey('payment_pin')); // one secret, unrecoverable
await security.revokeAll();                                 // hard kill-switch (e.g. logout)
```

`delete` removes data; `revoke` removes data **and** destroys the key so the
secret can never be decrypted again.

## 18. Recovery

Hardware keys are device-bound and non-transferable, so after invalidation or a
device change, re-provision from your source of truth:

```dart
Future<void> recover() async {
  await security.resetInvalidated();          // clear the dead key
  final fresh = await api.reissueToken();      // server is the source of truth
  await security.write(
    key: const SecretKey('api_token'),
    value: fresh,
    policy: SecurityPolicy.strong(),
    reason: 'Re-secure your account',
  );
}
```

## 19. Security architecture

- **Envelope encryption.** Each secret gets a random 256-bit **DEK**; the payload
  is sealed with AES-256-GCM (96-bit random nonce, 128-bit tag). The **DEK** is
  held by the hardware key vault (Android Keystore / iOS Keychain), biometric-
  gated per policy.
- **The gate is a key, not a boolean.** Gated operations run a real key op; a
  forged success can't unlock data.
- **Hardware keys never cross into Dart.** Only ciphertext, the DEK (transiently),
  and metadata cross the platform channel.
- **Fail loud.** Corruption → `SecureStorageException`; bad tag →
  `CryptographicException`; invalidation → `KeyInvalidatedException`. Never plaintext.

## 20. Threat model

**Protects against:** offline attackers with the device or a backup (secrets are
hardware-encrypted and device-bound), forged-boolean bypass, coerced new
enrollment (with `invalidateOnChange`), ciphertext tampering, IV reuse.

**Does not protect against:** a fully compromised OS/kernel or hardware attack;
extraction from a rooted/jailbroken device's live process memory; forcing a
specific modality; making hardware-bound secrets survive device migration.
Integrity (root/jailbreak) signals are advisory, never guarantees.

## 21. Android details

- **Android Keystore** holds every key (TEE- or StrongBox-backed); non-exportable.
- **BiometricPrompt** with `CryptoObject`; gated ops run inside the success callback.
- **KeyGenParameterSpec:** AES-256-GCM, `setUserAuthenticationRequired`,
  `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG[|AUTH_DEVICE_CREDENTIAL])`,
  `setInvalidatedByBiometricEnrollment`, optional StrongBox with TEE fallback.
- **Strength:** only `BIOMETRIC_STRONG` (Class 3) can gate keys.
- Requires **`FlutterFragmentActivity`**; `minSdk 24`.

## 22. iOS details

- **Keychain** items with **`SecAccessControl`**; `ThisDeviceOnly` (excluded from backups).
- **`biometryCurrentSet`** (default) vs **`biometryAny`** for enrollment binding.
- **Secure Enclave** P-256 signing backs `authenticate()`.
- **LocalAuthentication** for availability; `biometryType` is UX-only.
- Requires **`NSFaceIDUsageDescription`**; iOS **13.0+**.

## 23. Platform limitations

- **No forced modality** on either OS (Face ID vs fingerprint).
- **Android can't enumerate enrolled modalities** — use `status`/`strength`.
- **Hardware keys are device-bound** — no migration/restore; re-provision.
- **iOS Keychain survives app reinstall**; Android Keystore is wiped — behavior
  differs; a first-run purge for iOS is planned.
- **Not validated on physical hardware yet.** `signChallenge`, lifecycle events,
  `enableProtection`/`disableProtection`, `policyOf` are not implemented in 0.1.0.
- **macOS/Windows/Linux** are not yet supported.

## 24. Error handling

All failures are subtypes of the sealed `BiometricSecurityException`:

| Exception | Meaning |
|---|---|
| `BiometricAuthCanceledException` | user dismissed the prompt |
| `BiometricAuthFailedException` | biometric did not match |
| `BiometricLockedOutException` | too many attempts (`isPermanent`) |
| `BiometricUnavailableException` | no hardware / temporarily unavailable |
| `BiometricNotEnrolledException` | nothing enrolled |
| `KeyInvalidatedException` | key invalidated by enrollment/lock change |
| `CryptographicException` | tampered/corrupt ciphertext (no plaintext returned) |
| `SecureStorageException` | storage/metadata failure |
| `PolicyUnsupportedException` | device can't satisfy the policy |
| `UnsupportedPlatformException` | platform not implemented |

## 25. Testing

```bash
flutter analyze
flutter test               # Dart unit tests (storage engine, policy, facade)
cd example && flutter build apk --debug          # Android
cd example && flutter build ios --no-codesign    # iOS
```

Native unit tests: `cd example/android && ./gradlew :biometric_security:testDebugUnitTest`
and the Xcode `RunnerTests` scheme.

## 26. FAQ

**Can I force Face ID / fingerprint?** No — neither OS allows it. You can require
*strength* (Android) and present appropriate UI.

**Do I have to `await initialize()`?** Yes, once, before anything else.

**Is my secret gone after an OS/biometric change?** If protected with the default
`invalidateOnChange` policy, yes — by design. Re-provision from your backend.

**Does it work on emulators/simulators?** Availability and non-gated storage do.
Real biometric prompts and Secure Enclave need physical devices.

**Is it production-ready?** Not yet — see the status banner at the top.

## 27. Security recommendations

- Keep the default `SecurityPolicy.strong()` for anything sensitive.
- Never treat `authenticate()`'s result as server proof; use a signed challenge
  (when available) plus server-side authorization.
- Store only what you must on-device; keep the server as the source of truth for
  recoverable data.
- Set `android:allowBackup="false"` (or exclude the `bsec.*` prefs) for defense in depth.
- Test enrollment-change and reinstall flows on real devices before shipping.
- Review the platform limitations above and handle each one for your use case.

## 28. License

BSD 3-Clause — see [`LICENSE`](LICENSE). Contributions welcome; see
[`CONTRIBUTING.md`](CONTRIBUTING.md). Report vulnerabilities per
[`SECURITY.md`](SECURITY.md).
