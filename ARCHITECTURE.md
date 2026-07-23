# `biometric_security` — Architecture

> Status: **Design only. No production code.**
> Date: 2026-07-23
> Primary source: [`RESEARCH.md`](RESEARCH.md)
> Targets (initial): Android, iOS · (future): macOS, Windows, Linux

This document turns the research conclusions into a concrete, production-quality architecture. It is deliberately **conservative**: the simplest structure that keeps the security guarantees intact. Where a decision is security-critical it is written as a **Decision Record** (Decision / Why / Alternatives / Security implications / Platform limitations). Everything requiring your sign-off is collected in [§21](#21-architectural-decisions-requiring-approval).

### Design invariants (carried from RESEARCH.md)

- **INV-1 — The gate is a key, not a boolean.** Security-bearing operations must be gated by a hardware key that is *physically unusable* without a successful biometric auth (`CryptoObject` / `SecAccessControl`), never by a returned `true`.
- **INV-2 — Hardware key material never crosses the platform channel.** Only ciphertext, opaque handles, metadata, and typed events cross. Private keys stay in Keystore/Secure Enclave.
- **INV-3 — Never silently destroy secrets.** Invalidation/decrypt failure raises a typed event; the app decides. No silent key regeneration (the `flutter_secure_storage` anti-pattern).
- **INV-4 — No forced modality.** The OS chooses Face vs fingerprint. We enforce *strength* (Android) and surface modality for UX only.
- **INV-5 — Hardware keys are device-bound & non-transferable.** Re-provisioning is a first-class flow; the server is the source of truth for recoverable data.
- **INV-6 — Secure by default.** Strongest sensible policy is the default; weaker options are explicit, named, documented opt-ins.

### Table of Contents

1. [Overall Package Architecture](#1-overall-package-architecture)
2. [Dart Public API Layer](#2-dart-public-api-layer)
3. [Domain / Model Layer](#3-domain--model-layer)
4. [Authentication Layer](#4-authentication-layer)
5. [Secure Storage Layer](#5-secure-storage-layer)
6. [Cryptographic Layer](#6-cryptographic-layer)
7. [Key Management Layer](#7-key-management-layer)
8. [Biometric Lifecycle Layer](#8-biometric-lifecycle-layer)
9. [Platform Interface Layer](#9-platform-interface-layer)
10. [Android Implementation](#10-android-implementation)
11. [iOS Implementation](#11-ios-implementation)
12. [Error Handling](#12-error-handling)
13. [Data Migration](#13-data-migration)
14. [Key Rotation](#14-key-rotation)
15. [Key Invalidation](#15-key-invalidation)
16. [Revocation](#16-revocation)
17. [Biometric Enrollment Changes](#17-biometric-enrollment-changes)
18. [App Lifecycle Behavior](#18-app-lifecycle-behavior)
19. [Concurrent Authentication Requests](#19-concurrent-authentication-requests)
20. [Security Threat Model](#20-security-threat-model)
21. [Architectural Decisions Requiring Approval](#21-architectural-decisions-requiring-approval)

---

## 1. Overall Package Architecture

### DR-1 — Package topology: federated plugin, but only **two** platform packages at launch

**Decision.** Ship a **federated plugin** with the minimum viable split:

```
biometric_security                     # app-facing Dart API + policy engine + envelope crypto (pure Dart)
biometric_security_platform_interface  # abstract contract, shared models, enums, exceptions, channel codec
biometric_security_android             # Kotlin: BiometricPrompt + Keystore
biometric_security_darwin              # Swift: LAContext + Keychain + Secure Enclave (iOS now, macOS later)
```

`darwin` deliberately unifies iOS + macOS (shared LocalAuthentication/Keychain/Security frameworks) so the future macOS target costs almost nothing. Windows/Linux are added later as separate platform packages **without touching the app-facing API** — that is the entire reason to pay the federation tax now.

**Why.** The four options from the brief:

| Option | Verdict |
|---|---|
| Single plugin (one package, embedded native) | Rejected — future desktop platforms would force breaking changes to the app-facing package; can't publish a platform impl independently. |
| Plugin with internal platform implementations (non-federated, native folders inside one package) | Viable and simplest, but couples release cadence of native code to the Dart API and blocks third-party platform implementations. |
| **Federated plugin** | **Chosen** — the ecosystem norm (`local_auth`, `flutter_secure_storage`), isolates risky native code behind a stable Dart contract, lets platforms evolve/ship independently. |
| Multiple independent packages (separate auth vs storage vs crypto libs) | Rejected as over-engineering — the value is the *unified* layer; splitting it re-creates the fragmentation we're solving. |

This is the simplest topology that still satisfies "add macOS/Windows/Linux later without breaking users." We do **not** split auth/storage/crypto into separate published packages — they are internal layers of one package (§2–§8).

**Security implications.** The federation boundary is also the INV-2 boundary: the platform interface is the *only* place native ↔ Dart crosses, making it the single audit surface for "no key material leaks."
**Platform limitations.** None introduced; matches how official plugins already ship.
**Alternatives considered.** See table above.

### Layer map (all inside `biometric_security` unless noted)

```
┌────────────────────────────────────────────────────────────────────┐
│ 2. Public API      BiometricSecurity facade + use-case modules      │
│                    (AppLock, ProtectedValue, ProtectedKey/Signer)   │
├────────────────────────────────────────────────────────────────────┤
│ 3. Domain/Model    SecurityPolicy, Capabilities, SecretRef, results │
│ 4. Auth            AuthCoordinator (serializes prompts, INV-1)      │
│ 7. Key Mgmt        KeyManager (aliases, versions, rotation, revoke) │
│ 8. Lifecycle       EnrollmentWatcher, InvalidationDetector, events  │
│ 6. Crypto (Dart)   EnvelopeCipher (AEAD over DEK) — data layer only │
├────────────────────────────────────────────────────────────────────┤
│ 9. Platform IFC    BiometricSecurityPlatform (abstract) + codec     │  ← INV-2 boundary
├───────────────────────────────┬────────────────────────────────────┤
│ 10. Android (Kotlin)          │ 11. Darwin (Swift)                  │
│ BiometricPrompt+CryptoObject  │ LAContext + SecAccessControl        │
│ Keystore (AES KEK / EC)       │ Keychain + Secure Enclave (P-256)   │
│ 5. Secure Storage: prefs blob │ 5. Secure Storage: Keychain items   │
└───────────────────────────────┴────────────────────────────────────┘
```

Note: the **Secure Storage layer (§5)** and **KEK material** live natively; the **Envelope crypto (§6)** for bulk data lives in Dart operating only on DEKs and ciphertext (never on hardware keys), per INV-2.

---

## 2. Dart Public API Layer

Small, task-oriented, secure-by-default. Most apps import only `biometric_security`.

**Facade + capability probe**
- `BiometricSecurity` — entry facade; constructed with an optional default `SecurityPolicy`.
- `Future<Capabilities> capabilities()` — availability, enrolled, strength, modality (informational), StrongBox/Enclave presence, and the *actual security level achievable*.

**Use-case modules (the public surface developers actually call)**
- `AppLock` — `authenticate(policy)` → returns a cryptographically-backed `AuthSession` (a real key op ran, per INV-1), plus `isLocked`, `lock()`.
- `ProtectedValue` — biometric-gated encrypted storage: `write(ref, bytes, policy)`, `read(ref) → bytes` (prompts), `delete(ref)`, `contains(ref)`. This is "biometric-protected data."
- `ProtectedKey` / `ChallengeSigner` — hardware key-pair for backend-verifiable auth: `sign(challenge, policy)`, `publicKey()`. Implements the sign-a-nonce pattern (beats the boolean).
- `FeatureGate` — attach a `policy` tag to a feature; `guard(featureId)` runs the gate.

**Lifecycle & control**
- `rotateKey(scope)`, `revoke(ref)`, `revokeAll()`, `enableProtection(ref, policy)`, `disableProtection(ref)`.
- `Stream<KeyLifecycleEvent> events` — emits `KeyInvalidated`, `ReprovisionRequired`, `EnrollmentChanged`, `IntegrityRisk` (INV-3).

**Design rules.** Every method that can fail for a security reason returns a typed result/throws a typed exception (§12) — never a bare bool for security decisions. `policy` is optional and inherits the facade default (INV-6). No method silently regenerates keys.

---

## 3. Domain / Model Layer

Immutable value objects shared across Dart and mirrored in the platform interface codec.

### `SecurityPolicy` — the single knob-set that normalizes both OSes (DR-2)

```
SecurityPolicy {
  BiometricStrength strength            // strong (default) | weakAllowed(info only) 
  DeviceCredential  deviceCredential    // disallow (default) | allowFallback
  EnrollmentBinding enrollmentBinding   // invalidateOnChange (default) | persistAcrossEnrollment
  AuthValidity      authValidity        // perUse (default) | window(Duration)
  HardwareRequirement hardware          // preferStrongestAvailable (default) | requireSecureHardware
  Accessibility     accessibility       // thisDeviceOnlyWhenUnlocked (default) | afterFirstUnlock
  String?           localizedReason     // prompt copy
  bool              confirmationRequired // Android setConfirmationRequired / iOS interaction hint
}
```

### DR-2 — One normalized policy model over two divergent OSes

**Decision.** Express security intent once; map it per platform in the native layer.

| Policy field | Android mapping | iOS mapping |
|---|---|---|
| `strength = strong` | `BIOMETRIC_STRONG` / `AUTH_BIOMETRIC_STRONG` | biometrics (iOS has no weak tier ⇒ inherently strong) |
| `deviceCredential = allowFallback` | add `DEVICE_CREDENTIAL` / `AUTH_DEVICE_CREDENTIAL` | `deviceOwnerAuthentication` / `.or .devicePasscode` |
| `enrollmentBinding = invalidateOnChange` | `setInvalidatedByBiometricEnrollment(true)` (default) | `.biometryCurrentSet` |
| `enrollmentBinding = persistAcrossEnrollment` | `setInvalidatedByBiometricEnrollment(false)` | `.biometryAny` |
| `authValidity = perUse` | timeout `0/-1` + `CryptoObject` | fresh `LAContext` per op |
| `authValidity = window(d)` | `setUserAuthenticationParameters(d, …)` | reuse `LAContext` within `d` |
| `hardware = requireSecureHardware` | `setIsStrongBoxBacked(true)`→ fallback TEE; refuse if software | Secure Enclave key; refuse if unavailable |
| `accessibility = thisDeviceOnly…` | Keystore is device-bound implicitly | `…WhenUnlockedThisDeviceOnly` |

**Why.** Developers must not hand-code platform divergence; that is exactly where the research says bugs live. A single enum-based model is testable and auditable.
**Security implications.** Defaults encode INV-6 (strong, no fallback, invalidate-on-change, per-use, this-device-only). Weakening is explicit and greppable in app code.
**Platform limitations.** `strength = weakAllowed` cannot gate a key on Android (Class 2 can't back `CryptoObject`); if selected for a key-bearing op it degrades to *presence-only* and is documented as non-cryptographic. iOS has no strength tier to honor.
**Alternatives.** Per-platform policy objects (rejected — leaks platform detail to apps); free-form maps (rejected — untyped, unsafe).

### Other domain types
- `Capabilities { available, enrolled, strength, modality(informational), hasStrongBox, hasSecureEnclave, achievableLevel }`
- `SecretRef` — stable logical id for a secret (maps to key alias + storage key + metadata version).
- `SecurityLevel { strongBox, tee, secureEnclave, software, none }` — what was *actually* achieved (reported honestly).
- `AuthSession` — proof an auth-bound key op succeeded (opaque, time-stamped).
- Result/exception hierarchy (§12); `KeyLifecycleEvent` union (§8).

---

## 4. Authentication Layer

`AuthCoordinator` (Dart) is the single choke point for every prompt-bearing operation.

Responsibilities:
- **Serialize** all biometric prompts process-wide (§19) — one native prompt at a time.
- Bind each auth to a **concrete key operation** (encrypt/decrypt/sign) so INV-1 holds — there is no "authenticate then trust a flag" path in the security-bearing modules.
- Translate native callbacks into typed results (§12); map lockout/cancel/invalidation to events.
- Apply `authValidity`: for `window`, hold a short-lived native auth context and reuse; for `perUse`, force a fresh prompt+`CryptoObject`/`LAContext` per op.

`AppLock.authenticate()` is implemented as: run a **real** decrypt/sign against a dedicated app-lock key. If the key op succeeds, the user is authenticated; if it throws invalidation, emit `ReprovisionRequired`. This makes app-lock resistant to boolean-hooking on rooted devices (best-effort; see threat model).

---

## 5. Secure Storage Layer

Stores **ciphertext + metadata**, not keys. Keys live in Keystore/Enclave (§7).

- **Android:** encrypted DEK-wrapped payloads + metadata in a dedicated `SharedPreferences` file (app-private). The KEK in Keystore does the unwrap; prefs hold only ciphertext, IVs, tags, versioned metadata.
- **iOS:** Keychain items (generic password class) holding ciphertext + metadata, with `kSecAttrAccessible…ThisDeviceOnly`; the Enclave key wraps the DEK. **Access-control-bearing** items additionally carry a `SecAccessControl`.

### DR-3 — We do **not** depend on `flutter_secure_storage`
**Decision.** Implement the thin storage slice ourselves. **Why.** Its abstraction hides per-item access control and (critically) silently regenerates keys on decrypt failure, violating INV-3. **Security implications.** We own the failure semantics: a decrypt failure surfaces as `KeyInvalidated`, never a silent wipe. **Platform limitations.** iOS Keychain items **persist across uninstall**; Android Keystore clears on uninstall — normalized in §16/§17. **Alternatives.** Depend on it (rejected, INV-3); fork it (rejected, RESEARCH.md §10).

---

## 6. Cryptographic Layer

### DR-4 — Envelope encryption: hardware-sealed KEK wraps per-secret DEKs

**Decision.**
- **Data encryption (bulk):** **AES-256-GCM** as the default AEAD (ChaCha20-Poly1305 as an alternative where a platform lacks AES acceleration). Runs in the native layer where the DEK is available, or in Dart for large payloads — but only ever over the **DEK**, never the KEK.
- **Key hierarchy:** each secret has its own random **256-bit DEK**. The DEK is **wrapped by a hardware KEK**:
  - Android: KEK is an **AES-256 Keystore key** (GCM wrap) *or* an EC Keystore key; usage-gated by `CryptoObject`.
  - iOS: KEK is a **P-256 Secure Enclave** key; DEK wrapped via **ECIES / ECDH→HKDF→AES-GCM** because the Enclave is EC-only.
- **Nonce/IV:** 96-bit random IV per encryption via the platform CSPRNG (`SecRandomCopyBytes` / `SecureRandom` from the Keystore provider). **Never reuse an IV under the same key**; a fresh DEK+IV per write makes reuse structurally impossible.
- **Auth tag:** 128-bit GCM tag, stored with ciphertext; verified on decrypt (tamper ⇒ typed `IntegrityError`, no plaintext returned).
- **Key versioning:** every wrapped blob carries `{schemaVersion, kekAlias, kekVersion, algo, kdfParams, createdAt}`. Enables rotation (§14) and migration (§13).

**Why.** Envelope is the only model that reconciles "iOS Enclave can't hold symmetric keys" with "we need symmetric bulk crypto," supports **many secrets under few hardware keys**, and makes **rotation** (rewrap DEKs) and **bulk revocation** (destroy KEK) cheap. AES-256-GCM is the standard authenticated cipher, hardware-accelerated on both platforms.
**Security implications.** Bulk data touches a software AEAD step (unavoidable on iOS); the DEK is only ever in memory transiently and is itself protected at rest by the hardware KEK. IIn-memory DEK is a residual exposure on a compromised process (threat model TB-3).
**Platform limitations.** Secure Enclave = **P-256 EC only**, no RSA/AES/import (RESEARCH.md §4.4) ⇒ ECIES envelope mandatory on iOS. Android StrongBox may be absent ⇒ TEE fallback.
**Alternatives.** (a) Store the symmetric key directly in Android Keystore and mirror with per-item RSA on iOS — rejected: asymmetric platform models, no clean rotation. (b) Pure-Dart crypto with a software master key — rejected: not hardware-backed, violates INV-1. (c) Per-secret hardware key (no envelope) — supported as an *option* for high-value single secrets, but not the default (too many Keystore/Enclave entries, coarse rotation).

### DR-5 — Multiple secrets & keying strategy
**Decision.** Default **envelope** (one KEK per *protection scope*, many DEKs). Offer opt-in **per-secret hardware key** for designated high-value secrets. A "protection scope" groups secrets sharing a policy + KEK (e.g. `appLock`, `default`, custom).
**Why/Sec/Alt.** Fewer hardware entries, atomic scope-level revocation, per-secret invalidation still possible via DEK deletion; per-secret keys give finest-grained invalidation at higher cost.

---

## 7. Key Management Layer

`KeyManager` (Dart) orchestrates aliases, versions, and lifecycle; the native layer performs the actual Keystore/Enclave operations.

- **Alias scheme:** `bsec.<scope>.kek.v<version>` (Android Keystore alias / iOS key tag). DEK-wrap metadata references the alias+version.
- **Metadata store:** versioned JSON alongside each secret (in §5 storage) — never contains key material, only references and params.
- **Lifecycle state machine** (canonical): `Create → Protect → Use → Invalidate → Revoke → Destroy`.

```
Create   generate KEK in Keystore/Enclave under policy (fail if hardware req unmet)
Protect  wrap DEK with KEK; persist ciphertext+metadata (§5)
Use      biometric-gated unwrap/encrypt/sign via CryptoObject / SecAccessControl (§4)
Invalidate  KEK becomes unusable (enrollment change / lock disabled) → emit event (§15)
Revoke   app- or user-initiated: delete DEK(s) and/or KEK; secrets become undecryptable (§16)
Destroy  delete KEK alias + wipe metadata + overwrite ciphertext; terminal
```

`KeyManager` guarantees INV-3: an invalidated `Use` never auto-triggers `Create`; it surfaces `ReprovisionRequired` and waits for explicit app action.

---

## 8. Biometric Lifecycle Layer

Detects and reports state changes; owns the **event stream**.

- `InvalidationDetector` — on any `Use` that throws `KeyPermanentlyInvalidatedException` (Android) / `errSecAuthFailed`/decode failure on a `biometryCurrentSet` item (iOS), classify and emit `KeyInvalidated{scope, reason}`.
- `EnrollmentWatcher` — best-effort proactive signal. Android: compare a stored enrollment fingerprint (via `BiometricManager` state / a canary key that invalidates) at foreground; iOS: `LAContext.evaluatedPolicyDomainState` change indicates the biometric set changed. Emits `EnrollmentChanged`.
- `IntegrityMonitor` — optional root/jailbreak heuristics + (if enabled) Play Integrity / DeviceCheck-App Attest → `IntegrityRisk` (advisory, never a hard gate — RESEARCH.md §6.2).

Events are **advisory to the app**; the package never takes destructive action on its own (INV-3).

---

## 9. Platform Interface Layer

`biometric_security_platform_interface` defines the contract; it is the **INV-2 audit boundary**.

- `abstract class BiometricSecurityPlatform extends PlatformInterface`.
- Method set (illustrative): `getCapabilities`, `createKek(scope, policyDto)`, `wrap(scope, dekCiphertextRequest)`, `unwrap(scope, blob, promptDto)`, `sign(scope, challenge, promptDto)`, `deleteKey(scope|alias)`, `readItem/writeItem/deleteItem`, `evaluatedDomainState`.
- **Codec rule:** DTOs carry only ciphertext, IVs, tags, aliases, policy enums, prompt strings, and typed error codes. **No private key bytes, ever** (INV-2). A schema test asserts no field can carry raw key material.
- Channels: a `MethodChannel` for request/response; an `EventChannel` for lifecycle events (§8). All native errors map to a shared typed error code table (§12).

---

## 10. Android Implementation (`biometric_security_android`, Kotlin)

Requires host `MainActivity` to extend **`FlutterFragmentActivity`** (the #1 `local_auth` pitfall — documented + asserted at runtime with a clear error).

- **Android Keystore** (`AndroidKeyStore` provider) holds every KEK; keys are non-exportable, device-bound, TEE- or StrongBox-backed.
- **`KeyGenParameterSpec`** for a KEK (AES-256-GCM KEK example):
  - `setBlockModes(GCM)`, `setEncryptionPaddings(NoPadding)`, `setKeySize(256)`
  - `setUserAuthenticationRequired(true)`
  - `setUserAuthenticationParameters(timeout, allowedTypes)` — `timeout=0` ⇒ per-use; `allowedTypes = AUTH_BIOMETRIC_STRONG [| AUTH_DEVICE_CREDENTIAL]` from policy
  - `setInvalidatedByBiometricEnrollment(true|false)` from `enrollmentBinding`
  - `setIsStrongBoxBacked(true)` when `requireSecureHardware`/preferred → catch `StrongBoxUnavailableException` → retry TEE (report achieved `SecurityLevel`)
  - optional `setAttestationChallenge(...)` for backend attestation.
- **BiometricPrompt** (`androidx.biometric`): `PromptInfo` built from policy; `setAllowedAuthenticators(BIOMETRIC_STRONG [| DEVICE_CREDENTIAL])`; `authenticate(promptInfo, CryptoObject(cipher|signature))`. Key op runs **inside** `onAuthenticationSucceeded` using the returned `CryptoObject` — INV-1.
- **Biometric strength:** enforce `BIOMETRIC_STRONG`; query `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` for capabilities; Class 2/1 cannot back keys and are reported as non-crypto-capable.
- **Device-credential fallback:** only when `deviceCredential = allowFallback`; note such keys are not enrollment-invalidated (documented trade-off).
- **Key invalidation:** `KeyPermanentlyInvalidatedException` on cipher init → mapped to `KeyInvalidated` event; **no silent regen**.
- **Hardware-backed keys:** report `KeyInfo.securityLevel` / `isInsideSecureHardware()` as `SecurityLevel`.

Required explicit documentation items (all above): ✔ Keystore ✔ BiometricPrompt ✔ KeyGenParameterSpec ✔ auth requirements ✔ strength ✔ device-credential fallback ✔ key invalidation ✔ hardware-backed keys.

---

## 11. iOS Implementation (`biometric_security_darwin`, Swift; iOS now, macOS later)

- **LocalAuthentication:** `LAContext` evaluated with `deviceOwnerAuthenticationWithBiometrics` (biometrics) or `deviceOwnerAuthentication` (biometrics-or-passcode) per `deviceCredential`. `biometryType` surfaced for **UX only** (INV-4). Fresh `LAContext` per op for `perUse`; reuse within `window`.
- **Keychain:** ciphertext + metadata stored as generic-password items with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (default) or `…AfterFirstUnlockThisDeviceOnly`.
- **SecAccessControl:** built from policy — `.privateKeyUsage` + `.biometryCurrentSet` (default) or `.biometryAny`, optionally `.or(.devicePasscode)` when fallback allowed. Attached to the Enclave key so usage is impossible without OS-verified auth (INV-1).
- **biometryCurrentSet:** default (`enrollmentBinding = invalidateOnChange`) — key/item becomes permanently inaccessible if the enrolled set changes (coerced-enrollment defense).
- **biometryAny:** opt-in (`persistAcrossEnrollment`) — survives new enrollments (weaker, documented).
- **Secure Enclave:** P-256 key generated with `kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent`, access control as above; used for ECDH/ECDSA. DEK wrapped via ECIES (ECDH→HKDF→AES-GCM). EC-only limits acknowledged (§6). Device without Enclave ⇒ software fallback only if `hardware` policy allows, else refuse.
- **Key invalidation:** unwrap/sign failing with `errSecAuthFailed` / item-not-found on a `biometryCurrentSet` key → `KeyInvalidated`; **no silent regen** (INV-3).
- **Uninstall persistence:** Keychain survives uninstall → handled by §16 (explicit provisioning check + optional first-run purge).

Required explicit documentation items: ✔ LocalAuthentication ✔ Keychain ✔ SecAccessControl ✔ biometryAny ✔ biometryCurrentSet ✔ Secure Enclave ✔ key invalidation.

---

## 12. Error Handling

Single typed hierarchy, shared via the platform interface (INV-3: every security failure is a first-class, catchable outcome — never a silent recovery).

```
BiometricSecurityException (sealed)
├─ UnavailableException            hardware/API absent
├─ NotEnrolledException            no biometric enrolled
├─ StrengthInsufficientException   only weak biometrics present
├─ UserCanceledException           user dismissed prompt
├─ AuthFailedException             biometric mismatch (retryable)
├─ LockedOutException              temporary lockout (retry after)
├─ PermanentlyLockedOutException   requires device-credential unlock
├─ KeyInvalidatedException         enrollment/lock change invalidated KEK  → triggers ReprovisionRequired
├─ ReprovisionRequiredException    caller must re-create + re-seal secrets
├─ HardwareUnavailableException    StrongBox/Enclave required but absent
├─ PolicyUnsupportedException      requested policy not expressible on device
├─ IntegrityException              AEAD tag mismatch / tampering (no plaintext returned)
└─ IntegrityRiskException          root/jailbreak signal (advisory)
```

Each carries `code`, `message`, `platformDetail?`, `isRecoverable`, and `scope?`. Native code maps to a fixed code table so Android/iOS produce identical Dart types.

---

## 13. Data Migration

### DR-6 — Explicit, versioned, non-destructive migration
**Decision.** Every stored blob carries `schemaVersion`. On read, if `schemaVersion < current`, run a registered forward migrator that re-wraps/re-encodes and rewrites atomically (write-new → verify → delete-old). Migrations are **never** lossy and never silently drop unreadable data — an unmigratable blob raises `ReprovisionRequired`.
**Why.** App upgrades and algorithm/policy changes must not corrupt or silently discard secrets (INV-3).
**Security implications.** Migration may require a biometric prompt (to unwrap under the old KEK) — surfaced honestly. **Platform limitations.** None. **Alternatives.** Best-effort/in-place mutation (rejected — corruption risk); wipe-on-version-change (rejected — data loss).

---

## 14. Key Rotation

### DR-7 — Rotate by re-wrapping DEKs under a new KEK version
**Decision.** `rotateKey(scope)`: generate `kek.v(n+1)` → for each secret in scope, biometric-gated unwrap DEK under `v(n)`, re-wrap under `v(n+1)`, rewrite metadata → delete `v(n)`. DEKs themselves may optionally be regenerated (full rotation with data re-encryption) or preserved (KEK-only rotation).
**Why.** Cheap, envelope-native, no plaintext re-exposure beyond the transient DEK; supports scheduled rotation and post-incident rotation.
**Security implications.** Requires one auth per scope (or per secret if `perUse`); a crash mid-rotation is safe because old version isn't deleted until new is verified. **Platform limitations.** None beyond auth prompts. **Alternatives.** Re-encrypt all data under a fresh symmetric key held in software (rejected — not hardware-sealed).

---

## 15. Key Invalidation

Invalidation is **detected, not caused, by us**. Triggers (platform-mapped in §17): new/removed biometric enrollment (when `invalidateOnChange`/`biometryCurrentSet`), device lock disabled, secure hardware reset.

Flow: `Use` fails with platform invalidation error → `InvalidationDetector` emits `KeyInvalidated{scope,reason}` → `KeyManager` marks scope `invalid` and blocks further `Use` → app receives `ReprovisionRequired` and decides (re-authenticate from server, re-enroll secrets, or wipe). **We never auto-regenerate** (INV-3). Data sealed by the invalid KEK is, by design, unrecoverable on-device (INV-5) — the honest contract.

---

## 16. Revocation

### DR-8 — Two revocation scopes, both explicit and complete
**Decision.**
- `revoke(ref)` — delete that secret's DEK + ciphertext + metadata (single secret dies).
- `revokeAll()` / `revoke(scope)` — delete the KEK alias (all DEKs in scope become undecryptable instantly) then wipe ciphertext/metadata.
On **iOS**, because Keychain survives uninstall, revocation and a first-run "clean slate" check both actively delete items; provisioning writes a device-install marker so a reinstall is detected and stale items purged if policy requires.
**Why.** Revocation must be immediate and total; deleting the KEK is the strongest, cheapest kill-switch. **Security implications.** Irreversible by design (that's the point). **Platform limitations.** Android Keystore auto-clears on uninstall (revocation "for free"); iOS needs the explicit purge described. **Alternatives.** Flag-based soft revoke (rejected — data still decryptable).

---

## 17. Biometric Enrollment Changes

Central normalization table (the research's highest-risk area):

| Field / event | `invalidateOnChange` (default) | `persistAcrossEnrollment` (opt-in) |
|---|---|---|
| Android backing | `setInvalidatedByBiometricEnrollment(true)` | `false` |
| iOS backing | `.biometryCurrentSet` | `.biometryAny` |
| New biometric enrolled | KEK invalid → `KeyInvalidated` → `ReprovisionRequired` | KEK survives; secrets still usable |
| Biometric removed | Invalid → reprovision | Survives (until all removed) |
| All biometrics removed | Invalid → reprovision | Invalid (no biometric to gate) |
| Security posture | Defends against coerced-enrollment; more re-provisioning | Convenience; weaker |

Documented explicitly so app authors choose consciously (INV-6 default = secure).

---

## 18. App Lifecycle Behavior

Defined behavior for each scenario the brief lists:

| Event | Behavior |
|---|---|
| **User changes biometrics** | Per §17. Default: KEK invalid → `KeyInvalidated`/`ReprovisionRequired`; app re-provisions. |
| **User removes biometrics** | Per §17. Default: invalidation. |
| **User disables device lock** | Both platforms invalidate auth-bound keys (no secure lock screen). → `KeyInvalidated`. Re-provision after lock re-enabled. |
| **Biometric becomes unavailable** (temp) | `capabilities()` reflects it; `Use` raises `Unavailable`/`NotEnrolled`; if `allowFallback`, device credential can still unlock. No data loss. |
| **Biometric locked out** (too many attempts) | `LockedOut` (retry later) or `PermanentlyLockedOut` (needs device-credential unlock). No key destruction. |
| **Secure key becomes invalid** | §15 flow; blocked `Use`; `ReprovisionRequired`. |
| **App reinstalled** | Android: Keystore keys gone → secrets undecryptable → clean reprovision. iOS: Keychain persists → install-marker check purges/reuses per policy (§16). Behavior normalized so the developer sees one contract: "reinstall ⇒ reprovision." |
| **App upgraded** | Keys survive (same signing key/package). Metadata migration (§13) runs if schema changed. No prompts unless a `Use`/migration needs one. |
| **User restores app data** (backup) | Hardware keys are **not** in backups (`ThisDeviceOnly`/Keystore non-exportable). Restored ciphertext without its device-bound KEK ⇒ undecryptable ⇒ `ReprovisionRequired`. We explicitly exclude our secrets from cloud backup where possible. |
| **Device rooted/jailbroken** | `IntegrityMonitor` may emit `IntegrityRisk` (advisory). Hardware keys remain protected; per-use `CryptoObject`/fresh `LAContext` limit abuse; app policy decides whether to refuse. Never a silent guarantee. |

App foreground/background: on resume, `EnrollmentWatcher` re-checks domain state; any in-flight auth is canceled on background (§19); `window` auth validity is treated as expired across a background transition for auth-bound ops.

---

## 19. Concurrent Authentication Requests

### DR-9 — Serialize all prompts through a single coordinator queue
**Decision.** `AuthCoordinator` holds a process-wide FIFO mutex. Only one native biometric prompt is ever active. Concurrent callers either **queue** (default) or **fail-fast** with `AuthBusyException` (opt-in per call). Backgrounding cancels the active prompt and rejects the queue head with `UserCanceledException`.
**Why.** Both `BiometricPrompt` and `LAContext` misbehave with overlapping prompts (undefined UI, crashes); serialization is the only safe model. **Security implications.** Prevents a race where a second request rides a first request's auth window; each queued op re-evaluates policy at execution. **Platform limitations.** Native APIs are single-prompt anyway. **Alternatives.** Allow parallel (rejected — platform-unsafe); global lock without queue (rejected — poor UX, lost requests).

---

## 20. Security Threat Model

### Assets
A1 hardware KEKs · A2 DEKs (transient) · A3 protected secrets at rest · A4 auth-signing keys · A5 policy/metadata integrity.

### Security boundaries
- **B1 Secure hardware (TEE/StrongBox/Secure Enclave):** trusted; private keys never leave it (INV-2). Highest boundary.
- **B2 OS keystore/keychain + biometric subsystem:** trusted to enforce access control; relied on for INV-1.
- **B3 Platform channel (Dart↔native):** carries only ciphertext/handles; audited to never carry key material.
- **B4 Dart/app process:** semi-trusted; transiently holds DEKs/plaintext. Compromise here is the residual risk.
- **B5 Backup/cloud/other device:** untrusted; excluded via `ThisDeviceOnly`/non-exportable keys.

### Threats & mitigations
| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Boolean-hook bypass of biometric check | INV-1 key-gated ops; sign-challenge for backend verification | On rooted device, an *already-unlocked* `window` op could be abused → default `perUse` |
| T2 | Extract keys from device | Non-exportable hardware keys (B1) | Hardware attack out of scope |
| T3 | Coerced new enrollment unlocks old secrets | `invalidateOnChange`/`biometryCurrentSet` default | User chose `persistAcrossEnrollment` |
| T4 | Silent data loss on invalidation | INV-3, no auto-regen, typed events | App mishandles event (its responsibility) |
| T5 | Secrets leak via cloud backup | `ThisDeviceOnly` + backup exclusion | Misconfigured host app |
| T6 | Ciphertext tampering | AES-GCM auth tag; reject on mismatch | — |
| T7 | IV reuse | Fresh DEK+random 96-bit IV per write | — |
| T8 | Process-memory scraping of DEK/plaintext (B4) | Minimize DEK lifetime; per-use; no plaintext logging | Compromised OS/process (accepted) |
| T9 | Overlapping-prompt race | AuthCoordinator serialization (§19) | — |
| T10 | Rooted/jailbroken device | Advisory `IntegrityRisk`; policy may refuse | Not a hard guarantee (documented) |

### Explicit non-goals (honest limits, per INV-4/INV-5)
- Cannot force a specific biometric modality.
- Cannot protect against a fully compromised OS/kernel or hardware attack.
- Cannot make hardware-bound secrets survive device migration/restore.
- Cannot guarantee root/jailbreak detection.

---

## 21. Architectural Decisions Requiring Approval

Each maps to a DR/§ above. **These are the gate before implementation.**

1. **Package topology (DR-1):** Federated plugin with `biometric_security` + `_platform_interface` + `_android` + `_darwin` (iOS+macOS unified). Approve the federation tax now for future desktop platforms? ✅/❌
2. **Normalized `SecurityPolicy` model (DR-2):** Single enum-based policy mapped per-platform, with the specific defaults (strong · no device-credential fallback · invalidate-on-enrollment · per-use · this-device-only). Approve these secure-by-default values? ✅/❌
3. **No `flutter_secure_storage` dependency (DR-3):** Own the storage slice to control failure semantics. Approve building it vs depending? ✅/❌
4. **Envelope encryption + AES-256-GCM + hardware KEK (DR-4):** Approve AES-256-GCM default (ChaCha20-Poly1305 alt), 256-bit DEKs, 96-bit random IVs, 128-bit tags, ECIES envelope on iOS? ✅/❌
5. **Multi-secret keying default (DR-5):** Envelope (one KEK per scope, many DEKs) as default, per-secret hardware keys as opt-in. Approve? ✅/❌
6. **Key lifecycle & alias scheme (§7):** `Create→Protect→Use→Invalidate→Revoke→Destroy`, alias `bsec.<scope>.kek.v<n>`, versioned metadata. Approve? ✅/❌
7. **Migration policy (DR-6):** Versioned, non-destructive, reprovision-on-unmigratable. Approve? ✅/❌
8. **Rotation model (DR-7):** Re-wrap DEKs under new KEK version; optional full data re-encryption. Approve? ✅/❌
9. **Invalidation contract (§15) & INV-3:** Never auto-regenerate; always emit `ReprovisionRequired`. Approve this (accepts more re-provisioning UX)? ✅/❌
10. **Revocation semantics (DR-8):** KEK-delete kill-switch; explicit iOS uninstall-purge behavior. Approve? ✅/❌
11. **Enrollment-binding default (§17):** `invalidateOnChange` / `biometryCurrentSet` as default (favors security over convenience). Approve? ✅/❌
12. **Reinstall/restore contract (§18):** Normalize to "reinstall or restore ⇒ reprovision" across platforms (incl. iOS Keychain purge on reinstall). Approve? ✅/❌
13. **Concurrency model (DR-9):** Serialize all prompts via a single FIFO coordinator; queue-by-default / fail-fast opt-in. Approve? ✅/❌
14. **Integrity signals (§8/§20):** Root/jailbreak + optional Play Integrity / App Attest are **advisory only**, never a hard gate. Approve advisory-only stance? ✅/❌
15. **Hardware requirement default (DR-2 `hardware`):** `preferStrongestAvailable` (degrade + report) as default vs hard-require secure hardware. Approve degrade-and-report default? ✅/❌
16. **Minimum baselines (open):** Android `minSdk` and iOS minimum version — need your target numbers before native work (affects StrongBox/attestation/API availability). Provide values.
17. **Package license (RESEARCH.md §7):** BSD-3-Clause (recommended) vs Apache-2.0 (patent grant). Choose.
18. **Backend/attestation scope:** Is there a server to consume challenge-signatures/attestation? Determines whether `ChallengeSigner` is a launch feature or deferred. Confirm.

---

*End of ARCHITECTURE.md — no production code included, by design.*
