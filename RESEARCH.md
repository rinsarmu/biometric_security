# `biometric_security` — Research & Architecture Analysis

> Status: **Research only. No implementation.**
> Date: 2026-07-23
> Target platforms (initial): Android, iOS · (future): macOS, Windows, Linux
> Author: engineering research pass prior to design freeze.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Existing Package Comparison](#2-existing-package-comparison)
3. [Native Android Security Analysis](#3-native-android-security-analysis)
4. [Native iOS Security Analysis](#4-native-ios-security-analysis)
5. [Platform Capability Matrix](#5-platform-capability-matrix)
6. [Security Risks](#6-security-risks)
7. [Licensing Analysis](#7-licensing-analysis)
8. [Recommended Architecture](#8-recommended-architecture)
9. [Recommended Dependencies](#9-recommended-dependencies)
10. [Fork vs New Implementation Decision](#10-fork-vs-new-implementation-decision)
11. [Open Questions](#11-open-questions)
12. [Recommended Next Steps](#12-recommended-next-steps)
13. [Appendix A — Sources](#appendix-a--sources)

---

## 1. Executive Summary

### 1.1 The problem

The Flutter ecosystem has **capable but fragmented** primitives for biometric security. No single package delivers the whole chain that a serious app needs:

```
biometric availability → policy enforcement → hardware-backed key →
biometric-gated crypto → encrypted storage → enrollment-change invalidation →
key rotation / revocation → app-lock & feature-gating
```

Today teams stitch together `local_auth` (present a biometric prompt) + `flutter_secure_storage` (encrypt at rest) + hand-rolled native glue for anything involving **keys that are cryptographically bound to biometric state**. That seam is exactly where security bugs live: apps routinely treat `local_auth`'s returned boolean as a security guarantee, when it is only a UI signal that is trivially bypassable on a compromised device.

### 1.2 The core insight

**A returned "true" from a biometric prompt is not a security boundary. A key that physically cannot be used unless biometric authentication succeeded *is*.**

The value `biometric_security` should add over the status quo is to make the *cryptographic binding* — Keystore/Keychain keys whose usage is gated by `setUserAuthenticationParameters` / `SecAccessControl` — the default and primary API, with the "just show a prompt" flow available but clearly labeled as the weaker path.

### 1.3 Recommendation (headline)

> **D — Combine approaches, leaning heavily toward "new plugin on a federated platform-interface architecture," while *depending on* rather than forking the two best-maintained primitives where they genuinely help.**

Concretely:

- **Build** a new federated plugin (`biometric_security` + `biometric_security_platform_interface` + `biometric_security_android` + `biometric_security_darwin`) that owns the **key-management + biometric-binding core** natively. This is the differentiator and cannot be assembled reliably from existing packages.
- **Depend on** `local_auth` (official, BSD-3) for the *availability/strength/enrolled-biometrics detection* surface where it is already correct and well-maintained — but **do not** rely on it for the security decision. Consider dropping it later if the native layer must be written anyway.
- **Do not fork** `flutter_secure_storage`. Re-use its *ideas*, not its code. Its Android model (RSA-wrapped AES key in Keystore, prefs blob) and iOS model (Keychain items) are a good baseline but its abstraction hides exactly the knobs we must expose (per-item access-control, biometric gating, enrollment invalidation). Interop-compatible storage is a nice-to-have, not a reason to fork.
- **Depend on** `pointycastle` and/or `cryptography`/`cryptography_plus` only for *pure-Dart* helpers (envelope encryption of large payloads, HKDF, AEAD) — never for anything that should be hardware-backed. Hardware-backed keys must stay in the Keystore/Secure Enclave and never transit Dart.

### 1.4 What is genuinely hard (and why this package is worth building)

- **You cannot force a *specific* biometric modality** (Face ID vs Touch ID vs fingerprint) on either platform from an app. Any API that promises "Face ID only" is misrepresenting the OS. We must design around this, not pretend otherwise.
- **Enrollment-change invalidation semantics differ** between Android (`setInvalidatedByBiometricEnrollment`) and iOS (`biometryCurrentSet` vs `biometryAny`) and both interact badly with app upgrades, key migration, and device-credential fallback. This is the single most bug-prone area and the strongest argument for a dedicated, well-tested package.
- **"Strong vs weak" biometrics is an Android-only concept** and only `BIOMETRIC_STRONG` (Class 3) can gate Keystore keys. Weak/Class 2 and convenience/Class 1 cannot. iOS has no analogous public taxonomy.

---

## 2. Existing Package Comparison

Scores are engineering judgement, not marketing. "Use as dependency?" is specifically *for this project*.

### 2.1 `local_auth` (+ `local_auth_android`, `local_auth_darwin`)

| Attribute | Assessment |
|---|---|
| Maintainer | **Official** `flutter/packages` team (Google) |
| License | **BSD-3-Clause** |
| Activity | High, continuous. Recent releases bumped Java 17 / Flutter 3.35 / Dart 3.9 baselines (Dec 2025). |
| Architecture | Federated (app-facing `local_auth`, platform packages `local_auth_android` / `local_auth_darwin`, interface `local_auth_platform_interface`). Good model to emulate. |

**Does well**
- Presents the correct system biometric UI (`BiometricPrompt` on Android, `LAContext`/Face ID/Touch ID on iOS) and returns a boolean + typed errors.
- Reliable *availability* detection: `isDeviceSupported()`, `canCheckBiometrics`, `getAvailableBiometrics()` returning a `BiometricType` set.
- `AuthenticationOptions`: `biometricOnly`, `stickyAuth`, `useErrorDialogs`, `sensitiveTransaction`.
- Well-documented error codes and platform-specific message localization.

**Limitations**
- **Returns a boolean, not a cryptographic result.** There is no binding between "auth succeeded" and any key operation. On a rooted/hooked device the boolean is forgeable (Frida/objection can flip the return). It authenticates *presence*, not a *transaction*.
- **`canCheckBiometrics` ≠ enrolled.** It reports hardware capability; you still must check `getAvailableBiometrics()` for actual enrollment. Common developer trap.
- **No key management, no storage, no enrollment-change invalidation.** Out of scope by design.
- **Cannot select a modality.** `BiometricType` is informational; you cannot demand Face ID over Touch ID (see §4).
- **Android requires `FlutterFragmentActivity`** (not `FlutterActivity`) — the #1 integration failure and a frequent GitHub issue.
- Historical friction: post-Flutter-3 devices with PIN-only (no biometric enrolled) still being prompted; iOS fallback-button behavior with `biometricOnly:true`.

**Common developer pain**
- Forgetting `FlutterFragmentActivity` → runtime crash.
- Treating the boolean as authorization for sensitive actions (security anti-pattern).
- Expecting to force Face-ID-only or fingerprint-only (impossible).
- Confusing "device supported" with "biometric enrolled."

**Use as dependency?** **Yes, initially — for detection only.** It is the safe, official source of availability/strength/enrolled info. **Not** for the security decision.
**Worth forking?** **No.** It is official, healthy, BSD-3. Forking inherits maintenance cost and loses upstream fixes. If we end up writing the native availability probes anyway (likely), we can drop the dependency without a fork.
**Security implication:** Safe to depend on; just never let its boolean *be* the gate.

### 2.2 `flutter_secure_storage` (+ platform packages)

| Attribute | Assessment |
|---|---|
| Maintainer | Julian Steenbakker (`juliansteenbakker`), community-maintained; original © German Saprykin 2017 |
| License | **BSD-3-Clause** |
| Activity | Active; v10.x line (v10.3.1 ~mid-2026). v10 reworked the Android cipher path (AES key stored directly in Keystore; optional biometric auth). |
| Platforms | Android, iOS, macOS, Linux, Windows, Web (federated). |

**Does well**
- Simple `read/write/delete/readAll` key-value API over iOS Keychain and Android Keystore-wrapped storage.
- Android: historically RSA-OAEP-wrapped AES-GCM with the wrapping key in Keystore; v10 added storing the AES key directly in Keystore and StrongBox support where available.
- iOS/macOS: Keychain items with configurable `kSecAttrAccessible` and access groups.
- Cross-platform breadth already solved (incl. desktop/web), which matters for our future-platform roadmap.

**Limitations**
- **Abstraction hides the knobs we need.** Per-item `SecAccessControl` flags, biometric gating, `biometryCurrentSet`/enrollment invalidation, and Android `setUserAuthenticationParameters` are not first-class, uniform, per-secret controls. Biometric support exists but is coarse.
- **Historical data-loss / corruption issues on Android**: `BadPaddingException`/`KeyStoreException` after OS upgrades or key regeneration; the library added "recreate the key if decoding fails" logic — which on the wrong path means **silent loss of previously stored secrets**. This is precisely the enrollment/upgrade minefield our package must handle *deliberately*, not silently.
- Web backend is not hardware-backed (irrelevant now, relevant to future roadmap messaging).
- No concept of key rotation, revocation, or app-lock policy — it is storage, not a security policy engine.

**Common developer pain**
- Secrets disappearing after Android upgrades / backup-restore / `setInvalidatedByBiometricEnrollment` interactions.
- Confusion about which `kSecAttrAccessible` level is used and whether items survive restore-to-new-device.
- Expecting biometric-gated reads to be uniform across platforms.

**Use as dependency?** **No (as the core).** Optionally as a fallback backend for *non-sensitive* config, but our secret storage must own the access-control surface. Depending on it for core storage would force us to work *around* its abstraction.
**Worth forking?** **No.** Forking imports its Android legacy-compat baggage and its silent-recreate behavior, and we'd be maintaining a large multi-platform surface (incl. web/desktop) we don't need yet. Re-implement the small, sharp subset we need with the access-control model as a first-class citizen. Study its source (BSD-3 permits) for the Android Keystore edge cases it has already discovered.
**Security implication:** Its silent key-recreation on decrypt failure is a *usability-over-integrity* trade-off we must consciously reject or make explicit.

### 2.3 `biometric_storage` (authpass)

| Attribute | Assessment |
|---|---|
| Maintainer | authpass (Herbert Poul); community |
| License | MIT (verify at pin time) |
| Focus | Store a blob **behind** biometric/device-credential auth; Keystore/Keychain-gated. |

**Does well** — This is the closest existing package to our *core* idea: it creates an OS-gated storage item that **requires** biometric/device-credential auth to read, using `setUserAuthenticationRequired`/`SecAccessControl`. Supports Android, iOS, macOS, and has Linux/Windows attempts.
**Limitations** — Blob-oriented (not a rich policy engine); enrollment-invalidation options exist but aren't uniformly surfaced; smaller maintenance bandwidth than official packages; API is oriented to "one protected file," not multi-secret + rotation + revocation + feature-gating.
**Use as dependency?** No, but **it is the most important package to study/benchmark against** — it validates the approach and has solved real native edge cases. **Worth forking?** Borderline. It is a plausible fork base for the *storage-gated-by-biometric* slice, but its scope is narrower than ours and its abstractions would still need reworking. Recommendation: **study, don't fork** — reimplement with our policy model.
**Security implication:** Good model (true OS gating). Confirm its enrollment-invalidation defaults.

### 2.4 `biometric_signature`

| Attribute | Assessment |
|---|---|
| Focus | Create a **key pair** in Secure Enclave / StrongBox / Windows Hello and produce **biometric-gated signatures**. Android, iOS, macOS, Windows. |
| License | Verify at pin time (MIT/BSD-family typical). |

**Does well** — Implements the *challenge–response signing* pattern that fixes `local_auth`'s "forgeable boolean" weakness: the server sends a nonce, the app signs it with a hardware key that is unusable without biometric auth. Auto-detects Secure Enclave migration. This is the **right primitive for server-side-verifiable biometric auth**.
**Limitations** — Signing-only; no encrypted storage, no policy engine, no rotation/revocation lifecycle. Community-maintained.
**Use as dependency?** No, but **incorporate the pattern** (hardware key-pair + sign-a-challenge) as a first-class capability of our package. **Worth forking?** No — scope mismatch. **Security implication:** Strong; the signing pattern should be part of our public API for "prove biometric auth to a backend."

### 2.5 `cryptography` / `cryptography_plus` (Dart)

| Attribute | Assessment |
|---|---|
| Original | `dint-dev/cryptography` (gohilla), latest ~2.9.0 (Nov 2025) |
| Fork | `cryptography_plus` at `emz-hanauer/dart-cryptography`, actively maintained after upstream stalled |
| License | **Apache-2.0** |
| Native accel | `cryptography_flutter` uses OS crypto on Android/Apple. |

**Does well** — Broad, correct algorithm coverage (AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, HKDF, PBKDF2, HMAC). Good for **pure-Dart envelope/AEAD** operations on data we deliberately keep in Dart.
**Limitations** — Pure-Dart keys live in the Dart heap → **not hardware-backed**, exposed to memory inspection. Two competing lineages (fragmentation risk); pick one deliberately. Apache-2.0 (patent grant) vs BSD elsewhere — mixed but compatible (see §7).
**Use as dependency?** **Optionally**, only for pure-Dart data-layer crypto (e.g. AEAD-wrapping a large payload whose *data-encryption key* is itself sealed by a hardware key). **Never** for keys that must be hardware-resident. **Worth forking?** No. **Security implication:** Anything it touches is software-crypto — treat as such and keep DEKs hardware-sealed.

### 2.6 `pointycastle`

Pure-Dart port of Bouncy Castle. MIT-family license, widely used, stable but low-level. Same role/verdict as `cryptography`: **pure-Dart data-layer only**, never for hardware-backed material. Prefer `cryptography`'s ergonomics unless we need an algorithm only PointyCastle provides.

### 2.7 Comparison summary table

| Package | Core value | HW-backed key mgmt | Biometric-gated crypto | Enrollment invalidation | Rotation/revocation | Policy/app-lock | Maint. | License | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| `local_auth` | Prompt + availability | ✗ | ✗ (boolean only) | ✗ | ✗ | ✗ | ★★★★★ official | BSD-3 | **Depend (detection only)** |
| `flutter_secure_storage` | KV secure storage | partial | coarse | opaque/silent | ✗ | ✗ | ★★★★ | BSD-3 | Study, don't fork |
| `biometric_storage` | Biometric-gated blob | ✓ | ✓ (read gate) | partial | ✗ | ✗ | ★★★ | MIT* | **Benchmark, don't fork** |
| `biometric_signature` | HW key-pair signing | ✓ | ✓ (sign gate) | partial | ✗ | ✗ | ★★★ | * | Adopt pattern |
| `cryptography`/`_plus` | Dart algorithms | ✗ | ✗ | ✗ | n/a | ✗ | ★★★ / ★★★★ | Apache-2.0 | Depend (data layer) |
| `pointycastle` | Dart algorithms | ✗ | ✗ | ✗ | n/a | ✗ | ★★★ | MIT-family | Optional data layer |
| **`biometric_security` (this)** | **Unified security layer** | **✓** | **✓ (usage-gated)** | **✓ explicit** | **✓** | **✓** | — | BSD-3 (proposed) | **Build** |

`*` = confirm exact license at dependency-pin time.

---

## 3. Native Android Security Analysis

### 3.1 The two building blocks

- **AndroidX `BiometricPrompt`** (`androidx.biometric`) — the UI + authentication flow. Backports across API levels and unifies fingerprint/face/iris + device-credential fallback.
- **Android Keystore** — hardware-backed (TEE, or **StrongBox** on a dedicated secure element where present) key container. Keys are generated in and never leave secure hardware; the app receives only a handle.

The security property we want comes from **binding a Keystore key's usability to biometric authentication** via `KeyGenParameterSpec.setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(timeout, type)`. Then a `CryptoObject` wrapping that key is passed to `BiometricPrompt.authenticate(...)`; the cipher/signature only becomes usable **inside the success callback**. This is the real gate — not the boolean.

### 3.2 Biometric strength classes (Class 1/2/3)

| Class | Name | Can gate Keystore keys? | Notes |
|---|---|---|---|
| Class 3 | **`BIOMETRIC_STRONG`** | **Yes** | Only strong biometrics can authorize crypto keys. Required for `CryptoObject`. |
| Class 2 | `BIOMETRIC_WEAK` | **No** | Can show a prompt and return success, but **cannot** unlock a key. UI-only assurance. |
| Class 1 | Convenience | No | e.g. some face unlocks; not usable for auth gating. |

**Consequence:** any *cryptographically enforced* biometric feature must require `BIOMETRIC_STRONG`. On a device whose only enrolled biometric is Class 2, our key-gated flows must degrade to device-credential or refuse — we cannot silently downgrade to a forgeable boolean.

`BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` tells us whether strong biometrics are available/enrolled. We must check this explicitly, not just "canAuthenticate()".

### 3.3 Can we force a specific modality (fingerprint vs face)?

**No.** The app requests a *strength* (`BIOMETRIC_STRONG`/`WEAK`) and optionally allows `DEVICE_CREDENTIAL`. The OS chooses which enrolled modality/sensor to present. There is **no supported API to demand "fingerprint only" or "face only."** You can only:
- require **strong** biometrics (which excludes weak face implementations), and
- inform the user via availability queries what exists.

Any product requirement of "fingerprint only" must be reframed as "strong biometric, with UX copy," and treated as non-enforceable at the OS level.

### 3.4 Device-credential fallback

`setUserAuthenticationParameters(timeout, KeyProperties.AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL)` and/or `setAllowedAuthenticators(... | DEVICE_CREDENTIAL)` let PIN/pattern/password satisfy the gate.

- **`AUTH_DEVICE_CREDENTIAL` keys are *not* invalidated by biometric enrollment changes** (there is no biometric set bound to them), which is more stable but weaker (a shoulder-surfed PIN unlocks them).
- Mixing `AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL` gives resilience but means "biometric" is no longer strictly required. This must be a **per-policy, explicit choice** in our API, never a hidden default.

### 3.5 Key invalidation & enrollment changes — the crux

- A key created with `setUserAuthenticationRequired(true)` and biometric auth type is, **by default, invalidated when a new biometric is enrolled** (or all removed). Using it afterward throws `KeyPermanentlyInvalidatedException`.
- `setInvalidatedByBiometricEnrollment(false)` opts out — new enrollments do **not** invalidate the key. This trades security (a coerced new fingerprint could unlock old secrets) for stability.
- **Time-bound auth** (`setUserAuthenticationValidityDurationSeconds`, deprecated API 30 → replaced by the `timeout` arg of `setUserAuthenticationParameters`) allows the key to be used for N seconds after any device auth **without** a `CryptoObject`. Timeout `0`/`-1` means **per-use** auth with a `CryptoObject` — the strongest binding.

**Design stance:** default to **per-use, `CryptoObject`-bound, invalidate-on-enrollment** keys for high-value secrets, and expose the weaker options as explicit, documented policy levels. Detect `KeyPermanentlyInvalidatedException` and surface a well-defined "re-enroll / re-provision" event rather than silently regenerating (which is what `flutter_secure_storage` did and which silently drops data).

### 3.6 Hardware backing, StrongBox, attestation

- `KeyInfo.isInsideSecureHardware()` (older) / `getSecurityLevel()` reports whether the key is TEE/StrongBox-backed vs software.
- `setIsStrongBoxBacked(true)` requests the discrete secure element; **not all devices have it** → must catch `StrongBoxUnavailableException` and fall back to TEE.
- **Key attestation** (`setAttestationChallenge`) yields an X.509 chain provable to a backend that the key is hardware-backed and biometric-gated. This is the gold standard for server-verifiable enrollment and should be an optional capability.

### 3.7 Rooted-device reality

Keystore private key material generally remains protected by the TEE/StrongBox even on a rooted device (extraction requires hardware compromise). **But** root enables **hooking the app process** (Frida) to bypass `local_auth`-style boolean checks and to abuse an *already-unlocked* time-bound key. Mitigations: prefer per-use `CryptoObject` binding (nothing to abuse outside the callback), use signing/attestation for backend-verifiable auth, and treat root/Play-Integrity signals as risk inputs — never as a hard guarantee.

### 3.8 App upgrades, migration, multiple secrets, rotation

- **App upgrade:** Keystore keys survive app updates (same package + signing key). Data-at-rest survives if the key survives. Risk is code paths that regenerate keys on version bumps.
- **Backup/restore & device transfer:** Keystore keys are **non-exportable and device-bound** — they do **not** transfer to a new device. Secrets sealed by them are unrecoverable off-device by design → our model must support **re-provisioning** and treat server as source of truth for anything recoverable.
- **Multiple secrets:** either one KEK (key-encryption-key) in Keystore wrapping many DEKs (envelope model, fewer Keystore entries, easy bulk revocation) or one Keystore key per secret (finer-grained gating/invalidation). We should support **envelope-by-default** with optional per-secret keys for high-value items.
- **Key rotation:** generate new key with new alias, re-encrypt DEKs, delete old alias. Aliasing scheme + versioned metadata is required.

---

## 4. Native iOS Security Analysis

### 4.1 The building blocks

- **LocalAuthentication (`LAContext`, `LAPolicy`)** — presents Face ID / Touch ID, evaluates a policy, returns success/typed error. Like `local_auth`, this alone is a **boolean** and is bypassable on a jailbroken/hooked device.
- **Keychain Services** — encrypted item store; items carry `kSecAttrAccessible` (when readable relative to device unlock) and optionally a `SecAccessControl`.
- **`SecAccessControl`** — the object that **binds an item/key's accessibility to biometric/passcode requirements** (`.biometryCurrentSet`, `.biometryAny`, `.userPresence`, `.devicePasscode`, `.and`/`.or` combinations, `.applicationPassword`).
- **Secure Enclave** — coprocessor generating/holding **P-256 (secp256r1) EC keys** (`kSecAttrTokenIDSecureEnclave`) whose private key never leaves hardware; you get signing/ECDH via handles only.

The real gate on iOS is a **Secure Enclave key (or Keychain item) whose `SecAccessControl` requires biometrics** — usage is impossible without a successful biometric evaluation performed by the OS. That is the property to build on, not `LAContext.evaluatePolicy`'s boolean.

### 4.2 Can we force Face ID vs Touch ID?

**No.** iOS exposes `LAContext.biometryType` (`.faceID` / `.touchID` / `.opticID` / `.none`) **for informational/UX purposes only**. The policy you evaluate is `deviceOwnerAuthenticationWithBiometrics` (biometrics) or `deviceOwnerAuthentication` (biometrics-or-passcode). **You cannot demand a specific modality** — the device only *has* one biometric family, and the OS decides. "Force Face ID" is not expressible. We surface `biometryType` for UI only and document that enforcement is impossible.

### 4.3 `biometryCurrentSet` vs `biometryAny` — enrollment changes

This is iOS's analogue to Android's `setInvalidatedByBiometricEnrollment`:

| Flag | Behavior on enrollment change | Security | Use when |
|---|---|---|---|
| **`.biometryCurrentSet`** | Item/key becomes **permanently inaccessible** if fingerprints/face are **added or removed** (or, historically, passcode change effects). Binds to the *current* biometric set. | **Stronger** — a coerced new enrollment can't unlock old secrets. | High-value secrets; default for sensitive items. |
| **`.biometryAny`** | Survives enrollment additions; only invalidated if biometrics fully disabled. | Weaker — new enrollment can unlock. | Convenience, lower-value. |

**Design stance:** default `.biometryCurrentSet` for protected secrets; expose `.biometryAny` as an explicit, documented lower-security policy. Detect the "item now inaccessible" error (`errSecAuthFailed`/decode failure) and raise an explicit re-provision event — never silently recreate.

### 4.4 Secure Enclave — capabilities & limitations

**Can:** generate/store non-exportable **P-256** keys; ECDSA signing and ECDH key agreement; gate usage behind `SecAccessControl` (biometrics/passcode); attest indirectly via the signing pattern.

**Cannot / limits:**
- **Only EC P-256.** No RSA, no AES *inside* the Enclave, no arbitrary key import. For symmetric/bulk encryption you do **envelope encryption**: derive/agree a symmetric key via the Enclave key, encrypt data with AES-GCM/ChaCha in software. The Enclave protects the *key-agreement/wrapping key*, not the bulk cipher.
- **Not exportable, device-bound** — no backup/transfer; new device ⇒ new key ⇒ re-provision.
- **Simulator caveats** — Secure Enclave behavior can't be fully validated on simulator; requires real hardware. Some macOS/iOS simulator paths silently differ.
- **Access-control + Enclave interaction subtlety:** when a key is Secure-Enclave-resident, some access-control/`LAContext` interactions behave differently (e.g. auth may or may not be prompted depending on flags and cached `LAContext`), a known source of confusion — must be validated per-flag on-device.

### 4.5 Keychain accessibility & data lifecycle

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` / `...AfterFirstUnlockThisDeviceOnly` — `ThisDeviceOnly` variants are **excluded from iCloud/iTunes backup and device migration**, which is what we want for hardware-bound secrets. Non-`ThisDeviceOnly` items can migrate (usually undesirable for our threat model).
- Keychain items **persist across app uninstall/reinstall** by default (unlike Android) unless deliberately cleared — a footgun for "revocation" semantics; we must clear on provisioning/revocation explicitly.
- **Access groups / keychain-sharing entitlement** enable multi-app/extension sharing; out of scope initially but affects future design.

### 4.6 Jailbreak reality

Enclave-held private keys stay protected even on jailbroken devices (extraction needs hardware attack). But jailbreak enables **process hooking** to bypass `LAContext` booleans and abuse cached `LAContext` reuse. Mitigations mirror Android: prefer **per-operation** access control (fresh `LAContext`, `.biometryCurrentSet`), use the **sign-a-challenge** pattern for backend-verifiable auth, and treat jailbreak detection as a risk signal, not a guarantee.

### 4.7 App upgrade / migration / multiple secrets / rotation (iOS)

- **Upgrade:** Keychain + Enclave keys survive app updates.
- **Migration to new device:** Enclave keys don't transfer; `ThisDeviceOnly` items don't restore ⇒ re-provision path mandatory.
- **Multiple secrets:** one Enclave key as KEK wrapping many DEKs (envelope), or per-secret access-control items. Same trade-off as Android.
- **Rotation:** create new Enclave key + re-wrap DEKs + delete old key/item; version metadata required.

---

## 5. Platform Capability Matrix

Legend: ✅ supported/enforceable · ⚠️ partial / informational only / caveats · ❌ not possible.

| Capability | Android | iOS | Notes / future desktop |
|---|---|---|---|
| Detect biometric hardware present | ✅ | ✅ | `BiometricManager` / `LAContext.canEvaluatePolicy` |
| Detect biometric **enrolled** | ✅ | ✅ | Distinct from "hardware present" |
| Detect biometric **strength** | ✅ (Class 1/2/3) | ⚠️ (type only, no strength taxonomy) | Android strength is enforceable; iOS is not |
| Report modality (face/finger/iris) | ⚠️ informational | ⚠️ informational (`biometryType`) | UX only |
| **Force a specific modality** (Face vs Finger) | ❌ | ❌ | Not expressible on either OS |
| Require **strong** biometric to gate a key | ✅ (`BIOMETRIC_STRONG`) | ⚠️ (biometrics gate exists; no "strong" tier) | iOS biometrics ≈ strong by default |
| Hardware-backed key storage | ✅ TEE / ⚠️ StrongBox (device-dependent) | ✅ Secure Enclave (P-256 only) | |
| **Usage-gated** key (unusable without auth) | ✅ (`CryptoObject`) | ✅ (`SecAccessControl`) | The real security boundary |
| Symmetric keys in secure HW | ✅ (AES in Keystore) | ❌ (Enclave = EC only → envelope) | iOS needs software AEAD wrapping |
| RSA in secure HW | ✅ (Keystore RSA) | ❌ (Enclave = P-256 EC only) | |
| Device-credential fallback | ✅ (`DEVICE_CREDENTIAL`) | ✅ (`deviceOwnerAuthentication` / `.devicePasscode`) | Weakens "biometric required" |
| Invalidate key on **new enrollment** | ✅ default; opt-out via `setInvalidatedByBiometricEnrollment(false)` | ✅ via `.biometryCurrentSet` (vs `.biometryAny`) | Semantics differ; must normalize |
| Per-use vs time-window auth | ✅ (`timeout` param) | ⚠️ (per-`LAContext`; reuse window via context) | |
| Key attestation to backend | ✅ (X.509 attestation) | ⚠️ (via signing pattern; App Attest separate) | |
| Sign server challenge with HW key | ✅ | ✅ | Backend-verifiable auth (beats boolean) |
| Secrets survive app upgrade | ✅ | ✅ | If key not regenerated |
| Secrets survive uninstall | ❌ (Keystore cleared) | ⚠️ (Keychain persists unless cleared) | Opposite defaults — normalize! |
| Secrets transfer to new device | ❌ | ❌ (`ThisDeviceOnly`/Enclave) | Re-provision required |
| Key rotation | ✅ (alias scheme) | ✅ (new Enclave key + rewrap) | Our layer must orchestrate |
| Revocation (make secret unusable) | ✅ (delete key/alias) | ✅ (delete key/item) | Must be explicit, esp. iOS uninstall persistence |
| Detect rooted/jailbroken | ⚠️ (Play Integrity/heuristics) | ⚠️ (heuristics) | Risk signal, not guarantee |

**Two normalization hazards to design around explicitly:**
1. **Uninstall persistence is opposite** (Android clears, iOS keeps). Our "revoke/reset" must behave identically to the developer.
2. **Enrollment-invalidation is opt-out on Android but opt-in-flag on iOS.** Our policy enum must map cleanly to both.

---

## 6. Security Risks

### 6.1 Design-level risks (things developers get wrong that our API must prevent)

| Risk | Description | Our mitigation |
|---|---|---|
| **Boolean-as-authorization** | Treating `local_auth`/`LAContext` success as a security gate; forgeable via hooking. | Make **key-usage-gated** operations the primary API; the boolean flow is labeled "presence check, non-cryptographic." |
| **Silent key regeneration → data loss** | On decrypt failure/invalidation, silently recreating the key drops all prior secrets (fs_storage precedent). | **Never** silently regenerate. Emit typed `KeyInvalidated`/`ReprovisionRequired` events; caller decides. |
| **Weak-biometric downgrade** | Falling back to Class 2 / non-strong when strong unavailable. | Enforce `BIOMETRIC_STRONG`; refuse or require device-credential explicitly per policy. |
| **Enrollment-change confusion** | Not accounting for coerced-new-fingerprint attack. | Default to `biometryCurrentSet` / invalidate-on-enrollment for high-value secrets. |
| **Assuming modality enforcement** | Building UX/security on "Face ID only." | Document impossibility; `biometryType` is UX-only. |
| **DEK exposure in Dart** | Passing hardware-sealed keys through the Dart heap. | Hardware keys never cross the platform channel; only ciphertext/handles do. |
| **Uninstall/migration assumptions** | Expecting secrets to survive/transfer (or expecting them gone). | Normalize revocation; document non-transferability; server = source of truth for recoverable data. |

### 6.2 Platform/threat risks

- **Rooted/jailbroken devices:** process hooking bypasses booleans and can abuse cached auth windows. Mitigate with per-use `CryptoObject`/fresh `LAContext`, signing/attestation, integrity signals.
- **StrongBox absence / TEE-only:** not all Android devices have StrongBox; must degrade gracefully and report actual security level.
- **Secure Enclave EC-only:** no symmetric HW crypto on iOS → envelope encryption is mandatory; the software AEAD step is a (small, well-understood) exposure window.
- **Simulator/test gaps:** biometrics + Enclave can't be fully validated on simulators/emulators → mandate device-matrix testing in CI where possible.
- **Backup/restore & cloud sync:** wrong `kSecAttrAccessible` can leak secrets into iCloud backups; always `ThisDeviceOnly` for hardware-bound secrets.
- **Time-window keys:** a non-per-use key unlocked once can be abused within its validity window by a hooked process.

### 6.3 Supply-chain / dependency risk

- Fewer, well-scoped dependencies. Each added crypto/storage dependency is attack surface. Prefer official (`local_auth`) and widely-audited (`cryptography`, `pointycastle`) where used at all; pin versions and review changelogs for silent security-relevant behavior changes.

---

## 7. Licensing Analysis

| Component | License | Compatibility with a BSD-3 plugin | Notes |
|---|---|---|---|
| `local_auth` (+ platform pkgs) | BSD-3-Clause | ✅ Ideal | Official Flutter; permissive. |
| `flutter_secure_storage` | BSD-3-Clause | ✅ (if we depended) — but we're not | Study source freely under BSD terms; attribute if code is reused. |
| `biometric_storage` | MIT* | ✅ | Verify at pin time. |
| `biometric_signature` | * (verify) | likely ✅ | Confirm before adopting any code. |
| `cryptography` / `cryptography_plus` | Apache-2.0 | ✅ (compatible; note patent grant + NOTICE handling) | Apache-2.0 is more restrictive than BSD in attribution/patent clauses but fully usable; keep NOTICE if bundling. |
| `pointycastle` | MIT-derived (Bouncy Castle-style) | ✅ | Permissive. |

**Recommended license for `biometric_security`: BSD-3-Clause** — matches the Flutter ecosystem norm (`local_auth`, `flutter_secure_storage`), maximizes adoption, and is compatible with all dependencies above. **Apache-2.0** is a reasonable alternative if we want an explicit patent grant (relevant for a security/crypto package); it remains compatible with our BSD/MIT/Apache dependency set. **Avoid** GPL/LGPL dependencies entirely (none of the above are).

**Practical rules:**
- If we copy/adapt any BSD/MIT/Apache code (e.g. an Android Keystore edge-case handler learned from `flutter_secure_storage`), reproduce the required copyright/notice.
- Keep a `THIRD_PARTY_LICENSES` file once dependencies are pinned.
- Re-verify each non-official package's license at the exact pinned version before shipping.

---

## 8. Recommended Architecture

### 8.1 Federated plugin layout (mirrors `local_auth`/`flutter_secure_storage`)

```
biometric_security/                    # app-facing Dart API (the only thing most users import)
  └─ depends on ↓
biometric_security_platform_interface/ # abstract PlatformInterface + shared models/enums/exceptions
  ├─ biometric_security_android/       # Kotlin: BiometricPrompt + Keystore + CryptoObject
  └─ biometric_security_darwin/        # Swift: LAContext + Keychain + SecAccessControl + Secure Enclave (iOS+macOS)
        (future) _windows / _linux
```

Rationale: the federated model lets us add desktop platforms without touching the app-facing API, matches ecosystem conventions, and isolates the risky native code behind a stable Dart contract. `darwin` unifies iOS+macOS (shared LocalAuthentication/Keychain APIs), easing the future macOS target.

### 8.2 Layered internal design

```
┌──────────────────────────────────────────────────────────────┐
│  Public Dart API (biometric_security)                          │
│  - BiometricSecurity facade                                    │
│  - Use-case modules: AppLock, ProtectedValue, ProtectedKey,    │
│    ChallengeSigner, SecureVault                                │
├──────────────────────────────────────────────────────────────┤
│  Policy engine (Dart, shared)                                  │
│  - SecurityPolicy: strength, deviceCredentialFallback,         │
│    invalidateOnEnrollment, authValidity (perUse|window),       │
│    requireStrongBox/Enclave, accessibility                     │
│  - Normalizes Android/iOS differences into ONE model           │
├──────────────────────────────────────────────────────────────┤
│  Platform interface (method/EventChannel contract)             │
│  - Only ciphertext, handles, metadata cross the boundary       │
│  - Typed results & error taxonomy (no silent recovery)         │
├───────────────────────────────┬──────────────────────────────┤
│  Android native (Kotlin)       │  Darwin native (Swift)        │
│  BiometricPrompt + CryptoObject│  LAContext + SecAccessControl │
│  Keystore (AES/EC), StrongBox, │  Keychain items, Secure       │
│  attestation, invalidation     │  Enclave P-256, biometry set  │
└───────────────────────────────┴──────────────────────────────┘
```

### 8.3 Core model: envelope encryption + hardware-sealed KEK

- Each protected secret = **DEK** (data encryption key) encrypting the payload via AES-GCM/ChaCha20-Poly1305.
- The **DEK is sealed by a hardware KEK**:
  - Android: AES or EC KEK in Keystore, usage-gated by `BiometricPrompt`+`CryptoObject`.
  - iOS: P-256 Enclave key; DEK wrapped via ECIES/ECDH-derived key (software AEAD), usage-gated by `SecAccessControl`.
- Metadata (versioned) stored alongside: key alias, policy, KDF params, security level actually achieved (TEE/StrongBox/Enclave/software), created/rotated timestamps.
- Enables: multiple secrets (many DEKs, one/few KEKs), **rotation** (rewrap DEKs under new KEK), **revocation** (delete KEK ⇒ all DEKs dead, or delete individual DEK), and **enrollment invalidation** handled at the KEK.

### 8.4 Public API surface (illustrative — not final, no implementation)

- `BiometricSecurity.capabilities()` → availability, enrolled, strength, modality (informational), StrongBox/Enclave presence, actual security level.
- `SecurityPolicy` value object — the single knob set mapping to both platforms.
- **App-lock use case:** `AppLock.authenticate(policy)` → cryptographically verified session (backed by a per-use key op, not a bare boolean).
- **Protected value:** `ProtectedValue.write/read(key, bytes, policy)` — biometric-gated encrypted storage (our "biometric-protected data").
- **Protected key / signer:** `ChallengeSigner.sign(challenge, policy)` — hardware key-pair, backend-verifiable auth.
- **Lifecycle:** `rotateKey`, `revoke(key)`, `revokeAll`, `enableProtection/disableProtection`, `onKeyInvalidated` event stream (`ReprovisionRequired`).
- **Feature-level protection:** policy-tagged gates the app can attach to features.

### 8.5 Error taxonomy (explicit, no silent recovery)

`Unavailable`, `NotEnrolled`, `StrengthInsufficient`, `UserCanceled`, `LockedOut`/`PermanentlyLockedOut`, `KeyInvalidated` (enrollment changed), `ReprovisionRequired`, `HardwareUnavailable` (StrongBox/Enclave), `PolicyUnsupported`, `IntegrityRisk` (root/jailbreak signal). Every one is a first-class, documented outcome the caller must handle.

---

## 9. Recommended Dependencies

| Dependency | Role | Required? | Justification |
|---|---|---|---|
| `plugin_platform_interface` | Base class for the platform interface | Yes | Standard federated-plugin hygiene. |
| **AndroidX `androidx.biometric`** (native) | BiometricPrompt | Yes (Android) | Canonical Android biometric UI/flow. |
| Android Keystore (platform) | HW key store | Yes (Android) | No dependency; platform API. |
| iOS **LocalAuthentication / Security** frameworks | LAContext, Keychain, SecAccessControl, Secure Enclave | Yes (iOS) | Platform frameworks; no third-party dep. |
| `local_auth` | Availability/strength/enrolled **detection only** | **Optional/initial** | Official, BSD-3. Use to bootstrap detection; may be dropped once native probes exist. |
| `cryptography` **or** `cryptography_plus` | Pure-Dart AEAD/HKDF for the **data layer only** | Optional | Only for software-side envelope ops; pick one lineage deliberately. Apache-2.0. |
| `pointycastle` | Alt pure-Dart crypto | Optional/last-resort | Only if an algorithm is missing from the above. |

**Explicitly NOT recommended as core dependencies:** `flutter_secure_storage` (abstraction mismatch — study, don't depend), `biometric_storage`/`biometric_signature` (benchmark/adopt-pattern, don't depend). No hardware-key material ever passes through any Dart-side crypto dependency.

---

## 10. Fork vs New Implementation Decision

### 10.1 Options considered

**A. New plugin from scratch.** Full control over the security model, access-control surface, invalidation semantics, and error taxonomy. Highest effort; must re-discover native edge cases. Best correctness ceiling.

**B. Wrap existing packages** (`local_auth` + `flutter_secure_storage` + glue). Fastest to a demo. But the *core value* (usage-gated hardware keys, explicit invalidation, rotation/revocation) is exactly what those packages **do not expose**. You end up fighting their abstractions and inheriting `flutter_secure_storage`'s silent-recreate behavior. Ceiling is too low for a "production-grade security layer."

**C. Fork an existing package.** Candidates: `biometric_storage` (closest scope) or `flutter_secure_storage` (biggest platform breadth). A fork inherits maintenance burden, legacy-compat baggage, and design decisions we'd want to change (silent recreation, coarse gating, no policy engine). Diverging quickly makes upstream merges worthless. No candidate's architecture matches our policy-engine + rotation/revocation + normalized-invalidation goals closely enough to justify carrying its history.

**D. Combine.** Build the native security core new (A), *depend on* the official `local_auth` for detection and permissive Dart crypto libs for the data layer (B-style, narrowly), and *study/benchmark* `biometric_storage`/`biometric_signature`/`flutter_secure_storage` for native edge cases and patterns (learn from, don't fork).

### 10.2 Decision

> **Choose D, weighted toward A.** Build a new federated plugin owning the biometric-binding + key-lifecycle core. Depend on `local_auth` (detection) and a pure-Dart crypto lib (data layer) as thin, replaceable helpers. Do **not** fork.

### 10.3 Why not fork (summary)

- Our differentiator is a **policy engine + hardware-usage-gating + explicit lifecycle** that no existing package is architected around; a fork would be ~rewritten anyway.
- Forks inherit **security-relevant legacy behaviors** we specifically want to reject (silent key regeneration, coarse biometric gating).
- Official/permissive licensing means we can freely **study** source for hard-won native edge cases without taking on fork maintenance.
- Multi-platform breadth we don't yet need (web/desktop in `flutter_secure_storage`) is fork liability, not asset.

---

## 11. Open Questions

1. **Product enforcement expectations.** Are any stakeholders assuming "Face ID only" / "fingerprint only"? This is **impossible** on both OSes — confirm the requirement is reframed as "strong biometric + UX copy" before design freeze.
2. **Default invalidation posture.** Ship secure-by-default (`biometryCurrentSet` / invalidate-on-enrollment, per-use) even though it causes more re-provisioning? Recommended yes, but confirm the UX tolerance.
3. **Device-credential fallback default.** Off by default (biometric-strict) or on (resilience)? Recommend off-by-default, opt-in per policy.
4. **Server-side story.** Is there a backend that can consume attestation/challenge-signatures? If yes, prioritize the `ChallengeSigner` capability; if no, the value of hardware binding is local-only and should be communicated honestly.
5. **Recoverability.** For which secrets is on-device-only, non-transferable, non-recoverable acceptable? Anything recoverable needs a server escrow story outside this package's scope.
6. **Minimum OS/API baseline.** Android `minSdk` (BiometricPrompt/StrongBox/attestation availability varies), iOS minimum version — pin these before native work.
7. **StrongBox/Enclave requirement policy.** Hard-require secure hardware (refuse on TEE-only/no-Enclave) or degrade with reported security level? Recommend degrade-and-report, hard-require opt-in.
8. **`cryptography` vs `cryptography_plus`.** Choose one lineage; assess maintenance trajectory at pin time.
9. **macOS timeline.** `darwin` shared code assumes near-term macOS; confirm so we structure the Swift package accordingly from day one.
10. **Testing matrix.** Which physical devices/OS versions in CI? Biometrics/Enclave can't be validated on simulators — budget for a device lab or cloud device farm.
11. **Integrity signals.** Do we integrate Play Integrity / DeviceCheck-App Attest, or leave root/jailbreak detection to the host app?
12. **Multi-secret keying strategy default.** Envelope (shared KEK) vs per-secret Keystore/Enclave keys as the default — confirm the trade-off (bulk revocation & fewer entries vs finest-grained invalidation).

---

## 12. Recommended Next Steps

1. **Resolve the blocking open questions** (§11 items 1–3, 6, 7) with stakeholders — especially the "no forced modality" reality and the default security posture. These change the API shape.
2. **Write a short design doc / ADR** freezing: the federated package layout (§8.1), the `SecurityPolicy` model that normalizes Android/iOS invalidation & fallback, and the explicit error taxonomy (§8.5).
3. **Build two native spikes** (throwaway, on real hardware) to de-risk the hardest seams **before** committing the public API:
   - Android: Keystore key with `setUserAuthenticationParameters` + `CryptoObject`, exercise `KeyPermanentlyInvalidatedException` on new enrollment, StrongBox fallback, attestation chain.
   - iOS: Secure Enclave P-256 key + `SecAccessControl(.biometryCurrentSet)`, exercise enrollment-change invalidation, envelope-wrap a DEK, `ThisDeviceOnly` accessibility.
4. **Define the platform-interface contract** (method + event channels) ensuring **no hardware key material crosses the boundary** — only ciphertext, handles, metadata, and typed events.
5. **Prototype the app-facing facade** for one end-to-end use case (`ProtectedValue.write/read` with biometric gating) to validate ergonomics.
6. **Stand up the device test matrix / CI plan** early — this package's correctness is only provable on real devices.
7. **Pin dependencies & verify licenses** at the exact versions; create `THIRD_PARTY_LICENSES`.
8. **Only then** begin production implementation, platform interface first, Android and Darwin in parallel.

---

## Concise Recommendation

**Build a new federated Flutter plugin (`biometric_security`) whose core is native — Android `BiometricPrompt`+Keystore with `CryptoObject` usage-gating, and iOS `LAContext`+Keychain+`SecAccessControl`+Secure Enclave — organized around a policy engine that normalizes the platforms' divergent enrollment-invalidation, strength, and fallback semantics into one model.** Do **not** fork any existing package: `flutter_secure_storage` and `biometric_storage` are worth studying for native edge cases but their abstractions and legacy behaviors (notably silent key regeneration and coarse gating) are the wrong foundation. **Depend narrowly** on the official `local_auth` (BSD-3) for availability/strength detection and on a permissive pure-Dart crypto library (`cryptography`/`pointycastle`, Apache-2.0/MIT) for the software data layer only — never for hardware-backed keys. License the package **BSD-3-Clause** to match the ecosystem.

The package's real value is making the **cryptographic binding** (a key that is physically unusable without a successful biometric authentication) the primary, default API — replacing the industry-standard-but-forgeable "trust the boolean" pattern — and handling the genuinely hard lifecycle: enrollment-change invalidation, key rotation, revocation, envelope-based multi-secret storage, and honest, explicit error handling that **never silently destroys stored secrets**.

Two hard truths to communicate up front: (1) **neither platform lets an app force a specific biometric modality** (Face ID vs fingerprint) — only strength (Android) and UX framing; (2) **hardware-backed keys are device-bound and non-transferable**, so a re-provisioning path and (for recoverable data) a server source-of-truth are mandatory, not optional.

**Next:** resolve the blocking product questions (§11), freeze the `SecurityPolicy` + error-taxonomy design in an ADR, and run two throwaway on-device native spikes to de-risk invalidation/StrongBox/Enclave **before** writing any production code.

---

## Appendix A — Sources

- local_auth — https://pub.dev/packages/local_auth · changelog https://pub.dev/packages/local_auth/changelog · https://github.com/flutter/packages/tree/main/packages/local_auth
- local_auth_android changelog — https://pub.dev/packages/local_auth_android/changelog
- flutter_secure_storage — https://pub.dev/packages/flutter_secure_storage · https://github.com/juliansteenbakker/flutter_secure_storage · license https://pub.dev/packages/flutter_secure_storage/license
- biometric_storage — https://github.com/authpass/biometric_storage
- biometric_signature — https://pub.dev/packages/biometric_signature
- cryptography (Dart) — https://pub.dev/packages/cryptography · fork https://github.com/emz-hanauer/dart-cryptography · cryptography_plus https://pub.dev/documentation/cryptography_plus/latest/
- Flutter Gems (crypto/biometric category surveys) — https://fluttergems.dev/biometric-local-auth/ · https://fluttergems.dev/cryptography-security-permissions/
- Android Keystore system — https://developer.android.com/privacy-and-security/keystore
- Android BiometricPrompt / biometric auth guide — https://developer.android.com/identity/sign-in/biometric-auth
- OWASP MASTG (Android biometrics knowledge) — https://github.com/OWASP/mastg/issues/3748
- Apple — LAPolicy.deviceOwnerAuthenticationWithBiometrics — https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics
- Biometry-protected Keychain entries (biometryCurrentSet vs biometryAny) — https://medium.com/@alx.gridnev/biometry-protected-entries-in-ios-keychain-6125e130e0d5
- Keychain / Biometrics / Secure Enclave overview — https://medium.com/@gauravharkhani01/app-security-in-swift-keychain-biometrics-secure-enclave-69359b4cffba
- Apple Developer Forums — Secure Enclave key generation & access-control interactions — https://developer.apple.com/forums/thread/748611 · https://developer.apple.com/forums/thread/658821
- objection issue — biometryCurrentSet vs biometryAny observed behavior — https://github.com/sensepost/objection/issues/495
