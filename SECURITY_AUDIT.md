# `biometric_security` — Security & Quality Audit

> Reviewer role: independent senior mobile security engineer.
> Stance: adversarial — the implementation is assumed wrong until shown otherwise.
> Date: 2026-07-23 · Commit state: post-storage-layer.
> Verdict: **NOT production-ready.** Safe for controlled pilots after the fixes below; see [§ Production-readiness](#production-readiness-verdict).

---

## Executive summary

The package implements a defensible, hardware-backed design: AES-256-GCM envelope encryption with a per-secret data-encryption key (DEK), the DEK held in the Android Keystore / iOS Keychain and gated by `BiometricPrompt` / `SecAccessControl`, secure-by-default policies, and a typed error model that fails loudly instead of returning plaintext. I found **no critical (confidentiality-breaking) vulnerabilities**: no hardcoded keys, no plaintext key persistence, no nonce reuse, no weak/custom crypto, and the biometric-to-key binding is genuine on both platforms.

I did find **two high-risk defects** — both now **fixed**:
- **H-1** Concurrent writes to the same key could leave a DEK/ciphertext mismatch → an undecryptable secret (integrity/availability, silent data loss).
- **H-2** `requireSecureHardware` was **not enforced**: a software-backed key (Android, no TEE) or the software LocalAuthentication fallback (iOS, no Secure Enclave) was silently accepted — a policy bypass.

Several **medium/low** issues and honest **platform limitations** remain and are documented rather than hidden. The most consequential remaining items: rotation is not crash-atomic (M-2), iOS Keychain data survives reinstall with no first-run purge (M-3), and `authenticate()` on the no-Secure-Enclave fallback is a presence check, not a hardware assertion (M-4). None of these leak secret data; they are integrity, hygiene, or assurance-scope issues.

**This package must not be marketed as "production-ready" until the remaining medium items and the deferred features (real lifecycle events, `signChallenge`, on-device integration tests on rooted/jailbroken hardware) are addressed.** It is honest, well-tested at the unit level, and secure in its core cryptographic design.

---

## Critical findings

**None.** Specifically verified absent:

- **No hardcoded secrets / keys.** The only constant is `AUTH_PROOF` ("biometric_security.auth"), a *public* message signed/encrypted to prove a key op ran — not a secret.
- **No plaintext key persistence.** DEKs are stored encrypted by a hardware key (Android) or in a hardware-gated Keychain item (iOS); the hardware KEK never leaves secure hardware and never crosses the platform channel.
- **No weak or custom cryptography.** AES-256-GCM only, via the audited `cryptography` package.
- **No predictable/ reused nonces.** 96-bit nonces are CSPRNG-generated per encryption; a fresh DEK+nonce per write makes reuse structurally impossible (test: `each write uses a fresh nonce`).
- **No security bypass in biometric binding.** A gated secret's ciphertext is inert without the DEK, and the DEK cannot be obtained without a successful biometric key operation.

---

## High-risk findings (both FIXED)

### H-1 — Concurrent same-key writes could corrupt a secret · **FIXED**
`SecureStorage.write` stored the DEK and then the ciphertext blob in two awaited steps. Two overlapping writes to the *same* key could interleave so the vault held DEK_B while the persisted blob was sealed with DEK_A → every future read throws `CryptographicException` (silent data loss). Gated writes are serialized natively, but `encryptedOnly` writes are not, and the Dart-level window existed regardless.
- **Failure scenario:** two `write(key: 'token', …)` futures awaited together → `read` later throws even though both writes "succeeded".
- **Fix:** a per-key async lock (`_locked`) now serializes all operations on a given key; distinct keys still run concurrently. Regression test: `concurrent writes to the SAME key never corrupt it`.
- **File:** [lib/src/storage/secure_storage.dart](lib/src/storage/secure_storage.dart).

### H-2 — `requireSecureHardware` policy not enforced · **FIXED**
- **Android:** `createKey` handled `StrongBoxUnavailableException` but never checked the *achieved* level. On a device with no TEE, a **software-backed** key was accepted while the doc claimed rejection — a developer relying on `requireSecureHardware` got software keys silently.
- **iOS:** `authenticate()` fell back from Secure Enclave signing to `LAContext.evaluatePolicy` (a bypassable boolean) even when `requireSecureHardware` was set.
- **Fix (Android):** after key creation, if `requireSecureHardware` and `securityLevelOf == software`, the key is deleted and `POLICY_UNSUPPORTED` is thrown. **Fix (iOS):** the software fallback throws `policyUnsupported` when `requireSecureHardware`.
- **Files:** [KeystoreManager.kt](android/src/main/kotlin/com/example/biometric_security/KeystoreManager.kt), [SecureEnclaveAuth.swift](ios/Classes/SecureEnclaveAuth.swift).

---

## Medium-risk findings

### M-1 — App-lock unlock policy not persisted across launches · Remaining
`AppLock` remembers its policy in memory (`_policy`); after a cold start, `unlock()` falls back to the default policy until `enable()` is called again. If an app configured a *weaker* app-lock policy, a restart silently uses the (stronger) default — fail-safe, not fail-open — but it is a behavioral inconsistency. **Recommendation:** persist the app-lock policy. Low exploitability; classified medium for correctness.

### M-2 — Key rotation is not crash-atomic · Remaining (documented)
Because a per-secret DEK occupies a single hardware slot, a process kill between "store new DEK" and "write re-encrypted blob" leaves that one secret undecryptable until the caller retries `write`. It never corrupts or leaks *other* secrets. The earlier code comment claiming crash-safety was **false and has been corrected**. **Recommendation:** versioned DEK slots (write new-versioned DEK + blob, then delete old) for atomic rotation. Tracked, not yet implemented.

### M-3 — iOS Keychain data survives app reinstall (no first-run purge) · Remaining
On iOS, Keychain items (gated DEKs and ciphertext blobs) persist across uninstall/reinstall. A reinstalled app (or one with the same bundle id) inherits prior secrets. Android wipes on uninstall — a **platform-difference footgun**. **Recommendation:** write an install marker to `UserDefaults` (cleared on uninstall) and purge the Keychain namespace on first run when the marker is absent. Architecturally planned (ARCHITECTURE.md §16), not yet implemented.

### M-4 — `authenticate()` fallback is presence-only, and its token is not backend-verifiable · Remaining (documented)
On devices without a Secure Enclave (simulators; effectively no real iPhone since 5S), and on the Android proof path, `authenticate()` proves "a key op ran locally" but returns a token that no server can verify. Callers must check `AuthSession.securityLevel` and must not treat the token as a remote assertion. Real backend-verifiable auth requires `signChallenge`, which is **not yet implemented**. **Recommendation:** implement `signChallenge`; document that `authenticate()` is a local gate.

**Update (auth-key invalidation UX, fixed):** when a biometric-enrollment change invalidates the `authenticate()` key, the failure previously surfaced on iOS as a generic `BiometricAuthFailedException` ("CryptoTokenKit error -3") and, on both platforms, left the dead key in place so every subsequent `authenticate()` kept failing. Now both platforms **map this to a typed `KeyInvalidatedException` and self-heal**: because the auth key protects no stored secret, the invalidated key is deleted and the next `authenticate()` re-provisions with a fresh prompt. iOS `resetInvalidated()` (no scope) also now clears the default auth scope instead of being a no-op. Covered by `test/platform/error_mapping_test.dart`. (The *distinguishing* is best-effort on iOS's signing path per M-5's caveat, but the auth key carries no secret, so a false-positive only costs one extra re-provision prompt.)

### M-5 — `evaluatedPolicyDomainState` is deprecated (iOS 18) · Remaining
The proactive enrollment-change / invalidation detection on iOS relies on `LAContext.evaluatedPolicyDomainState`, which Apple deprecated in iOS 18. It still functions, but a future iOS release may remove it, degrading invalidation detection to the ambiguous `errSecAuthFailed` path. **Recommendation:** track Apple's replacement API; keep `.biometryCurrentSet` (which enforces invalidation at the OS level regardless) as the real guarantee.

### M-6 — Ciphertext blobs may be included in Android auto-backup · Remaining (low impact)
The blob and DEK SharedPreferences files are not excluded from Android auto-backup. Because the hardware keys that decrypt them never leave the device and are not backed up, the exported data is cryptographically inert (AES-256-GCM ciphertext + hardware-encrypted DEK). Still, defense-in-depth argues for exclusion. **Recommendation:** ship `android:fullBackupContent` / `dataExtractionRules` excluding the `bsec.*` prefs, or document `allowBackup=false` for host apps.

---

## Low-risk findings

- **L-1 — DEK lives in process memory, unzeroed.** The DEK and decrypted plaintext are `Uint8List`/`SecretKey` in the Dart (and transiently native) heap and cannot be reliably zeroed (GC, no `mlock`). Inherent to the envelope-with-software-payload model; in-scope only for an attacker who already has process memory access (root/jailbreak). Documented in the threat model (T8).
- **L-2 — DEK crosses the platform channel in plaintext (in-process).** `storeDek`/`loadDek` pass the raw DEK over the `MethodChannel`. This is in-process memory, not IPC, and the *hardware KEK* never crosses (INV-2 holds). Residual memory exposure only.
- **L-3 — Example app logs decrypted values to its on-screen log.** The *example* prints a read PIN for demonstration. Harmless in the demo, but it must not be copied into real apps. **Recommendation:** add a comment warning; never log secrets in the package itself (verified: the package logs nothing).
- **L-4 — Pure-Dart AES-GCM is not guaranteed constant-time.** The base `cryptography` package's Dart AES may have data-dependent timing. Low relevance to this local threat model. **Recommendation:** add `cryptography_flutter` for native-accelerated, constant-time AES on device.
- **L-5 — `authInProgress` guard can stick on a rare synchronous throw.** If prompt *setup* (not evaluation) throws before the callback path on either platform, the single-flight flag could remain set, blocking further prompts until app restart (DoS, not bypass). **Recommendation:** reset the guard in a `finally`/`catch` around prompt setup.

---

## Area-by-area review (the 28 requested areas)

| # | Area | Finding |
|---|---|---|
| 1 | Cryptography | AES-256-GCM only; no custom/weak crypto. ✅ |
| 2 | Key generation | CSPRNG DEK (`Random.secure`); 256-bit Keystore keys. ✅ |
| 3 | Key storage | Hardware Keystore/Keychain; ciphertext-only in prefs/Keychain blobs. ✅ (M-6 defense-in-depth) |
| 4 | Key lifecycle | Create→Protect→Use→Invalidate→Revoke→Destroy implemented. ✅ (M-2 rotation atomicity) |
| 5 | Key invalidation | Loud typed failure; no silent regen (INV-3). ✅ |
| 6 | Biometric binding | Genuine: DEK unusable without a successful key op. ✅ (H-2 fixed) |
| 7 | Enrollment changes | Android `setInvalidatedByBiometricEnrollment`; iOS `.biometryCurrentSet` + domain-state. ✅ (M-5 deprecation) |
| 8 | Authentication policies | Normalized, secure-by-default. ✅ (H-2 fixed) |
| 9 | Android Keystore | Correct GCM/no-padding/256, `CryptoObject` gating, StrongBox fallback. ✅ (H-2 fixed) |
| 10 | iOS Keychain | `SecAccessControl`, `ThisDeviceOnly`. ✅ (M-3 reinstall persistence) |
| 11 | Secure Enclave | P-256 gated signing for `authenticate()`. ✅ (M-4 fallback scope) |
| 12 | Sensitive data handling | No plaintext persistence; loud failures. ✅ (L-1/L-2 memory) |
| 13 | Logging | Package logs nothing sensitive. ✅ (L-3 example only) |
| 14 | Error messages | Generic, typed; no secret leakage. ✅ |
| 15 | Memory handling | No zeroization possible in Dart. ⚠️ L-1 |
| 16 | Data migration | Versioned, non-destructive, newer-version rejected. ✅ |
| 17 | Key rotation | Implemented + tested. ⚠️ M-2 not crash-atomic |
| 18 | Revocation | DEK-destroy makes secret unrecoverable; tested. ✅ |
| 19 | Race conditions | Per-key lock added. ✅ (H-1 fixed) |
| 20 | Concurrent requests | Prompts serialized natively; storage serialized per key. ✅ |
| 21 | App lifecycle | Background cancels prompts. ✅ (M-1 app-lock policy) |
| 22 | Background/foreground | iOS window auth treated as expired; prompts canceled. ✅ |
| 23 | Rooted devices | Hardware keys protected; boolean paths hardened via key-gating. ⚠️ advisory-only integrity signals |
| 24 | Jailbroken devices | Same; SE keys protected; fallback path weaker. ⚠️ M-4 |
| 25 | Package upgrade | Keys/data survive; migration handles schema. ✅ |
| 26 | Reinstallation | Android clears; iOS persists. ⚠️ M-3 |
| 27 | Backup/restore | Hardware keys non-exportable; `ThisDeviceOnly`. ✅ (M-6) |
| 28 | Platform differences | Normalized; residual asymmetries documented. ✅ |

---

## Recommendations (prioritized)

1. **Implement `signChallenge`** for backend-verifiable auth; document `authenticate()` as a local gate (M-4).
2. **iOS first-run purge** via a `UserDefaults` install marker (M-3).
3. **Atomic rotation** via versioned DEK slots (M-2).
4. **Persist app-lock and feature-gate policies** (M-1).
5. **Exclude `bsec.*` from Android backup**; recommend `allowBackup=false` for hosts (M-6).
6. **Add `cryptography_flutter`** for native, constant-time AES (L-4).
7. **On-device integration tests on real + rooted/jailbroken hardware**; nothing here is validated on a physical biometric device yet.
8. **Wire real lifecycle events** (currently the event stream never emits) so apps learn of invalidation proactively.
9. **Harden the single-flight guard** with a `finally` reset (L-5).

---

## Fixed issues

| ID | Severity | Status |
|---|---|---|
| H-1 | High | ✅ Fixed — per-key serialization + regression test |
| H-2 | High | ✅ Fixed — `requireSecureHardware` enforced (Android + iOS) |
| M-2 (doc) | Medium | ✅ Corrected the false "crash-safe" claim in code/docs |

## Remaining issues

| ID | Severity | Status |
|---|---|---|
| M-1 | Medium | Open — app-lock policy not persisted |
| M-2 | Medium | Open — rotation not crash-atomic |
| M-3 | Medium | Open — iOS reinstall inherits secrets |
| M-4 | Medium | Open — presence-only fallback; no `signChallenge` |
| M-5 | Medium | Open — deprecated iOS domain-state API |
| M-6 | Medium | Open — Android backup exclusion |
| L-1…L-5 | Low | Open — memory, in-process DEK, example logging, non-CT AES, guard reset |

## Known limitations (by design or platform)

- **No forced biometric modality** — impossible on both OSes (INV-4).
- **Hardware keys are device-bound** — no migration/restore; reprovisioning required (INV-5).
- **DEK exists in process memory** during operations — cannot be zeroed in Dart.
- **Integrity (root/jailbreak) signals are advisory** — never a hard guarantee.
- **Not validated on physical devices** — Keystore/Enclave biometric flows are covered only by framework-independent unit tests plus compile/build verification. Real-device and rooted/jailbroken testing is outstanding.
- **`signChallenge`, lifecycle events, `enableProtection`/`disableProtection`, `policyOf`** remain unimplemented.

---

## Verification run (this audit)

- `flutter analyze` (plugin + example): **No issues found.**
- `flutter test`: **43/43 passed** (incl. the H-1 concurrent-same-key regression).
- Kotlin unit tests: **4/4 passed**; `compileDebugKotlin` clean (H-2 fix compiled).
- iOS XCTest (iPhone 16 simulator): **5/5 passed**, `** TEST SUCCEEDED **` (H-2 fix compiled).
- Android example APK: **built.** iOS example: **built** (device, `--no-codesign`).

---

## Production-readiness verdict

**Not production-ready — and I will not claim otherwise.**

The cryptographic core is sound and the two high-risk defects are fixed, so the package is suitable for **internal pilots and non-critical data** now. Before it protects real user secrets in production it needs, at minimum: `signChallenge` for server-verifiable auth (M-4), the iOS reinstall purge (M-3), atomic rotation (M-2), and — non-negotiably — **on-device testing on real and rooted/jailbroken hardware**, since none of the biometric/Keystore/Enclave paths have executed on a physical device in this codebase. Until that on-device validation exists, any "production-ready" claim would be dishonest.
