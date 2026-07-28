# Use-Case Audit — `biometric_security`

> Question: can the **current** implementation support the three application flows
> (enable biometric login + store PIN · biometric login + retrieve PIN · normal
> authenticate) **without redesign**?
> Method: inspected `lib/`, the platform interface, the Android Kotlin, and the
> iOS Swift implementations against each flow. No assumptions — behavior below is
> read from the actual code.
> Date: 2026-07-24.

## Verdict at a glance

| Use case | Status |
|---|---|
| **UC1 — Enable biometric login + securely store PIN** | ✅ **Fully supported** (with a documented platform prompt-timing difference) |
| **UC2 — Biometric login + retrieve PIN + invalidation handling** | ✅ **Fully supported** |
| **UC3 — Normal authentication (no PIN)** | ✅ **Fully supported** |

**No package code changes are required to implement these three flows.** The
work is in the example app. One genuine capability is *absent* but *not required*
(a non-prompting standalone key-validity probe — see §"Gap"). I did **not** add
speculative APIs.

---

## The exact APIs to use

| Need | API | Prompts? | Notes |
|---|---|---|---|
| Is biometric login enabled? | `contains(key)` | **No** | Checks ciphertext presence only. Persists across restarts. |
| Availability / enrollment / strength | `getAvailability()` → `BiometricAvailability` | No | `status`, `strength`, `canAuthenticate`, `enrolledModalities`. |
| Securely store the PIN | `write(key, value, policy: SecurityPolicy.strong(), reason)` | Android: **yes**; iOS: **no** | Stores under a biometric-bound key (see §UC1). |
| Retrieve the PIN | `read(key, reason)` | Yes (only if the key is still valid) | Returns the PIN; throws `KeyInvalidatedException` if invalidated — **before** prompting. |
| Normal authentication | `authenticate(reason)` → `AuthSession` | Yes | Independent of storage; returns a session, not a bare `true`. |
| Disable / revoke login | `revoke(key)` | No | Destroys the key + ciphertext. |
| Recover after invalidation | `resetInvalidated()` then `write(...)` (or `revoke` then `write`) | Android write prompts | Fresh key; old PIN unrecoverable. |
| Security status snapshot | `getSecurityStatus()` → `SecurityStatus` | No | `achievableSecurityLevel`, `reprovisionRequired`, `integrityRisk`. |

---

## UC1 — Enable biometric login + store PIN — ✅ Fully supported

**App responsibility (correct):** show the PIN sheet, validate `123654` **in the
app** (the package must not know a test PIN), and only then store it.

**Package:** `write(SecretKey('...'), pin, policy: SecurityPolicy.strong())`
stores the PIN under envelope encryption whose **data-encryption key lives in a
biometric-gated Keystore/Keychain entry**. The PIN is **never** placed in plain
storage. Confirmed:
- The blob (ciphertext) is written to app-private prefs/Keychain; it contains no
  plaintext and no key material.
- The DEK is stored gated (Android: `setUserAuthenticationRequired` Keystore key;
  iOS: `SecAccessControl` `.biometryCurrentSet`).

**Platform prompt-timing difference (must be honored, not hidden):**
- **Android** — a gated `write` **shows the biometric prompt** (the DEK is sealed
  inside `BiometricPrompt`'s success callback). So "authenticate → store" happens
  in one call. ✔ matches the requested flow directly.
- **iOS** — adding a gated Keychain item **does not prompt** (`SecItemAdd` never
  authenticates; the gate applies on *read*). So on iOS, `write` alone is silent.
  To make the user "see the biometric prompt during enable" (as the flow shows),
  the app calls `authenticate(reason)` **first on iOS**, then `write`. (Doing this
  on Android too would double-prompt, so the example branches by platform.)

**State the app can determine:** *enabled* = `contains(pinKey)`; *disabled/revoked*
= not present; *invalidated* = present but `read` throws `KeyInvalidatedException`.

## UC2 — Biometric login + retrieve PIN — ✅ Fully supported

The requested flow is: *check enabled → check availability → check key/enrollment
validity → if invalidated, don't retrieve and require re-enable → else prompt and
retrieve.*

**`read()` implements exactly this, in the correct order:**
1. `contains(pinKey)` → is login enabled (no prompt).
2. `getAvailability()` → is biometric usable now.
3. `read(pinKey, reason)`:
   - If the biometric-bound key was invalidated, `read` throws
     `KeyInvalidatedException` **before any prompt is shown**
     (Android: `Cipher.init` throws `KeyPermanentlyInvalidatedException`; iOS: the
     biometric domain-state comparison throws first). → app does **not** retrieve,
     revokes/disables login, asks the user to enable again.
   - If valid, the OS prompt appears, the user authenticates, and the PIN is
     returned to Flutter.
   - If absent, returns `null` → treat as not enabled.

So "check validity, and only if valid prompt-and-retrieve" is a **single, atomic,
TOCTOU-free** operation — no separate probe is needed, and it cannot be raced.

**The package returns the PIN, not `true`.** `read` returns the decrypted bytes
after authentication; `authenticate` (the boolean-ish presence check) is a
different method.

## UC3 — Normal authentication — ✅ Fully supported

`authenticate(reason)` is **independent from storage**: it uses a dedicated auth
key/scope (Android: a gated Keystore key; iOS: a Secure Enclave signing key),
performs a real key operation, and returns an `AuthSession` (with `securityLevel`
and a token) — never touching the stored PIN. It does not read or write any
secret. ✔ clean separation of "prove presence" vs "retrieve protected data".

---

## The eight attention points

| # | Question | Answer |
|---|---|---|
| 1 | `authenticate()` independent from storage? | **Yes** — separate method, separate key/scope, returns `AuthSession`; never reads/writes secrets. |
| 2 | `write()` protects the PIN with biometric auth? | **Yes** — biometric-bound DEK (Keystore/Keychain). Android prompts on write; iOS gates on read. |
| 3 | `read()` retrieves the PIN after authentication? | **Yes** — returns decrypted bytes post-auth; not a boolean. |
| 4 | Enrollment/key invalidation actually detected? | **Yes** — surfaced as `KeyInvalidatedException` from `read`, *before* prompting. Android via `KeyPermanentlyInvalidatedException`; iOS via `evaluatedPolicyDomainState` comparison for `.biometryCurrentSet`. |
| 5 | Login can be disabled/revoked after invalidation? | **Yes** — `revoke(key)` destroys the key + ciphertext; app flips its enabled flag. |
| 6 | App can determine whether login is currently valid? | **Partially, by design** — *enabled* is known without a prompt (`contains`); *validity* is proven by the login `read` itself (which no-prompt-throws if invalid). There is **no separate non-prompting validity probe** (see Gap). Not required for the flows. |
| 7 | Distinguishes authentication from secure data access? | **Yes** — `authenticate()` vs `read()` are distinct operations on distinct keys. |
| 8 | Recovers safely after invalidation? | **Yes** — never silently regenerates or returns plaintext; recovery is explicit (`resetInvalidated`/`revoke` then `write`). |

---

## The one genuine gap (not required, not added)

There is **no standalone, non-prompting API to ask "is the biometric-bound key
still valid?"** without attempting a `read`. The native signals exist internally
(Android `Cipher.init`, iOS domain-state), but are not exposed as a separate
method.

**Why it is not required:** `read()` already performs the validity check first
and only prompts if valid, which is exactly the requested UC2 ordering. A separate
probe would only let the UI display "Key: Valid" *before* a login attempt; the
example instead derives key state from the last login/read and labels it honestly.

**If desired later** (small, non-redesign): a read-only
`Future<ProtectedKeyStatus> protectedKeyStatus(SecretKey)` reusing the existing
native `Cipher.init` / domain-state logic. Deliberately **not** implemented here
to honor "implement only what is required."

---

## Behaviors that must respect platform reality (no faking)

- **Android** invalidates a gated key when a **new** biometric is enrolled
  (`setInvalidatedByBiometricEnrollment(true)`, the default). Behavior on
  *removal* varies by OEM. Detection is reliable at key-use time.
- **iOS** (`.biometryCurrentSet`, default) invalidates on **add or remove**;
  detected via domain-state before prompting.
- A policy of `EnrollmentBinding.persistAcrossEnrollment`
  (Android `setInvalidatedByBiometricEnrollment(false)` / iOS `.biometryAny`)
  **survives** enrollment changes by design — do not expect invalidation there.
- The package **never** silently falls back to insecure storage, silently makes a
  new key and reuses the old PIN, or allows login on an invalidated key.

## Conclusion

All three use cases are **fully supported by the existing public API**. Required
package changes: **none.** The example app will be rebuilt to demonstrate the
three flows, honoring the Android/iOS prompt-timing difference and surfacing the
enrolled/valid/invalidated/revoked states.
