# Changelog

All notable changes to `biometric_security` are documented here. This project
follows [Semantic Versioning](https://semver.org). Pre-1.0 releases are betas:
the public API may still change between minor versions.

## 0.1.14

- Improved pub.dev discoverability: keyword-rich package description and README
  opening (Face ID, Touch ID, fingerprint, Keystore, Keychain, Secure Enclave),
  pub.dev badges, and a "how it compares" table vs `local_auth` /
  `flutter_secure_storage`.

## 0.1.13

- Fixed the `homepage`/`repository`/`issue_tracker` URLs (they pointed at a
  non-existent GitHub account, so the pub.dev "Repository" link 404'd).
- Cleaned up the README status banner.

## 0.1.12

Initial public beta. Every implemented flow is validated on physical Android and
iOS devices; a few APIs remain stubs (see the "Platform limitations" section of
the README). As a pre-1.0 release, the public API may still change.

### Added

- **Availability detection** — `getAvailability()` reports supported vs enrolled
  modalities, biometric strength, secure-hardware presence, and what the device
  can actually enforce (`EnforceableGuarantees`).
- **Biometric authentication** — `authenticate()` backed by a real hardware key
  operation (Android `BiometricPrompt` + `CryptoObject`; iOS Secure Enclave
  signing), not a bare boolean.
- **Secure encrypted storage** — `write`/`read`/`contains`/`delete`/`deleteAll`
  using AES-256-GCM envelope encryption with a per-secret data-encryption key
  held in the Android Keystore / iOS Keychain.
- **Biometric-protected storage** — reads are gated by the OS biometric prompt
  when the policy requires it.
- **App-lock** and **feature-level protection** sub-APIs.
- **Key lifecycle** — versioned metadata, migration, `rotateKey`, `revoke`,
  `revokeAll`, and `resetInvalidated` for recovery after invalidation.
- **Normalized `SecurityPolicy`** mapping one intent to both platforms
  (strength, device-credential fallback, enrollment binding, auth validity,
  hardware requirement, accessibility).
- **Typed error model** — a sealed `BiometricSecurityException` hierarchy;
  failures never return plaintext or silently regenerate keys.

### Security

- Enforced `requireSecureHardware` on both platforms (rejects software-backed
  keys / software auth fallback).
- Serialized per-key storage operations to prevent a concurrent-write
  DEK/ciphertext mismatch.
- All high-risk findings from an independent security review are fixed.

### Known limitations

- Every implemented flow is validated by unit tests and on physical Android and
  iOS devices.
- `signChallenge`, lifecycle-event emission, `enableProtection`/
  `disableProtection`, and `policyOf` are declared but not yet implemented.
- macOS, Windows, and Linux are not yet supported.
- Root/jailbreak behavior cannot be exercised on a standard device; integrity
  signals are advisory only.
