# Changelog

All notable changes to `biometric_security` are documented here. This project
follows [Semantic Versioning](https://semver.org). Pre-1.0 releases are betas:
the public API may still change between minor versions.

## 0.1.0

Initial public beta. **Not yet production-ready** — see the "Status" and
"Platform limitations" sections of the README and `SECURITY_AUDIT.md`.

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
- See `SECURITY_AUDIT.md` for the full independent audit and remaining items.

### Known limitations

- Biometric/Keystore/Secure-Enclave paths are validated by unit tests and
  device/simulator builds, but **not yet on physical biometric hardware**.
- `signChallenge`, lifecycle-event emission, `enableProtection`/
  `disableProtection`, and `policyOf` are declared but not yet implemented.
- macOS, Windows, and Linux are not yet supported.
