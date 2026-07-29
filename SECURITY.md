# Security Policy

`biometric_security` is a security-critical package. We take reports seriously
and appreciate responsible disclosure.

## Status

**This package is a 0.1.0 public beta and is not yet production-ready.** An
independent security review fixed all high-risk findings; medium/low items and
on-device validation remain. Do not use it to protect high-value production
secrets until those items are complete.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (beta — security fixes only) |
| < 0.1.0 | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Instead, email **roberaensermu@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version(s) and platform(s),
- any suggested remediation.

We aim to acknowledge within **72 hours** and to provide a remediation plan
within **14 days**, coordinating a disclosure timeline with you. Please give us a
reasonable window to release a fix before public disclosure.

## Scope

In scope: cryptographic weaknesses, key-management or biometric-binding bypasses,
plaintext/key leakage, incorrect Keystore/Keychain/SecAccessControl
configuration, and logic that returns secrets without authentication.

Out of scope (documented limitations, not vulnerabilities): forcing a specific
biometric modality, extracting keys from a compromised OS/kernel or live process
memory on a rooted/jailbroken device, and making device-bound hardware keys
survive migration. See the README threat model.

## Security model (summary)

- AES-256-GCM envelope encryption; per-secret data-encryption key.
- Keys held in Android Keystore / iOS Keychain + Secure Enclave; the hardware key
  never crosses into Dart.
- Biometric-gated key operations (not a forgeable boolean).
- Fails loud: never returns plaintext or silently regenerates keys.

Full detail is documented in the README.
