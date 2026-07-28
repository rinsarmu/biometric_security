# `biometric_security` — Encryption & Storage Flow

> Implements the envelope model from [`ARCHITECTURE.md`](ARCHITECTURE.md) §6/§8.3.
> Engine: [`lib/src/storage/`](lib/src/storage/). No custom cryptography — AES-256-GCM via the `cryptography` package.

## 1. Keying strategy — per-secret DEK (not a shared master key)

The brief asked us to decide between a shared master key and per-value keys. We use **one random 256-bit data-encryption key (DEK) per secret** — the *safest practical* choice:

- **Isolation:** compromising or destroying one secret's DEK cannot affect any other secret. A single shared master key would make one compromise total.
- **Clean revocation:** because the DEK lives only in the hardware vault, destroying it makes exactly that secret unrecoverable, immediately.
- **Cross-platform necessity:** iOS's Secure Enclave is asymmetric-only (RESEARCH.md §4.4), so a per-secret symmetric DEK held in hardware is the uniform model that works on both platforms.

The **payload** is sealed with AES-256-GCM under the DEK (software, via `cryptography`). The **DEK** is held by the hardware `KeyVault` (Android Keystore / iOS Keychain + Secure Enclave), biometric-gated when the policy requires. The hardware key that protects the DEK **never enters Dart** (INV-2).

## 2. Components

| Layer | File | Role |
|---|---|---|
| `SecureStorage` | `storage/secure_storage.dart` | Orchestrates write/read/delete/revoke/rotate |
| `PayloadCipher` | `storage/payload_cipher.dart` | AES-256-GCM seal/open over a DEK |
| `Envelope` | `storage/envelope.dart` | Versioned metadata + ciphertext blob; migration |
| `KeyVault` | `storage/key_vault.dart` | Hardware DEK storage (gated); `PlatformKeyVault` → native |
| `BlobStore` | `storage/blob_store.dart` | Opaque ciphertext persistence; `PlatformBlobStore` → native |

Native DEK storage reuses the gated `write`/`read` primitives (Android Keystore per-secret key / iOS Keychain `SecAccessControl`). Native blob storage is non-gated raw bytes (`BlobStore.kt` SharedPreferences / `BlobKeychain.swift` Keychain, `ThisDeviceOnly`).

## 3. Write flow

```
write(key, value, policy)
 1. DEK   = 32 random bytes (Random.secure)
 2. vault.storeDek(id=key, dek, policy)     → hardware, gated per policy  (prompts on Android if gated)
 3. sealed = AES-256-GCM(dek, value)        → { nonce(96-bit, random), cipherText, mac(128-bit) }
 4. envelope = { schemaVersion=1, vaultId=key, dekVersion=1, algorithm="AES-256-GCM",
                 gated, nonce, cipherText, mac, createdAtMs }
 5. blobStore.put(key, envelope.toBytes())  → opaque JSON blob, non-gated
```

The DEK is stored **before** the blob, so a declined/failed write never leaves a blob that looks valid but is unreadable.

## 4. Read flow

```
read(key, reason)
 1. blob = blobStore.get(key)               → null ⇒ return null
 2. envelope = Envelope.fromBytes(blob)      → throws SecureStorageException on corruption / migrates old schema
 3. dek = vault.loadDek(id=key, reason)      → prompts if gated; throws KeyInvalidatedException on invalidation
 4. plaintext = AES-256-GCM open(dek, envelope.payload)
                                             → throws CryptographicException on tag mismatch (NO plaintext returned)
```

Each failure is a distinct typed exception. Plaintext is returned only when the blob decodes, the DEK is valid, **and** the authentication tag verifies.

## 5. Every encrypted value carries

- **Secure random nonce** — 96-bit, generated fresh per encryption by `cryptography`. A fresh DEK+nonce per write makes nonce reuse under one key structurally impossible.
- **Authentication tag** — 128-bit GCM MAC, verified on every read.
- **Versioned metadata** — `schemaVersion` (on-disk format) + `dekVersion` (key version) + `algorithm`.
- **No key material** — the blob contains only ciphertext/nonce/tag/bookkeeping (asserted by tests).

## 6. Key versioning, rotation, migration

- **Rotation** (`rotate(key, policy)`): read (unwrap+decrypt, one prompt if gated) → new random DEK → re-seal → store new DEK + blob, bumping `dekVersion`. Old DEK overwritten in place.
- **Migration** (`Envelope.fromBytes`): reads the blob's `schemaVersion` and applies forward migrations (e.g. a pre-versioned *v0* blob gets `dekVersion`/`algorithm` defaults). A blob whose version is **newer** than supported is rejected, never misread.

## 7. What happens when a key becomes invalid

An enrollment change / disabled lock invalidates the hardware key protecting the DEK. On the next `read`, `vault.loadDek` surfaces `KeyInvalidatedException` (code `key_invalidated`).

**Defined behavior (INV-3):**
- Read **fails loudly** with `KeyInvalidatedException`. **Plaintext is never returned; security is never bypassed.**
- The ciphertext blob is **not** deleted — nothing is silently destroyed.
- The app decides: re-fetch the real value from its source of truth and re-`write`, after `resetInvalidated(scope:)` clears the dead key. The old secret is, by design, unrecoverable on-device.

## 8. Failure → exception map

| Situation | Exception (Dart) |
|---|---|
| Encryption failure (bad DEK length) | `CryptographicException` |
| Decryption failure / tampered ciphertext / **wrong auth tag** | `CryptographicException` |
| Corrupted blob (unparseable / missing fields / newer schema) | `SecureStorageException` |
| Missing DEK for an existing/restored blob | `SecureStorageException` |
| Invalidated key (enrollment / lock change) | `KeyInvalidatedException` |
| User canceled the unlock prompt | `BiometricAuthCanceledException` |

## 9. Guarantees & non-goals

**Never:** hardcoded keys or IVs; reused nonces; custom crypto; keys in UserDefaults / plain files / SQLite / SharedPreferences (only *ciphertext* is in SharedPreferences; DEKs are in Keystore/Keychain; the KEK never leaves hardware); plaintext or keys in logs; silent plaintext on failure.

**Tested** (`test/storage/secure_storage_test.dart`, 25+ cases): write/read, multiple independent keys, delete/deleteAll, corrupt ciphertext, tampered auth tag, tampered ciphertext, key invalidation (+ blob retained), revocation (unrecoverable even if ciphertext restored), concurrent access, migration (v0→v1 + newer-version rejection), rotation, nonce uniqueness, no-plaintext-in-blob.
