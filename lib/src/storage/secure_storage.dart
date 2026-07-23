/// The envelope-encryption storage engine.
library;

import 'dart:math';
import 'dart:typed_data';

import '../exceptions.dart';
import '../policy.dart';
import 'blob_store.dart';
import 'envelope.dart';
import 'key_vault.dart';
import 'payload_cipher.dart';

/// The secure storage engine: envelope encryption over a per-secret DEK, with
/// versioned metadata, migration, and key rotation.
///
/// Keying strategy (ARCHITECTURE.md DR-5, "safest practical"): **each secret has
/// its own random 256-bit DEK.** The payload is sealed with AES-256-GCM under
/// that DEK (software), and the DEK is held by the hardware [KeyVault]. This
/// gives per-secret isolation and revocation (destroying one secret's DEK cannot
/// affect any other) without a shared master key whose compromise would expose
/// everything. On iOS the DEK-in-hardware model is also mandatory because the
/// Secure Enclave is asymmetric-only (RESEARCH.md §4.4).
///
/// Concurrency: operations are independent per key; the engine holds no mutable
/// shared state, so concurrent calls on distinct keys are safe. The biometric
/// prompt itself is serialized by the platform layer (ARCHITECTURE.md §19).
class SecureStorage {
  SecureStorage({
    required KeyVault keyVault,
    required BlobStore blobStore,
    PayloadCipher? cipher,
    Random? random,
  }) : _vault = keyVault,
       _blobs = blobStore,
       _cipher = cipher ?? PayloadCipher(),
       _random = random ?? Random.secure();

  final KeyVault _vault;
  final BlobStore _blobs;
  final PayloadCipher _cipher;
  final Random _random;

  /// Encrypts and stores [value] under [key].
  Future<void> write({
    required String key,
    required Uint8List value,
    required SecurityPolicy policy,
    String? reason,
  }) async {
    final dek = _newDek();
    // Store the DEK in hardware first; if that is declined/fails, nothing is
    // half-written that could later be mistaken for valid data.
    await _vault.storeDek(id: key, dek: dek, policy: policy, reason: reason);
    final sealed = await _cipher.seal(dek: dek, clearText: value);
    final envelope = Envelope(
      schemaVersion: Envelope.currentSchemaVersion,
      vaultId: key,
      dekVersion: 1,
      algorithm: 'AES-256-GCM',
      gated: policy.requiresAuthentication,
      payload: sealed,
      createdAtMs: DateTime.now().millisecondsSinceEpoch,
    );
    await _blobs.put(key, envelope.toBytes());
  }

  /// Decrypts and returns the value for [key], or `null` if absent.
  ///
  /// Prompts when the secret is gated. Throws [KeyInvalidatedException] when the
  /// protecting key was invalidated, [CryptographicException] on a tag mismatch,
  /// and [SecureStorageException] on corrupt metadata. Never returns plaintext on
  /// any failure path (INV-3).
  Future<Uint8List?> read({required String key, String? reason}) async {
    final blob = await _blobs.get(key);
    if (blob == null) return null;
    final envelope = Envelope.fromBytes(blob); // throws on corruption
    final dek = await _vault.loadDek(id: key, reason: reason); // throws on invalidation
    return _cipher.open(dek: dek, payload: envelope.payload); // throws on tag mismatch
  }

  Future<bool> containsKey(String key) async => (await _blobs.get(key)) != null;

  /// Removes a secret and destroys its DEK (with a per-secret DEK, deleting the
  /// data already makes it cryptographically unrecoverable).
  Future<void> delete(String key) async {
    await _blobs.delete(key);
    await _vault.destroyDek(id: key);
  }

  /// Removes all secrets and destroys their DEKs.
  Future<void> deleteAll() async {
    await _blobs.clear();
    await _vault.destroyAll();
  }

  /// Alias for [delete] with revocation semantics: the DEK is destroyed, so the
  /// secret is unrecoverable even if its ciphertext were somehow restored.
  Future<void> revoke(String key) => delete(key);

  /// Hard kill-switch: destroys all key material, then wipes all ciphertext.
  Future<void> revokeAll() => deleteAll();

  /// All stored secret keys (metadata only; no decryption, no prompt).
  Future<Set<String>> keys() => _blobs.keys();

  /// Rotates the key material for [key]: unwraps the current value, generates a
  /// fresh DEK, re-encrypts, and re-stores — bumping [Envelope.dekVersion].
  ///
  /// Prompts once (to read the current value) when the secret is gated. Safe
  /// across a crash: the new DEK+blob are written before this returns; the old
  /// DEK is overwritten in place.
  Future<void> rotate({
    required String key,
    required SecurityPolicy policy,
    String? reason,
  }) async {
    final blob = await _blobs.get(key);
    if (blob == null) {
      throw const SecureStorageException('Cannot rotate a non-existent secret.');
    }
    final oldEnvelope = Envelope.fromBytes(blob);
    final clear = await read(key: key, reason: reason);
    if (clear == null) {
      throw const SecureStorageException('Cannot rotate: secret is unreadable.');
    }
    final newDek = _newDek();
    await _vault.storeDek(id: key, dek: newDek, policy: policy, reason: reason);
    final sealed = await _cipher.seal(dek: newDek, clearText: clear);
    final rotated = oldEnvelope.copyWith(
      dekVersion: oldEnvelope.dekVersion + 1,
      payload: sealed,
    );
    await _blobs.put(key, rotated.toBytes());
  }

  Uint8List _newDek() {
    final dek = Uint8List(PayloadCipher.dekLength);
    for (var i = 0; i < dek.length; i++) {
      dek[i] = _random.nextInt(256);
    }
    return dek;
  }
}
