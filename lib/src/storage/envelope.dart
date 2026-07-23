/// The versioned on-disk format for an encrypted secret.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../exceptions.dart';
import 'payload_cipher.dart';

/// The persisted, versioned metadata + ciphertext for one secret.
///
/// Stored as a self-describing JSON blob (base64 for binary fields) so it can be
/// inspected and migrated. It contains **no key material** — only the nonce,
/// ciphertext, authentication tag, and bookkeeping. The data-encryption key is
/// held separately by the hardware [KeyVault] (ARCHITECTURE.md §6).
class Envelope {
  /// The current on-disk schema version.
  static const int currentSchemaVersion = 1;

  /// The schema version this blob was written with.
  final int schemaVersion;

  /// The key-vault id holding the DEK for this secret.
  final String vaultId;

  /// The DEK version (bumped on rotation) — key versioning bookkeeping.
  final int dekVersion;

  /// The AEAD algorithm identifier.
  final String algorithm;

  /// Whether the DEK is protected by a biometric-gated vault entry.
  final bool gated;

  final SealedPayload payload;

  /// Creation timestamp (ms since epoch).
  final int createdAtMs;

  const Envelope({
    required this.schemaVersion,
    required this.vaultId,
    required this.dekVersion,
    required this.algorithm,
    required this.gated,
    required this.payload,
    required this.createdAtMs,
  });

  Envelope copyWith({int? dekVersion, SealedPayload? payload}) => Envelope(
    schemaVersion: schemaVersion,
    vaultId: vaultId,
    dekVersion: dekVersion ?? this.dekVersion,
    algorithm: algorithm,
    gated: gated,
    payload: payload ?? this.payload,
    createdAtMs: createdAtMs,
  );

  Uint8List toBytes() {
    final map = <String, Object?>{
      'schemaVersion': schemaVersion,
      'vaultId': vaultId,
      'dekVersion': dekVersion,
      'algorithm': algorithm,
      'gated': gated,
      'nonce': base64.encode(payload.nonce),
      'cipherText': base64.encode(payload.cipherText),
      'mac': base64.encode(payload.mac),
      'createdAtMs': createdAtMs,
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(map)));
  }

  /// Parses and, if necessary, migrates a stored blob to the current schema.
  ///
  /// Throws [SecureStorageException] on corrupt/unreadable data — never returns a
  /// partially-decoded or empty envelope (INV-3).
  factory Envelope.fromBytes(Uint8List bytes) {
    final Map<String, Object?> map;
    try {
      final decoded = jsonDecode(utf8.decode(bytes));
      if (decoded is! Map) {
        throw const FormatException('Envelope is not a JSON object.');
      }
      map = decoded.cast<String, Object?>();
    } catch (e) {
      throw const SecureStorageException(
        'Stored secret is corrupt and cannot be decoded.',
      );
    }
    return _migrate(map);
  }

  /// Applies forward migrations from the blob's schema version to the current
  /// one. Older versions gain sensible defaults for fields added later; an
  /// unknown/newer version is rejected rather than misread.
  static Envelope _migrate(Map<String, Object?> map) {
    var version = (map['schemaVersion'] as num?)?.toInt() ?? 0;

    // v0 -> v1: the pre-release format had no explicit version and no
    // `dekVersion`/`algorithm` fields; fill them with the original defaults.
    if (version == 0) {
      map['dekVersion'] ??= 1;
      map['algorithm'] ??= 'AES-256-GCM';
      map['gated'] ??= true;
      version = 1;
    }

    if (version > currentSchemaVersion) {
      throw SecureStorageException(
        'Stored secret uses a newer format (v$version) than this version '
        'supports (v$currentSchemaVersion).',
      );
    }

    try {
      return Envelope(
        schemaVersion: currentSchemaVersion,
        vaultId: map['vaultId']! as String,
        dekVersion: (map['dekVersion'] as num).toInt(),
        algorithm: map['algorithm']! as String,
        gated: map['gated']! as bool,
        payload: SealedPayload(
          nonce: base64.decode(map['nonce']! as String),
          cipherText: base64.decode(map['cipherText']! as String),
          mac: base64.decode(map['mac']! as String),
        ),
        createdAtMs: (map['createdAtMs'] as num?)?.toInt() ?? 0,
      );
    } catch (e) {
      throw const SecureStorageException(
        'Stored secret is missing required fields and cannot be read.',
      );
    }
  }
}
