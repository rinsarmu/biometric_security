/// The ciphertext-blob persistence abstraction and its platform implementation.
library;

import 'dart:typed_data';

import '../platform/platform_interface.dart';

/// Persists opaque, already-encrypted [Envelope] blobs.
///
/// Blobs contain only ciphertext + non-sensitive metadata, so they need no
/// gating; the security comes from the AEAD and the hardware-held DEK. Nothing
/// here is a cryptographic key.
abstract class BlobStore {
  Future<void> put(String key, Uint8List blob);
  Future<Uint8List?> get(String key);
  Future<void> delete(String key);
  Future<Set<String>> keys();
  Future<void> clear();
}

/// Production [BlobStore] backed by the platform's non-gated raw storage
/// (Android SharedPreferences / iOS Keychain items, `ThisDeviceOnly`).
class PlatformBlobStore implements BlobStore {
  PlatformBlobStore(this._platform);

  final BiometricSecurityPlatform _platform;

  @override
  Future<void> put(String key, Uint8List blob) =>
      _platform.blobPut(key: key, blob: blob);

  @override
  Future<Uint8List?> get(String key) => _platform.blobGet(key: key);

  @override
  Future<void> delete(String key) => _platform.blobDelete(key: key);

  @override
  Future<Set<String>> keys() => _platform.blobKeys();

  @override
  Future<void> clear() => _platform.blobClear();
}
