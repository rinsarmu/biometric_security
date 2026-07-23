import 'dart:typed_data';

import 'package:biometric_security/biometric_security.dart';
import 'package:biometric_security/src/storage/blob_store.dart';
import 'package:biometric_security/src/storage/key_vault.dart';

/// In-memory [KeyVault] for tests. Supports simulating key invalidation.
class FakeKeyVault implements KeyVault {
  final Map<String, Uint8List> deks = {};

  /// Ids whose [loadDek] should throw [KeyInvalidatedException].
  final Set<String> invalidated = {};

  int storeCalls = 0;

  @override
  Future<void> storeDek({
    required String id,
    required Uint8List dek,
    required SecurityPolicy policy,
    String? reason,
  }) async {
    storeCalls++;
    deks[id] = Uint8List.fromList(dek);
  }

  @override
  Future<Uint8List> loadDek({required String id, String? reason}) async {
    if (invalidated.contains(id)) {
      throw KeyInvalidatedException(scope: id);
    }
    final dek = deks[id];
    if (dek == null) {
      throw const SecureStorageException('No key material for this secret.');
    }
    return dek;
  }

  @override
  Future<void> destroyDek({required String id}) async {
    deks.remove(id);
  }

  @override
  Future<void> destroyAll() async {
    deks.clear();
  }
}

/// In-memory [BlobStore] for tests.
class FakeBlobStore implements BlobStore {
  final Map<String, Uint8List> data = {};

  @override
  Future<void> put(String key, Uint8List blob) async {
    data[key] = Uint8List.fromList(blob);
  }

  @override
  Future<Uint8List?> get(String key) async => data[key];

  @override
  Future<void> delete(String key) async {
    data.remove(key);
  }

  @override
  Future<Set<String>> keys() async => data.keys.toSet();

  @override
  Future<void> clear() async => data.clear();
}
