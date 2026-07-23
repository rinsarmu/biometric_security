import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_security/biometric_security.dart';
import 'package:biometric_security/src/storage/envelope.dart';
import 'package:biometric_security/src/storage/payload_cipher.dart';
import 'package:biometric_security/src/storage/secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/fakes.dart';

Uint8List _bytes(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  late FakeKeyVault vault;
  late FakeBlobStore blobs;
  late SecureStorage storage;
  const policy = SecurityPolicy.strong();

  setUp(() {
    vault = FakeKeyVault();
    blobs = FakeBlobStore();
    storage = SecureStorage(keyVault: vault, blobStore: blobs);
  });

  group('write/read', () {
    test('round-trips a value', () async {
      await storage.write(key: 'pin', value: _bytes('1234'), policy: policy);
      final out = await storage.read(key: 'pin');
      expect(out, _bytes('1234'));
    });

    test('read of a missing key returns null', () async {
      expect(await storage.read(key: 'nope'), isNull);
    });

    test('the stored blob contains no plaintext and no key material', () async {
      await storage.write(key: 'pin', value: _bytes('supersecret'), policy: policy);
      final blob = utf8.decode(blobs.data['pin']!);
      expect(blob.contains('supersecret'), isFalse);
      // The DEK lives only in the vault, never in the blob.
      expect(blob.contains(base64.encode(vault.deks['pin']!)), isFalse);
    });

    test('each write uses a fresh nonce (no nonce reuse)', () async {
      await storage.write(key: 'a', value: _bytes('same'), policy: policy);
      final first = Envelope.fromBytes(blobs.data['a']!);
      await storage.write(key: 'a', value: _bytes('same'), policy: policy);
      final second = Envelope.fromBytes(blobs.data['a']!);
      expect(first.payload.nonce, isNot(second.payload.nonce));
      expect(first.payload.cipherText, isNot(second.payload.cipherText));
    });

    test('envelope carries versioned metadata', () async {
      await storage.write(key: 'a', value: _bytes('x'), policy: policy);
      final env = Envelope.fromBytes(blobs.data['a']!);
      expect(env.schemaVersion, Envelope.currentSchemaVersion);
      expect(env.algorithm, 'AES-256-GCM');
      expect(env.dekVersion, 1);
      expect(env.payload.mac.length, 16); // 128-bit tag
      expect(env.payload.nonce.length, 12); // 96-bit nonce
    });
  });

  group('multiple keys', () {
    test('are independent', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      await storage.write(key: 'b', value: _bytes('BBB'), policy: policy);
      expect(await storage.read(key: 'a'), _bytes('AAA'));
      expect(await storage.read(key: 'b'), _bytes('BBB'));
      expect((await storage.keys()), containsAll(<String>['a', 'b']));
    });

    test('each secret has its own DEK', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      await storage.write(key: 'b', value: _bytes('BBB'), policy: policy);
      expect(vault.deks['a'], isNot(vault.deks['b']));
    });
  });

  group('delete / deleteAll', () {
    test('delete removes the blob and the DEK', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      await storage.delete('a');
      expect(await storage.read(key: 'a'), isNull);
      expect(vault.deks.containsKey('a'), isFalse);
      expect(blobs.data.containsKey('a'), isFalse);
    });

    test('deleteAll clears everything', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      await storage.write(key: 'b', value: _bytes('BBB'), policy: policy);
      await storage.deleteAll();
      expect(await storage.keys(), isEmpty);
      expect(vault.deks, isEmpty);
    });

    test('delete is idempotent', () async {
      await storage.delete('ghost'); // must not throw
    });
  });

  group('failure handling', () {
    test('corrupt ciphertext blob throws SecureStorageException', () async {
      blobs.data['x'] = Uint8List.fromList([0, 1, 2, 3, 4]); // not valid JSON
      expect(
        () => storage.read(key: 'x'),
        throwsA(isA<SecureStorageException>()),
      );
    });

    test('tampered authentication tag throws CryptographicException', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      final env = Envelope.fromBytes(blobs.data['a']!);
      final badMac = Uint8List.fromList(env.payload.mac);
      badMac[0] = badMac[0] ^ 0xFF; // flip a tag bit
      final tampered = env.copyWith(
        payload: SealedPayload(
          nonce: env.payload.nonce,
          cipherText: env.payload.cipherText,
          mac: badMac,
        ),
      );
      blobs.data['a'] = tampered.toBytes();
      expect(
        () => storage.read(key: 'a'),
        throwsA(isA<CryptographicException>()),
      );
    });

    test('tampered ciphertext throws CryptographicException (no plaintext)',
        () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      final env = Envelope.fromBytes(blobs.data['a']!);
      final badCt = Uint8List.fromList(env.payload.cipherText);
      badCt[0] = badCt[0] ^ 0xFF;
      blobs.data['a'] = env
          .copyWith(
            payload: SealedPayload(
              nonce: env.payload.nonce,
              cipherText: badCt,
              mac: env.payload.mac,
            ),
          )
          .toBytes();
      expect(
        () => storage.read(key: 'a'),
        throwsA(isA<CryptographicException>()),
      );
    });

    test('newer schema version is rejected, not misread', () {
      final future = Uint8List.fromList(
        utf8.encode(jsonEncode({'schemaVersion': 999})),
      );
      expect(
        () => Envelope.fromBytes(future),
        throwsA(isA<SecureStorageException>()),
      );
    });
  });

  group('key invalidation', () {
    test('read throws KeyInvalidatedException and keeps the blob', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      vault.invalidated.add('a');
      expect(
        () => storage.read(key: 'a'),
        throwsA(isA<KeyInvalidatedException>()),
      );
      // INV-3: the ciphertext is NOT silently destroyed.
      expect(blobs.data.containsKey('a'), isTrue);
    });

    test('never returns plaintext when the key is invalid', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      vault.invalidated.add('a');
      Object? caught;
      try {
        await storage.read(key: 'a');
      } catch (e) {
        caught = e;
      }
      expect(caught, isA<KeyInvalidatedException>());
    });
  });

  group('revocation', () {
    test('revoke makes the secret unrecoverable even if ciphertext returns',
        () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      final savedBlob = Uint8List.fromList(blobs.data['a']!);
      await storage.revoke('a');
      // Restore only the ciphertext; the DEK is gone.
      blobs.data['a'] = savedBlob;
      expect(
        () => storage.read(key: 'a'),
        throwsA(isA<SecureStorageException>()),
      );
    });

    test('revokeAll destroys all keys and data', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      await storage.write(key: 'b', value: _bytes('BBB'), policy: policy);
      await storage.revokeAll();
      expect(vault.deks, isEmpty);
      expect(blobs.data, isEmpty);
    });
  });

  group('concurrent access', () {
    test('concurrent writes to distinct keys all persist', () async {
      await Future.wait([
        for (var i = 0; i < 20; i++)
          storage.write(key: 'k$i', value: _bytes('v$i'), policy: policy),
      ]);
      final reads = await Future.wait([
        for (var i = 0; i < 20; i++) storage.read(key: 'k$i'),
      ]);
      for (var i = 0; i < 20; i++) {
        expect(reads[i], _bytes('v$i'));
      }
    });

    test('concurrent reads of the same key are consistent', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      final results = await Future.wait([
        for (var i = 0; i < 10; i++) storage.read(key: 'a'),
      ]);
      for (final r in results) {
        expect(r, _bytes('AAA'));
      }
    });
  });

  group('migration', () {
    test('reads a legacy (v0) blob by migrating it forward', () async {
      // Write normally, then rewrite the blob in the pre-versioned v0 format.
      await storage.write(key: 'a', value: _bytes('legacy'), policy: policy);
      final map =
          jsonDecode(utf8.decode(blobs.data['a']!)) as Map<String, Object?>;
      map.remove('schemaVersion');
      map.remove('dekVersion');
      map.remove('algorithm');
      blobs.data['a'] = Uint8List.fromList(utf8.encode(jsonEncode(map)));

      final out = await storage.read(key: 'a');
      expect(out, _bytes('legacy'));
    });

    test('Envelope migration fills v0 defaults', () {
      // A minimal v0 blob with valid (empty-ish) crypto fields.
      final v0 = {
        'vaultId': 'a',
        'gated': true,
        'nonce': base64.encode(Uint8List(12)),
        'cipherText': base64.encode(Uint8List(4)),
        'mac': base64.encode(Uint8List(16)),
        'createdAtMs': 0,
      };
      final env = Envelope.fromBytes(
        Uint8List.fromList(utf8.encode(jsonEncode(v0))),
      );
      expect(env.schemaVersion, Envelope.currentSchemaVersion);
      expect(env.dekVersion, 1);
      expect(env.algorithm, 'AES-256-GCM');
    });
  });

  group('key rotation', () {
    test('rotate re-keys and preserves the value', () async {
      await storage.write(key: 'a', value: _bytes('AAA'), policy: policy);
      final oldDek = Uint8List.fromList(vault.deks['a']!);

      await storage.rotate(key: 'a', policy: policy);

      expect(vault.deks['a'], isNot(oldDek)); // new DEK
      expect(await storage.read(key: 'a'), _bytes('AAA')); // same value
      final env = Envelope.fromBytes(blobs.data['a']!);
      expect(env.dekVersion, 2); // version bumped
    });

    test('rotate on a missing key throws', () async {
      expect(
        () => storage.rotate(key: 'ghost', policy: policy),
        throwsA(isA<SecureStorageException>()),
      );
    });
  });
}
