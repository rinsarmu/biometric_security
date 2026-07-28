import 'dart:typed_data';

import 'package:biometric_security/biometric_security.dart';
import 'package:biometric_security/src/storage/secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'support/fakes.dart';

/// A fake platform providing capability detection and a canned auth session.
/// Storage is exercised through an injected [SecureStorage] over in-memory fakes.
class _FakePlatform extends BiometricSecurityPlatform
    with MockPlatformInterfaceMixin {
  int initializeCalls = 0;
  int authenticateCalls = 0;
  String? lastAuthScope;

  @override
  Future<void> initialize(BiometricSecurityConfig config) async {
    initializeCalls++;
  }

  @override
  Future<BiometricAvailability> getAvailability() async {
    return const BiometricAvailability(
      isSupported: true,
      supportedModalities: {BiometricModality.fingerprint},
      enrolledModalities: {},
      strength: BiometricStrength.strong,
      canAuthenticate: true,
      status: BiometricStatus.ready,
      guarantees: EnforceableGuarantees(
        canEnforceStrength: true,
        canBindKeyToAuthentication: true,
        canInvalidateOnEnrollmentChange: true,
      ),
      hasStrongBox: true,
      hasSecureEnclave: false,
    );
  }

  @override
  Future<AuthSession> authenticate({
    required String reason,
    required SecurityPolicy policy,
    String? cancelLabel,
    String scope = 'default',
  }) async {
    authenticateCalls++;
    lastAuthScope = scope;
    return AuthSession(
      token: 'ok',
      authenticatedAt: DateTime.fromMillisecondsSinceEpoch(0),
      securityLevel: SecurityLevel.strongBox,
    );
  }

  @override
  Future<void> resetInvalidated({String? scope}) async {}

  @override
  Stream<KeyLifecycleEvent> lifecycleEvents() => const Stream.empty();
}

void main() {
  group('SecurityPolicy', () {
    test('default constructor is secure-by-default', () {
      const p = SecurityPolicy();
      expect(p.minimumStrength, BiometricStrength.strong);
      expect(p.deviceCredentialFallback, DeviceCredentialFallback.disallow);
      expect(p.enrollmentBinding, EnrollmentBinding.invalidateOnChange);
      expect(p.authValidity, AuthValidity.perOperation);
      expect(p.requiresAuthentication, isTrue);
    });

    test('encryptedOnly does not require authentication', () {
      expect(
        const SecurityPolicy.encryptedOnly().requiresAuthentication,
        isFalse,
      );
    });

    test('presets differ from the strong default', () {
      expect(
        const SecurityPolicy.balanced(),
        isNot(const SecurityPolicy.strong()),
      );
      expect(
        const SecurityPolicy.convenient().deviceCredentialFallback,
        DeviceCredentialFallback.allow,
      );
    });

    test('round-trips through toMap/fromMap', () {
      const original = SecurityPolicy.balanced();
      final restored = SecurityPolicy.fromMap(original.toMap());
      expect(restored, original);
    });
  });

  group('Model deserialization', () {
    test('BiometricAvailability.fromMap parses modalities and enums', () {
      final a = BiometricAvailability.fromMap(const {
        'isSupported': true,
        'supportedModalities': ['face', 'fingerprint'],
        'enrolledModalities': ['face'],
        'strength': 'strong',
        'canAuthenticate': true,
        'status': 'ready',
        'guarantees': {
          'canEnforceStrength': true,
          'canBindKeyToAuthentication': true,
          'canInvalidateOnEnrollmentChange': true,
          'canForceSpecificModality': true, // must be forced to false
        },
        'hasStrongBox': false,
        'hasSecureEnclave': true,
      });
      expect(a.supportedModalities, {
        BiometricModality.face,
        BiometricModality.fingerprint,
      });
      expect(a.guarantees.canForceSpecificModality, isFalse);
    });

    test('unknown enum names fall back safely', () {
      final a = BiometricAvailability.fromMap(const {'strength': 'bogus'});
      expect(a.strength, BiometricStrength.none);
    });
  });

  group('Exceptions', () {
    test('all concrete exceptions are BiometricSecurityException', () {
      final samples = <BiometricSecurityException>[
        const BiometricAuthCanceledException(),
        const BiometricAuthFailedException(),
        const BiometricLockedOutException(isPermanent: true),
        const BiometricUnavailableException(),
        const BiometricNotEnrolledException(),
        const KeyInvalidatedException(scope: 's'),
        const EnrollmentChangedException(),
        const SecureStorageException(),
        const CryptographicException(),
        const UnsupportedPlatformException(),
        const PolicyUnsupportedException(),
        const NotInitializedException(),
      ];
      for (final e in samples) {
        expect(e, isA<BiometricSecurityException>());
        expect(e.message, isNotEmpty);
      }
    });
  });

  group('BiometricSecurity facade', () {
    late _FakePlatform fake;
    late FakeKeyVault vault;
    late FakeBlobStore blobs;
    late BiometricSecurity security;

    setUp(() {
      fake = _FakePlatform();
      vault = FakeKeyVault();
      blobs = FakeBlobStore();
      security = BiometricSecurity(
        platform: fake,
        storage: SecureStorage(keyVault: vault, blobStore: blobs),
      );
    });

    test('throws NotInitializedException before initialize()', () {
      expect(security.getAvailability, throwsA(isA<NotInitializedException>()));
    });

    test('initialize is idempotent', () async {
      await security.initialize();
      await security.initialize();
      expect(fake.initializeCalls, 1);
    });

    test('getAvailability delegates to the platform', () async {
      await security.initialize();
      expect((await security.getAvailability()).canAuthenticate, isTrue);
    });

    test('write/read round-trips text through the engine', () async {
      await security.initialize();
      await security.write(key: const SecretKey('token'), value: 'hello');
      expect(await security.read(key: const SecretKey('token')), 'hello');
      // Ciphertext is stored, plaintext is not.
      expect(utf8Contains(blobs, 'token', 'hello'), isFalse);
    });

    test('read returns null for a missing key', () async {
      await security.initialize();
      expect(await security.read(key: const SecretKey('nope')), isNull);
    });

    test('contains/keys/delete behave and hide internal markers', () async {
      await security.initialize();
      await security.write(key: const SecretKey('a'), value: '1');
      expect(await security.contains(key: const SecretKey('a')), isTrue);
      expect(await security.keys(), contains(const SecretKey('a')));
      await security.delete(key: const SecretKey('a'));
      expect(await security.contains(key: const SecretKey('a')), isFalse);
    });

    test('authenticate delegates and passes the scope', () async {
      await security.initialize();
      final session = await security.authenticate(
        reason: 'x',
        scope: 'checkout',
      );
      expect(session.token, 'ok');
      expect(fake.lastAuthScope, 'checkout');
    });

    test('app lock enable/isEnabled/unlock/disable', () async {
      await security.initialize();
      expect(await security.appLock.isEnabled(), isFalse);
      await security.appLock.enable(reason: 'enable');
      expect(await security.appLock.isEnabled(), isTrue);
      // The app-lock marker is hidden from keys().
      expect(await security.keys(), isEmpty);
      final session = await security.appLock.unlock(reason: 'unlock');
      expect(session.token, 'ok');
      expect(fake.lastAuthScope, 'app_lock');
      await security.appLock.disable();
      expect(await security.appLock.isEnabled(), isFalse);
    });

    test(
      'feature gate: no policy succeeds trivially; with policy prompts',
      () async {
        await security.initialize();
        final open = await security.features.guard(featureId: 'f', reason: 'x');
        expect(open.securityLevel, SecurityLevel.none);
        expect(fake.authenticateCalls, 0);

        await security.features.setPolicy(
          featureId: 'f',
          policy: const SecurityPolicy.strong(),
        );
        await security.features.guard(featureId: 'f', reason: 'x');
        expect(fake.authenticateCalls, 1);
        expect(fake.lastAuthScope, 'feature.f');
      },
    );

    test('rotateKey preserves the value', () async {
      await security.initialize();
      await security.write(key: const SecretKey('a'), value: 'secret');
      await security.rotateKey(key: const SecretKey('a'));
      expect(await security.read(key: const SecretKey('a')), 'secret');
    });

    test('still-unimplemented contracts throw UnimplementedError', () async {
      await security.initialize();
      expect(
        () => security.signChallenge(challenge: Uint8List(0), reason: 'x'),
        throwsA(isA<UnimplementedError>()),
      );
    });
  });
}

/// Whether the stored blob for [key] contains [needle] as plaintext.
bool utf8Contains(FakeBlobStore blobs, String key, String needle) {
  final blob = blobs.data[key];
  if (blob == null) return false;
  return String.fromCharCodes(blob).contains(needle);
}
