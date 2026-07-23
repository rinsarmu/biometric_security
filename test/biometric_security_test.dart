import 'dart:convert';
import 'dart:typed_data';

import 'package:biometric_security/biometric_security.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

/// A fake platform with an in-memory store, used to drive the facade without a
/// native channel. Non-gated writes/reads round-trip; [authenticate] returns a
/// canned session so higher-level flows (app-lock, feature gate) can be tested.
class _FakePlatform extends BiometricSecurityPlatform
    with MockPlatformInterfaceMixin {
  int initializeCalls = 0;
  int authenticateCalls = 0;
  String? lastAuthScope;
  final Map<String, Uint8List> store = {};

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
  Future<SecurityStatus> getSecurityStatus() async {
    return SecurityStatus(
      availability: await getAvailability(),
      achievableSecurityLevel: SecurityLevel.strongBox,
      reprovisionRequired: false,
      integrityRisk: false,
    );
  }

  @override
  Stream<KeyLifecycleEvent> lifecycleEvents() => const Stream.empty();

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
  Future<void> write({
    required String key,
    required Uint8List value,
    required SecurityPolicy policy,
    String? reason,
  }) async {
    store[key] = value;
  }

  @override
  Future<Uint8List?> read({required String key, String? reason}) async =>
      store[key];

  @override
  Future<void> delete({required String key}) async {
    store.remove(key);
  }

  @override
  Future<void> deleteAll() async => store.clear();

  @override
  Future<bool> contains({required String key}) async => store.containsKey(key);

  @override
  Future<Set<String>> keys() async => store.keys.toSet();

  @override
  Future<void> revoke({required String key}) async {
    store.remove(key);
  }

  @override
  Future<void> revokeAll() async => store.clear();

  @override
  Future<void> resetInvalidated({String? scope}) async {}
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
      expect(const SecurityPolicy.encryptedOnly().requiresAuthentication, isFalse);
    });

    test('presets differ from the strong default', () {
      expect(const SecurityPolicy.balanced(), isNot(const SecurityPolicy.strong()));
      expect(const SecurityPolicy.convenient().deviceCredentialFallback,
          DeviceCredentialFallback.allow);
    });

    test('round-trips through toMap/fromMap', () {
      const original = SecurityPolicy.balanced();
      final restored = SecurityPolicy.fromMap(original.toMap());
      expect(restored, original);
    });

    test('copyWith replaces only the given field', () {
      const base = SecurityPolicy();
      final copy = base.copyWith(requireConfirmation: true);
      expect(copy.requireConfirmation, isTrue);
      expect(copy.minimumStrength, base.minimumStrength);
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
      expect(a.supportedModalities,
          {BiometricModality.face, BiometricModality.fingerprint});
      expect(a.enrolledModalities, {BiometricModality.face});
      expect(a.status, BiometricStatus.ready);
      expect(a.hasSecureEnclave, isTrue);
      // Honesty invariant: never surfaced as true.
      expect(a.guarantees.canForceSpecificModality, isFalse);
    });

    test('unknown enum names fall back safely', () {
      final a = BiometricAvailability.fromMap(const {
        'strength': 'bogus',
        'status': 'also_bogus',
      });
      expect(a.strength, BiometricStrength.none);
      expect(a.status, BiometricStatus.unknown);
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
    late BiometricSecurity security;

    setUp(() {
      fake = _FakePlatform();
      security = BiometricSecurity(platform: fake);
    });

    test('throws NotInitializedException before initialize()', () {
      expect(security.getAvailability, throwsA(isA<NotInitializedException>()));
    });

    test('initialize is idempotent', () async {
      await security.initialize();
      await security.initialize();
      expect(fake.initializeCalls, 1);
      expect(security.isInitialized, isTrue);
    });

    test('getAvailability delegates to the platform', () async {
      await security.initialize();
      final a = await security.getAvailability();
      expect(a.canAuthenticate, isTrue);
      expect(a.supportedModalities, contains(BiometricModality.fingerprint));
    });

    test('write/read round-trips text through the platform', () async {
      await security.initialize();
      await security.write(
        key: const SecretKey('token'),
        value: 'hello',
        policy: const SecurityPolicy.encryptedOnly(),
      );
      expect(await security.read(key: const SecretKey('token')), 'hello');
      expect(fake.store['token'], utf8.encode('hello'));
    });

    test('read returns null for a missing key', () async {
      await security.initialize();
      expect(await security.read(key: const SecretKey('nope')), isNull);
    });

    test('contains/keys/delete/deleteAll behave', () async {
      await security.initialize();
      await security.write(
        key: const SecretKey('a'),
        value: '1',
        policy: const SecurityPolicy.encryptedOnly(),
      );
      expect(await security.contains(key: const SecretKey('a')), isTrue);
      expect(await security.keys(), contains(const SecretKey('a')));
      await security.delete(key: const SecretKey('a'));
      expect(await security.contains(key: const SecretKey('a')), isFalse);
    });

    test('authenticate delegates and passes the scope', () async {
      await security.initialize();
      final session = await security.authenticate(reason: 'x', scope: 'checkout');
      expect(session.token, 'ok');
      expect(fake.lastAuthScope, 'checkout');
    });

    test('app lock enable/isEnabled/unlock/disable', () async {
      await security.initialize();
      expect(await security.appLock.isEnabled(), isFalse);
      await security.appLock.enable(reason: 'enable');
      expect(await security.appLock.isEnabled(), isTrue);
      final session = await security.appLock.unlock(reason: 'unlock');
      expect(session.token, 'ok');
      expect(fake.lastAuthScope, 'app_lock');
      await security.appLock.disable();
      expect(await security.appLock.isEnabled(), isFalse);
    });

    test('feature gate: no policy succeeds trivially; with policy prompts',
        () async {
      await security.initialize();
      final open = await security.features.guard(featureId: 'f', reason: 'x');
      expect(open.securityLevel, SecurityLevel.none);
      expect(fake.authenticateCalls, 0);

      await security.features.setPolicy(
        featureId: 'f',
        policy: const SecurityPolicy.strong(),
      );
      final gated = await security.features.guard(featureId: 'f', reason: 'x');
      expect(gated.token, 'ok');
      expect(fake.authenticateCalls, 1);
      expect(fake.lastAuthScope, 'feature.f');
    });

    test('still-unimplemented contracts throw UnimplementedError', () async {
      await security.initialize();
      expect(
        () => security.signChallenge(
          challenge: Uint8List(0),
          reason: 'x',
        ),
        throwsA(isA<UnimplementedError>()),
      );
    });
  });
}
