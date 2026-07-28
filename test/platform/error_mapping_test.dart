import 'package:biometric_security/biometric_security.dart';
import 'package:biometric_security/src/platform/method_channel.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Locks in the native → Dart error-code contract. In particular, both
/// `authenticate()` (Secure Enclave / Keystore auth key) and `read()` now emit
/// `key_invalidated` on a biometric-enrollment change, and it must surface as a
/// typed [KeyInvalidatedException] callers can catch consistently.
void main() {
  group('mapPlatformException', () {
    test('key_invalidated → KeyInvalidatedException', () {
      final e = mapPlatformException(
        PlatformException(code: 'key_invalidated', message: 'invalidated'),
      );
      expect(e, isA<KeyInvalidatedException>());
    });

    test('auth_canceled → BiometricAuthCanceledException', () {
      expect(
        mapPlatformException(PlatformException(code: 'auth_canceled')),
        isA<BiometricAuthCanceledException>(),
      );
    });

    test('locked_out_permanent → permanent BiometricLockedOutException', () {
      final e = mapPlatformException(
        PlatformException(code: 'locked_out_permanent'),
      );
      expect(e, isA<BiometricLockedOutException>());
      expect((e as BiometricLockedOutException).isPermanent, isTrue);
    });

    test('not_enrolled → BiometricNotEnrolledException', () {
      expect(
        mapPlatformException(PlatformException(code: 'not_enrolled')),
        isA<BiometricNotEnrolledException>(),
      );
    });

    test('unknown code → SecureStorageException (safe default)', () {
      expect(
        mapPlatformException(PlatformException(code: 'something_new')),
        isA<SecureStorageException>(),
      );
    });
  });
}
