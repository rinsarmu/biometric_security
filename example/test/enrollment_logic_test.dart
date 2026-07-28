import 'package:biometric_security/biometric_security.dart';
import 'package:biometric_security_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

/// Unit tests for the example's Dart-level enrollment interpretation helpers.
/// The actual enrollment-change *detection* is native and requires a physical
/// device — it is NOT tested here (that would be a fake test).
void main() {
  group('keyStateForError', () {
    test('KeyInvalidatedException maps to invalidated', () {
      expect(
        keyStateForError(const KeyInvalidatedException()),
        ProtectedKeyState.invalidated,
      );
    });

    test('cancellation maps to unknown', () {
      expect(
        keyStateForError(const BiometricAuthCanceledException()),
        ProtectedKeyState.unknown,
      );
    });

    test('other failures map to error', () {
      expect(
        keyStateForError(const SecureStorageException()),
        ProtectedKeyState.error,
      );
      expect(
        keyStateForError(const CryptographicException()),
        ProtectedKeyState.error,
      );
    });
  });

  group('enrollmentSummary', () {
    test(
      'includes status and strength, and notes Android cannot enumerate',
      () {
        const a = BiometricAvailability(
          isSupported: true,
          supportedModalities: {BiometricModality.fingerprint},
          enrolledModalities: {}, // Android reports none
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
        final summary = enrollmentSummary(a);
        expect(summary, contains('status=ready'));
        expect(summary, contains('strength=strong'));
        expect(summary, contains('does not enumerate'));
      },
    );

    test('lists enrolled modalities when the platform reports them (iOS)', () {
      const a = BiometricAvailability(
        isSupported: true,
        supportedModalities: {BiometricModality.face},
        enrolledModalities: {BiometricModality.face},
        strength: BiometricStrength.strong,
        canAuthenticate: true,
        status: BiometricStatus.ready,
        guarantees: EnforceableGuarantees(
          canEnforceStrength: true,
          canBindKeyToAuthentication: true,
          canInvalidateOnEnrollmentChange: true,
        ),
        hasStrongBox: false,
        hasSecureEnclave: true,
      );
      expect(enrollmentSummary(a), contains('enrolled=face'));
    });
  });
}
