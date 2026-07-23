/// The typed exception hierarchy for the public API.
///
/// Every failure thrown by the package is a subtype of
/// [BiometricSecurityException]. Callers may catch the sealed root broadly or
/// match precisely; the sealed hierarchy enables exhaustive `switch`.
library;

import 'enums.dart';

/// The sealed root of all failures thrown by `biometric_security`.
sealed class BiometricSecurityException implements Exception {
  /// A human-readable description of the failure.
  final String message;

  /// Opaque platform detail for logging only. Never a platform-specific type in
  /// the public API (INV-2).
  final Object? platformDetail;

  /// Creates an exception.
  const BiometricSecurityException(this.message, {this.platformDetail});

  @override
  String toString() => '$runtimeType: $message';
}

// --------------------------------------------------------------------------
// Authentication
// --------------------------------------------------------------------------

/// The user dismissed or canceled the prompt. Expected control flow.
class BiometricAuthCanceledException extends BiometricSecurityException {
  /// Creates a cancellation exception.
  const BiometricAuthCanceledException([
    super.message = 'Authentication was canceled by the user.',
  ]);
}

/// A biometric was presented but did not match. May be retryable.
class BiometricAuthFailedException extends BiometricSecurityException {
  /// Creates an authentication-failed exception.
  const BiometricAuthFailedException([
    super.message = 'Authentication failed.',
  ]);
}

/// Authentication is temporarily or permanently locked out.
class BiometricLockedOutException extends BiometricSecurityException {
  /// Whether the lockout requires a device-credential unlock to clear.
  final bool isPermanent;

  /// Creates a lockout exception.
  const BiometricLockedOutException({
    this.isPermanent = false,
    String message = 'Authentication is locked out.',
  }) : super(message);
}

// --------------------------------------------------------------------------
// Availability / enrollment
// --------------------------------------------------------------------------

/// Biometric authentication is unavailable on this device or right now.
class BiometricUnavailableException extends BiometricSecurityException {
  /// The precise unavailability reason.
  final BiometricStatus status;

  /// Creates an unavailability exception.
  const BiometricUnavailableException({
    this.status = BiometricStatus.unknown,
    String message = 'Biometric authentication is unavailable.',
  }) : super(message);
}

/// No biometric is enrolled on the device.
class BiometricNotEnrolledException extends BiometricSecurityException {
  /// Creates a not-enrolled exception.
  const BiometricNotEnrolledException([
    super.message = 'No biometric is enrolled on this device.',
  ]);
}

// --------------------------------------------------------------------------
// Key / enrollment lifecycle
// --------------------------------------------------------------------------

/// A key was permanently invalidated (for example by an enrollment change or by
/// the device lock being disabled). The package never auto-repairs this
/// (INV-3); the caller must reprovision.
class KeyInvalidatedException extends BiometricSecurityException {
  /// The affected protection scope, if known.
  final String? scope;

  /// Creates a key-invalidated exception.
  const KeyInvalidatedException({
    this.scope,
    String message = 'The protecting key was permanently invalidated.',
  }) : super(message);
}

/// The enrolled biometrics changed since the data was stored.
class EnrollmentChangedException extends BiometricSecurityException {
  /// Creates an enrollment-changed exception.
  const EnrollmentChangedException([
    super.message = 'The enrolled biometrics changed since this data was stored.',
  ]);
}

// --------------------------------------------------------------------------
// Storage / crypto
// --------------------------------------------------------------------------

/// A secure-storage operation failed.
class SecureStorageException extends BiometricSecurityException {
  /// Creates a secure-storage exception.
  const SecureStorageException([
    super.message = 'A secure storage operation failed.',
  ]);
}

/// A cryptographic operation failed, for example an authentication-tag
/// mismatch. No plaintext is ever returned on this path.
class CryptographicException extends BiometricSecurityException {
  /// Creates a cryptographic-failure exception.
  const CryptographicException([
    super.message = 'A cryptographic operation failed.',
  ]);
}

// --------------------------------------------------------------------------
// Configuration / platform
// --------------------------------------------------------------------------

/// The current platform has no `biometric_security` implementation.
class UnsupportedPlatformException extends BiometricSecurityException {
  /// Creates an unsupported-platform exception.
  const UnsupportedPlatformException([
    super.message = 'This platform is not supported by biometric_security.',
  ]);
}

/// The requested [SecurityPolicy] cannot be expressed on this device.
class PolicyUnsupportedException extends BiometricSecurityException {
  /// Creates a policy-unsupported exception.
  const PolicyUnsupportedException([
    super.message = 'The requested security policy is not supported on this device.',
  ]);
}

/// A method was called before [BiometricSecurity.initialize].
class NotInitializedException extends BiometricSecurityException {
  /// Creates a not-initialized exception.
  const NotInitializedException([
    super.message = 'BiometricSecurity.initialize() must be called first.',
  ]);
}
