/// Enumerations for the public `biometric_security` API.
library;

/// A biometric hardware family.
///
/// Informational for UX only; it is **not** selectable or enforceable. Neither
/// Android nor iOS lets an app force a specific modality.
enum BiometricModality { face, fingerprint, iris, unknown }

/// Android biometric strength classes.
///
/// iOS has no weak tier, so enrolled iOS biometrics are reported as [strong].
/// Only [strong] biometrics can gate a cryptographic key.
enum BiometricStrength { strong, weak, none }

/// Why authentication is or is not currently possible.
///
/// Distinguishes states that apps commonly conflate.
enum BiometricStatus {
  /// Enrolled and not locked out — authentication can proceed.
  ready,

  /// The device has no biometric sensors.
  noHardware,

  /// Sensors exist but are temporarily unavailable.
  hardwareUnavailable,

  /// Hardware is present but nothing is enrolled.
  notEnrolled,

  /// No device PIN/pattern/passcode is set, so the OS cannot secure keys.
  noDeviceCredential,

  /// Too many attempts — temporarily locked out.
  lockedOut,

  /// Locked out until the user unlocks with a device credential.
  lockedOutPermanently,

  /// State could not be determined.
  unknown,
}

/// Whether a device credential (PIN/pattern/passcode) may satisfy a biometric gate.
///
/// [allow] is weaker and such keys are **not** invalidated by enrollment changes.
enum DeviceCredentialFallback { disallow, allow }

/// How protected data reacts to a change in the enrolled biometric set.
///
/// [invalidateOnChange] defends against a coerced new enrollment unlocking old
/// secrets. Maps to Android `setInvalidatedByBiometricEnrollment` and iOS
/// `biometryCurrentSet` vs `biometryAny`.
enum EnrollmentBinding { invalidateOnChange, persistAcrossEnrollment }

/// How long a single authentication authorizes key use.
///
/// [perOperation] forces a fresh prompt for every use (strongest). [window]
/// permits reuse for a bounded duration.
enum AuthValidity { perOperation, window }

/// Whether secure hardware is required or merely preferred.
enum HardwareRequirement { preferStrongestAvailable, requireSecureHardware }

/// When encrypted data may be decrypted, relative to device unlock.
///
/// The `thisDeviceOnly` variants are excluded from backups and device
/// migration.
enum StorageAccessibility {
  whenUnlockedThisDeviceOnly,
  afterFirstUnlockThisDeviceOnly,
}

/// The security level actually achieved for a key.
///
/// Reported honestly; never assumed.
enum SecurityLevel {
  strongBox,
  trustedExecutionEnvironment,
  secureEnclave,
  software,
  none,
}

/// Kinds of lifecycle events emitted on
/// [BiometricSecurity.lifecycleEvents].
enum KeyLifecycleEventType {
  /// The enrolled biometric set changed (advisory).
  enrollmentChanged,

  /// A key became permanently unusable.
  keyInvalidated,

  /// Affected secrets must be re-created and re-sealed.
  reprovisionRequired,

  /// A device-integrity risk (root/jailbreak) was detected (advisory only).
  integrityRisk,
}

/// Internal helper: parse an enum value from its [Enum.name], with a fallback.
///
/// Kept package-private via the `src` layout; used by model deserialization.
T enumFromName<T extends Enum>(List<T> values, Object? name, T fallback) {
  if (name is! String) return fallback;
  for (final value in values) {
    if (value.name == name) return value;
  }
  return fallback;
}
