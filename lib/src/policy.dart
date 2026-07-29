/// The platform-independent expression of security intent.
library;

import 'enums.dart';

/// A single, platform-independent description of how a secret or an
/// authentication should be protected.
///
/// One policy type drives both authentication and storage so developers learn
/// it once. It is secure-by-default: the unnamed constructor is the strongest
/// sensible policy, and weaker behavior must be requested explicitly.
class SecurityPolicy {
  /// Minimum biometric strength. [BiometricStrength.strong] is required to
  /// cryptographically gate a key.
  final BiometricStrength minimumStrength;

  /// Whether a device credential may satisfy the gate.
  final DeviceCredentialFallback deviceCredentialFallback;

  /// What happens to protected data when the enrolled biometrics change.
  final EnrollmentBinding enrollmentBinding;

  /// Per-operation auth (default) versus a reuse window.
  final AuthValidity authValidity;

  /// The reuse window; only meaningful when [authValidity] is
  /// [AuthValidity.window].
  final Duration authWindow;

  /// Whether secure hardware is required or preferred.
  final HardwareRequirement hardwareRequirement;

  /// Backup/migration exposure of encrypted data at rest.
  final StorageAccessibility accessibility;

  /// Advisory modality hint only. The OS may ignore it entirely.
  final BiometricModality? preferredModality;

  /// Require an explicit confirmation tap after a biometric match.
  final bool requireConfirmation;

  /// Creates a policy. Defaults are the strongest sensible values:
  /// strong · no fallback · invalidate-on-enrollment · per-operation ·
  /// prefer strongest hardware · this-device-only.
  const SecurityPolicy({
    this.minimumStrength = BiometricStrength.strong,
    this.deviceCredentialFallback = DeviceCredentialFallback.disallow,
    this.enrollmentBinding = EnrollmentBinding.invalidateOnChange,
    this.authValidity = AuthValidity.perOperation,
    this.authWindow = Duration.zero,
    this.hardwareRequirement = HardwareRequirement.preferStrongestAvailable,
    this.accessibility = StorageAccessibility.whenUnlockedThisDeviceOnly,
    this.preferredModality,
    this.requireConfirmation = false,
  });

  /// Maximum security. Equivalent to the default constructor. Use for
  /// high-value secrets.
  const SecurityPolicy.strong() : this();

  /// Keeps strong biometrics but survives new enrollments and allows a short
  /// reuse window. Good for frequently-accessed, medium-value data.
  const SecurityPolicy.balanced()
    : this(
        enrollmentBinding: EnrollmentBinding.persistAcrossEnrollment,
        authValidity: AuthValidity.window,
        authWindow: const Duration(seconds: 30),
      );

  /// Allows device-credential fallback so users are never hard locked out.
  /// Weaker: such keys are not enrollment-invalidated.
  const SecurityPolicy.convenient()
    : this(
        deviceCredentialFallback: DeviceCredentialFallback.allow,
        enrollmentBinding: EnrollmentBinding.persistAcrossEnrollment,
      );

  /// Encryption-at-rest only, with no biometric gate. Reads and writes do not
  /// prompt. For non-sensitive configuration data.
  const SecurityPolicy.encryptedOnly()
    : this(minimumStrength: BiometricStrength.none);

  /// Whether this policy requires a biometric (or credential) prompt at all.
  ///
  /// False for [SecurityPolicy.encryptedOnly].
  bool get requiresAuthentication => minimumStrength != BiometricStrength.none;

  /// Returns a copy with the given fields replaced.
  SecurityPolicy copyWith({
    BiometricStrength? minimumStrength,
    DeviceCredentialFallback? deviceCredentialFallback,
    EnrollmentBinding? enrollmentBinding,
    AuthValidity? authValidity,
    Duration? authWindow,
    HardwareRequirement? hardwareRequirement,
    StorageAccessibility? accessibility,
    BiometricModality? preferredModality,
    bool? requireConfirmation,
  }) {
    return SecurityPolicy(
      minimumStrength: minimumStrength ?? this.minimumStrength,
      deviceCredentialFallback:
          deviceCredentialFallback ?? this.deviceCredentialFallback,
      enrollmentBinding: enrollmentBinding ?? this.enrollmentBinding,
      authValidity: authValidity ?? this.authValidity,
      authWindow: authWindow ?? this.authWindow,
      hardwareRequirement: hardwareRequirement ?? this.hardwareRequirement,
      accessibility: accessibility ?? this.accessibility,
      preferredModality: preferredModality ?? this.preferredModality,
      requireConfirmation: requireConfirmation ?? this.requireConfirmation,
    );
  }

  /// Serializes this policy for the platform channel.
  Map<String, Object?> toMap() => {
    'minimumStrength': minimumStrength.name,
    'deviceCredentialFallback': deviceCredentialFallback.name,
    'enrollmentBinding': enrollmentBinding.name,
    'authValidity': authValidity.name,
    'authWindowSeconds': authWindow.inSeconds,
    'hardwareRequirement': hardwareRequirement.name,
    'accessibility': accessibility.name,
    'preferredModality': preferredModality?.name,
    'requireConfirmation': requireConfirmation,
  };

  /// Deserializes a policy from a platform-channel map.
  factory SecurityPolicy.fromMap(Map<Object?, Object?> map) {
    return SecurityPolicy(
      minimumStrength: enumFromName(
        BiometricStrength.values,
        map['minimumStrength'],
        BiometricStrength.strong,
      ),
      deviceCredentialFallback: enumFromName(
        DeviceCredentialFallback.values,
        map['deviceCredentialFallback'],
        DeviceCredentialFallback.disallow,
      ),
      enrollmentBinding: enumFromName(
        EnrollmentBinding.values,
        map['enrollmentBinding'],
        EnrollmentBinding.invalidateOnChange,
      ),
      authValidity: enumFromName(
        AuthValidity.values,
        map['authValidity'],
        AuthValidity.perOperation,
      ),
      authWindow: Duration(
        seconds: (map['authWindowSeconds'] as num?)?.toInt() ?? 0,
      ),
      hardwareRequirement: enumFromName(
        HardwareRequirement.values,
        map['hardwareRequirement'],
        HardwareRequirement.preferStrongestAvailable,
      ),
      accessibility: enumFromName(
        StorageAccessibility.values,
        map['accessibility'],
        StorageAccessibility.whenUnlockedThisDeviceOnly,
      ),
      preferredModality: map['preferredModality'] == null
          ? null
          : enumFromName(
              BiometricModality.values,
              map['preferredModality'],
              BiometricModality.unknown,
            ),
      requireConfirmation: map['requireConfirmation'] as bool? ?? false,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is SecurityPolicy &&
      other.minimumStrength == minimumStrength &&
      other.deviceCredentialFallback == deviceCredentialFallback &&
      other.enrollmentBinding == enrollmentBinding &&
      other.authValidity == authValidity &&
      other.authWindow == authWindow &&
      other.hardwareRequirement == hardwareRequirement &&
      other.accessibility == accessibility &&
      other.preferredModality == preferredModality &&
      other.requireConfirmation == requireConfirmation;

  @override
  int get hashCode => Object.hash(
    minimumStrength,
    deviceCredentialFallback,
    enrollmentBinding,
    authValidity,
    authWindow,
    hardwareRequirement,
    accessibility,
    preferredModality,
    requireConfirmation,
  );
}
