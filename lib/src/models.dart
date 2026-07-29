/// Data models and status objects for the public API.
library;

import 'enums.dart';
import 'policy.dart';

/// One-time configuration for a [BiometricSecurity] instance.
class BiometricSecurityConfig {
  /// The default policy applied when a call omits its own.
  final SecurityPolicy defaultPolicy;

  /// A namespace so multiple logical stores do not collide. Maps to the
  /// key-alias scope used by the native key stores.
  final String namespace;

  /// Whether to emit [KeyLifecycleEventType.integrityRisk] events from
  /// best-effort root/jailbreak heuristics.
  final bool enableIntegritySignals;

  /// Creates a configuration with secure defaults.
  const BiometricSecurityConfig({
    this.defaultPolicy = const SecurityPolicy(),
    this.namespace = 'default',
    this.enableIntegritySignals = false,
  });

  /// Serializes this configuration for the platform channel.
  Map<String, Object?> toMap() => {
    'defaultPolicy': defaultPolicy.toMap(),
    'namespace': namespace,
    'enableIntegritySignals': enableIntegritySignals,
  };
}

/// A report of what the current device can actually enforce.
///
/// There is deliberately **no** `guaranteedModality` field, because neither
/// Android nor iOS can promise a specific biometric modality.
class EnforceableGuarantees {
  /// Whether a minimum biometric strength can be enforced (Android Class 3;
  /// iOS biometrics are strong by default).
  final bool canEnforceStrength;

  /// Whether a key can be made physically unusable without authentication.
  /// True on both platforms.
  final bool canBindKeyToAuthentication;

  /// Whether keys can be invalidated when the enrolled biometrics change.
  final bool canInvalidateOnEnrollmentChange;

  /// Always `false` — documented so callers never build UX on a false promise.
  final bool canForceSpecificModality;

  /// Creates a guarantees report. [canForceSpecificModality] defaults to
  /// `false` and should never be `true`.
  const EnforceableGuarantees({
    required this.canEnforceStrength,
    required this.canBindKeyToAuthentication,
    required this.canInvalidateOnEnrollmentChange,
    this.canForceSpecificModality = false,
  });

  /// Deserializes from a platform-channel map.
  factory EnforceableGuarantees.fromMap(Map<Object?, Object?> map) {
    return EnforceableGuarantees(
      canEnforceStrength: map['canEnforceStrength'] as bool? ?? false,
      canBindKeyToAuthentication:
          map['canBindKeyToAuthentication'] as bool? ?? false,
      canInvalidateOnEnrollmentChange:
          map['canInvalidateOnEnrollmentChange'] as bool? ?? false,
      canForceSpecificModality: false,
    );
  }
}

/// Answers the "supported / enrolled / available" questions of the five-way
/// biometric distinction.
class BiometricAvailability {
  /// Whether the device has any biometric hardware.
  final bool isSupported;

  /// Sensor families physically present on this device ("supported").
  final Set<BiometricModality> supportedModalities;

  /// Modalities the user has actually enrolled ("enrolled").
  final Set<BiometricModality> enrolledModalities;

  /// The strongest strength class currently enrolled.
  final BiometricStrength strength;

  /// Whether authentication can succeed right now ("available").
  final bool canAuthenticate;

  /// The precise reason when [canAuthenticate] is `false`.
  final BiometricStatus status;

  /// What this device can actually enforce.
  final EnforceableGuarantees guarantees;

  /// Whether Android StrongBox is present.
  final bool hasStrongBox;

  /// Whether an iOS Secure Enclave is present.
  final bool hasSecureEnclave;

  /// Creates an availability snapshot.
  const BiometricAvailability({
    required this.isSupported,
    required this.supportedModalities,
    required this.enrolledModalities,
    required this.strength,
    required this.canAuthenticate,
    required this.status,
    required this.guarantees,
    required this.hasStrongBox,
    required this.hasSecureEnclave,
  });

  /// An "unavailable/unknown" snapshot used before the platform reports state.
  const BiometricAvailability.unknown()
    : isSupported = false,
      supportedModalities = const {},
      enrolledModalities = const {},
      strength = BiometricStrength.none,
      canAuthenticate = false,
      status = BiometricStatus.unknown,
      guarantees = const EnforceableGuarantees(
        canEnforceStrength: false,
        canBindKeyToAuthentication: false,
        canInvalidateOnEnrollmentChange: false,
      ),
      hasStrongBox = false,
      hasSecureEnclave = false;

  /// Deserializes from a platform-channel map.
  factory BiometricAvailability.fromMap(Map<Object?, Object?> map) {
    Set<BiometricModality> parseModalities(Object? raw) {
      if (raw is! List) return const {};
      return raw
          .map(
            (e) => enumFromName(
              BiometricModality.values,
              e,
              BiometricModality.unknown,
            ),
          )
          .toSet();
    }

    return BiometricAvailability(
      isSupported: map['isSupported'] as bool? ?? false,
      supportedModalities: parseModalities(map['supportedModalities']),
      enrolledModalities: parseModalities(map['enrolledModalities']),
      strength: enumFromName(
        BiometricStrength.values,
        map['strength'],
        BiometricStrength.none,
      ),
      canAuthenticate: map['canAuthenticate'] as bool? ?? false,
      status: enumFromName(
        BiometricStatus.values,
        map['status'],
        BiometricStatus.unknown,
      ),
      guarantees: EnforceableGuarantees.fromMap(
        (map['guarantees'] as Map<Object?, Object?>?) ?? const {},
      ),
      hasStrongBox: map['hasStrongBox'] as bool? ?? false,
      hasSecureEnclave: map['hasSecureEnclave'] as bool? ?? false,
    );
  }
}

/// A one-call health snapshot of the protection subsystem.
class SecurityStatus {
  /// Current biometric availability.
  final BiometricAvailability availability;

  /// The highest security level the device can back keys with.
  final SecurityLevel achievableSecurityLevel;

  /// Whether any known scope is currently invalidated and awaiting reprovision.
  final bool reprovisionRequired;

  /// Advisory device-integrity assessment (best effort, never a guarantee).
  final bool integrityRisk;

  /// Creates a security-status snapshot.
  const SecurityStatus({
    required this.availability,
    required this.achievableSecurityLevel,
    required this.reprovisionRequired,
    required this.integrityRisk,
  });

  /// Deserializes from a platform-channel map.
  factory SecurityStatus.fromMap(Map<Object?, Object?> map) {
    return SecurityStatus(
      availability: BiometricAvailability.fromMap(
        (map['availability'] as Map<Object?, Object?>?) ?? const {},
      ),
      achievableSecurityLevel: enumFromName(
        SecurityLevel.values,
        map['achievableSecurityLevel'],
        SecurityLevel.none,
      ),
      reprovisionRequired: map['reprovisionRequired'] as bool? ?? false,
      integrityRisk: map['integrityRisk'] as bool? ?? false,
    );
  }
}

/// A lifecycle event emitted on [BiometricSecurity.lifecycleEvents].
///
/// Advisory only — the package never takes destructive action on its own.
class KeyLifecycleEvent {
  /// The kind of event.
  final KeyLifecycleEventType type;

  /// The affected protection scope, app-lock, or feature, if applicable.
  final String? scope;

  /// A human-readable description.
  final String message;

  /// Creates a lifecycle event.
  const KeyLifecycleEvent({
    required this.type,
    this.scope,
    required this.message,
  });

  /// Deserializes from a platform-channel map.
  factory KeyLifecycleEvent.fromMap(Map<Object?, Object?> map) {
    return KeyLifecycleEvent(
      type: enumFromName(
        KeyLifecycleEventType.values,
        map['type'],
        KeyLifecycleEventType.enrollmentChanged,
      ),
      scope: map['scope'] as String?,
      message: map['message'] as String? ?? '',
    );
  }
}
