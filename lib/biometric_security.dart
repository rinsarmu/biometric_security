/// A unified, developer-friendly security layer for Flutter that combines
/// biometric authentication, hardware-backed key management, and biometric-gated
/// encrypted storage.
///
/// This is the single public entry point. Import it and use [BiometricSecurity]
/// together with [SecurityPolicy].
///
/// ```dart
/// import 'package:biometric_security/biometric_security.dart';
///
/// final security = BiometricSecurity();
/// await security.initialize();
/// final availability = await security.getAvailability();
/// ```
library;

export 'src/biometric_security_base.dart'
    show BiometricSecurity, AppLock, FeatureProtection;
export 'src/enums.dart'
    show
        BiometricModality,
        BiometricStrength,
        BiometricStatus,
        DeviceCredentialFallback,
        EnrollmentBinding,
        AuthValidity,
        HardwareRequirement,
        StorageAccessibility,
        SecurityLevel,
        KeyLifecycleEventType;
export 'src/exceptions.dart';
export 'src/models.dart'
    show
        BiometricSecurityConfig,
        EnforceableGuarantees,
        BiometricAvailability,
        SecurityStatus,
        KeyLifecycleEvent;
export 'src/policy.dart' show SecurityPolicy;
export 'src/results.dart' show AuthSession, SignatureResult;
export 'src/secret_key.dart' show SecretKey;

// The platform interface is exported for federated platform implementations and
// for tests; app code should not need it.
export 'src/platform/platform_interface.dart' show BiometricSecurityPlatform;
