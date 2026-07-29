import CryptoKit
import Foundation
import LocalAuthentication

/// Read-only biometric capability detection via LocalAuthentication.
///
/// Answers the "supported / enrolled / available" questions of the five-way
/// distinction. Unlike Android, iOS *can* report the enrolled
/// modality (a device has a single biometric family), so `enrolledModalities`
/// is populated when a biometric is enrolled.
enum Capabilities {

    static func availabilityMap() -> [String: Any?] {
        let context = LAContext()
        var authError: NSError?
        let canBiometric = context.canEvaluatePolicy(
.deviceOwnerAuthenticationWithBiometrics, error: &authError)
        let modality = modalityString(context.biometryType)
        let hasHardware = context.biometryType != .none

        let strength = canBiometric ? "strong" : "none"
        let status = mapStatus(canBiometric: canBiometric, error: authError, context: context)

        return [
            "isSupported": hasHardware,
            "supportedModalities": modality.map { [$0] } ?? [],
            "enrolledModalities": (canBiometric ? modality.map { [$0] }: []) ?? [],
            "strength": strength,
            "canAuthenticate": canBiometric,
            "status": status,
            "guarantees": guaranteesMap(),
            "hasStrongBox": false,
            "hasSecureEnclave": SecureEnclave.isAvailable,
        ]
    }

    static func securityStatusMap() -> [String: Any?] {
        [
            "availability": availabilityMap(),
            "achievableSecurityLevel": SecureEnclave.isAvailable ? "secureEnclave" : "software",
            "reprovisionRequired": false,
            "integrityRisk": false,
        ]
    }

    private static func modalityString(_ type: LABiometryType) -> String? {
        switch type {
        case.faceID: return "face"
        case.touchID: return "fingerprint"
        case.none: return nil
        default:
            //.opticID (Vision Pro) and any future types.
            return "unknown"
        }
    }

    private static func mapStatus(
        canBiometric: Bool, error: NSError?, context: LAContext
    ) -> String {
        if canBiometric { return "ready" }
        guard let error = error, let code = LAError.Code(rawValue: error.code) else {
            return "unknown"
        }
        switch code {
        case.biometryNotEnrolled:
            return "notEnrolled"
        case.biometryNotAvailable:
            return context.biometryType == .none ? "noHardware" : "hardwareUnavailable"
        case.passcodeNotSet:
            return "noDeviceCredential"
        case.biometryLockout:
            return "lockedOut"
        default:
            return "unknown"
        }
    }

    private static func guaranteesMap() -> [String: Any?] {
        [
            "canEnforceStrength": true,
            "canBindKeyToAuthentication": true,
            "canInvalidateOnEnrollmentChange": true,
            // Never true: iOS cannot force a specific modality.
            "canForceSpecificModality": false,
        ]
    }
}
