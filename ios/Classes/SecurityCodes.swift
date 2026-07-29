import Foundation
import LocalAuthentication
import Security

/// The error-code contract shared with the Dart layer.
///
/// Every value here maps 1:1 to a typed `BiometricSecurityException` subtype in
/// `lib/src/platform/method_channel.dart` (`mapPlatformException`). Raw iOS
/// statuses (`OSStatus`, `LAError`) are never surfaced across the channel; they
/// are translated into one of these codes first.
enum SecurityCodes {
    static let authCanceled = "auth_canceled"
    static let authFailed = "auth_failed"
    static let lockedOut = "locked_out"
    static let lockedOutPermanent = "locked_out_permanent"
    static let unavailable = "unavailable"
    static let notEnrolled = "not_enrolled"
    static let keyInvalidated = "key_invalidated"
    static let enrollmentChanged = "enrollment_changed"
    static let storageError = "storage_error"
    static let cryptoError = "crypto_error"
    static let policyUnsupported = "policy_unsupported"
    static let notInitialized = "not_initialized"
}

/// A translated, channel-safe failure carrying a `SecurityCodes` value and a
/// human-readable message. The original cause is never sent across the channel.
struct PluginError: Error {
    let code: String
    let message: String

    init(_ code: String, _ message: String) {
        self.code = code
        self.message = message
    }
}

enum ErrorMapper {
    /// Translates a Keychain `OSStatus` to the shared contract.
    static func fromOSStatus(_ status: OSStatus) -> PluginError {
        switch status {
        case errSecUserCanceled:
            return PluginError(SecurityCodes.authCanceled, "Authentication was canceled.")
        case errSecAuthFailed:
            return PluginError(SecurityCodes.authFailed, "Authentication failed.")
        case errSecInteractionNotAllowed:
            return PluginError(
                SecurityCodes.unavailable,
                "The item is not accessible while the device is locked.")
        case errSecNotAvailable:
            return PluginError(
                SecurityCodes.unavailable, "Keychain is not available.")
        default:
            let message = SecCopyErrorMessageString(status, nil) as String?
            return PluginError(
                SecurityCodes.storageError,
                message ?? "Keychain error (\(status)).")
        }
    }

    /// Translates an `LAError`/`NSError` from LocalAuthentication or Secure
    /// Enclave signing to the shared contract.
    static func fromAuthError(_ error: Error) -> PluginError {
        let nsError = error as NSError
        guard nsError.domain == LAError.errorDomain,
            let code = LAError.Code(rawValue: nsError.code)
        else {
            return PluginError(
                SecurityCodes.authFailed, nsError.localizedDescription)
        }
        switch code {
        case.userCancel, .appCancel, .systemCancel:
            return PluginError(SecurityCodes.authCanceled, "Authentication was canceled.")
        case.authenticationFailed:
            return PluginError(SecurityCodes.authFailed, "Authentication failed.")
        case.userFallback:
            return PluginError(
                SecurityCodes.authFailed, "The user chose the fallback option.")
        case.biometryLockout:
            return PluginError(
                SecurityCodes.lockedOut,
                "Biometrics are locked. Unlock with your device passcode.")
        case.biometryNotEnrolled:
            return PluginError(SecurityCodes.notEnrolled, "No biometric is enrolled.")
        case.biometryNotAvailable:
            return PluginError(
                SecurityCodes.unavailable, "Biometric authentication is unavailable.")
        case.passcodeNotSet:
            return PluginError(
                SecurityCodes.unavailable, "No device passcode is set.")
        case.invalidContext, .notInteractive:
            return PluginError(
                SecurityCodes.unavailable, "Authentication context is unavailable.")
        default:
            return PluginError(SecurityCodes.authFailed, nsError.localizedDescription)
        }
    }
}
