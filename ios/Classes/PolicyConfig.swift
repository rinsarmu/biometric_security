import Foundation
import Security

/// The iOS-side parsed form of a Dart `SecurityPolicy`.
///
/// Holds the platform-independent intent and maps it to the concrete
/// `SecAccessControl` flags and Keychain protection class used by
/// `KeychainStore` and `SecureEnclaveAuth` (ARCHITECTURE.md DR-2, §11).
struct PolicyConfig: Equatable {
    let minimumStrength: String
    let deviceCredentialFallback: Bool
    /// When true, protected data is bound to the *current* biometric set
    /// (`biometryCurrentSet`); when false it persists across enrollment changes
    /// (`biometryAny`).
    let invalidateOnEnrollment: Bool
    let requireSecureHardware: Bool
    let afterFirstUnlock: Bool

    var requiresAuthentication: Bool { minimumStrength != "none" }

    static func secureDefault() -> PolicyConfig {
        PolicyConfig(
            minimumStrength: "strong",
            deviceCredentialFallback: false,
            invalidateOnEnrollment: true,
            requireSecureHardware: false,
            afterFirstUnlock: false)
    }

    static func from(_ map: [String: Any?]?) -> PolicyConfig {
        guard let map = map else { return secureDefault() }
        let d = secureDefault()
        let strength = (map["minimumStrength"] as? String) ?? d.minimumStrength
        let fallback = (map["deviceCredentialFallback"] as? String) == "allow"
        let binding = (map["enrollmentBinding"] as? String) ?? "invalidateOnChange"
        let hardware = (map["hardwareRequirement"] as? String) == "requireSecureHardware"
        let accessibility = (map["accessibility"] as? String) ?? "whenUnlockedThisDeviceOnly"
        return PolicyConfig(
            minimumStrength: strength,
            deviceCredentialFallback: fallback,
            invalidateOnEnrollment: binding == "invalidateOnChange",
            requireSecureHardware: hardware,
            afterFirstUnlock: accessibility == "afterFirstUnlockThisDeviceOnly")
    }

    /// The Keychain protection class. `ThisDeviceOnly` variants are excluded
    /// from backups and device migration (INV-5).
    var protectionClass: CFString {
        afterFirstUnlock
            ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    /// Builds a `SecAccessControl` for a biometric-gated item or key.
    ///
    /// - `biometryCurrentSet` vs `biometryAny` comes from `invalidateOnEnrollment`.
    /// - `devicePasscode` is added (via `.or`) only when fallback is allowed.
    /// - `privateKeyUsage` is added for Secure Enclave keys.
    func makeAccessControl(privateKeyUsage: Bool) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags =
            invalidateOnEnrollment ? .biometryCurrentSet : .biometryAny
        if deviceCredentialFallback {
            flags.insert(.or)
            flags.insert(.devicePasscode)
        }
        if privateKeyUsage {
            flags.insert(.privateKeyUsage)
        }
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, protectionClass, flags, &error)
        else {
            let message =
                (error?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String }
                ?? "Could not create access control."
            throw PluginError(SecurityCodes.policyUnsupported, message)
        }
        return access
    }
}
