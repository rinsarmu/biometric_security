import Foundation
import LocalAuthentication
import Security

/// Secure storage backed by the iOS Keychain.
///
/// Design:
/// - A **secret item** (`sec:<key>`) holds the value. When gated, it carries a
/// `SecAccessControl` requiring biometrics (`biometryCurrentSet` /
/// `biometryAny`), so the OS only releases the data after a successful
/// biometric evaluation. The Keychain encrypts data at rest with
/// hardware keys — nothing sensitive is stored in UserDefaults, plain files,
/// or SQLite.
/// - A companion **meta item** (`meta:<key>`, never gated) records whether the
/// secret is gated, its enrollment binding, and the biometric domain-state
/// fingerprint captured at write time. This lets `read` detect an enrollment
/// change *before* prompting (deterministic invalidation for
/// `biometryCurrentSet` items) and lets `keys()`/`contains()` work without a
/// prompt.
///
/// All values use a `ThisDeviceOnly` protection class, so secrets are excluded
/// from iCloud/iTunes backups and device migration.
final class KeychainStore {

    private let service: String

    init(namespace: String) {
        self.service = "bsec.\(namespace)"
    }

    struct Meta {
        let gated: Bool
        let invalidateOnEnrollment: Bool
        let domainState: String?
    }

    // MARK: - Public API

    func put(key: String, value: Data, policy: PolicyConfig) throws {
        // Overwrite semantics: delete first (delete never requires auth).
        removeRaw(account: secretAccount(key))
        removeRaw(account: metaAccount(key))

        if policy.requiresAuthentication {
            let access = try policy.makeAccessControl(privateKeyUsage: false)
            try addRaw(
                account: secretAccount(key), data: value, accessControl: access,
                accessible: nil)
            let domain = policy.invalidateOnEnrollment ? Self.currentDomainState(): nil
            try writeMeta(
                key: key,
                meta: Meta(
                    gated: true,
                    invalidateOnEnrollment: policy.invalidateOnEnrollment,
                    domainState: domain))
        } else {
            try addRaw(
                account: secretAccount(key), data: value, accessControl: nil,
                accessible: policy.protectionClass)
            try writeMeta(
                key: key,
                meta: Meta(gated: false, invalidateOnEnrollment: false, domainState: nil))
        }
    }

    /// Reads the value for `key`, prompting only when the secret is gated.
    /// Returns nil if the key does not exist. Throws `keyInvalidated` when a
    /// `biometryCurrentSet` item's enrollment has changed since it was written.
    func read(key: String, reason: String) throws -> Data? {
        guard let meta = readMeta(key: key) else { return nil }

        if !meta.gated {
            return try getRaw(account: secretAccount(key), context: nil)
        }

        if meta.invalidateOnEnrollment {
            let current = Self.currentDomainState()
            if meta.domainState != current {
                throw PluginError(
                    SecurityCodes.keyInvalidated,
                    "The enrolled biometrics changed; this item is no longer accessible.")
            }
        }

        let context = LAContext()
        context.localizedReason = reason
        return try getRaw(account: secretAccount(key), context: context)
    }

    func contains(key: String) -> Bool {
        readMeta(key: key) != nil
    }

    func keys() -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
            let items = out as? [[String: Any]]
        else { return [] }
        return items.compactMap { item -> String? in
            guard let account = item[kSecAttrAccount as String] as? String,
                account.hasPrefix(Self.metaPrefix)
            else { return nil }
            return String(account.dropFirst(Self.metaPrefix.count))
        }
    }

    func remove(key: String) {
        removeRaw(account: secretAccount(key))
        removeRaw(account: metaAccount(key))
    }

    func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Raw data helpers (also used by SecureEnclaveAuth for its key blob)

    func addRaw(
        account: String, data: Data, accessControl: SecAccessControl?, accessible: CFString?
    ) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
        ]
        if let accessControl = accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        } else if let accessible = accessible {
            query[kSecAttrAccessible as String] = accessible
        }
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw ErrorMapper.fromOSStatus(status) }
    }

    func getRaw(account: String, context: LAContext?) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ErrorMapper.fromOSStatus(status) }
        return out as? Data
    }

    func removeRaw(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Metadata

    private func writeMeta(key: String, meta: Meta) throws {
        var dict: [String: Any] = [
            "gated": meta.gated,
            "invalidateOnEnrollment": meta.invalidateOnEnrollment,
        ]
        if let domain = meta.domainState { dict["domainState"] = domain }
        let data = try JSONSerialization.data(withJSONObject: dict)
        try addRaw(
            account: metaAccount(key), data: data, accessControl: nil,
            accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }

    private func readMeta(key: String) -> Meta? {
        guard let data = try? getRaw(account: metaAccount(key), context: nil),
            let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return Meta(
            gated: dict["gated"] as? Bool ?? false,
            invalidateOnEnrollment: dict["invalidateOnEnrollment"] as? Bool ?? false,
            domainState: dict["domainState"] as? String)
    }

    // MARK: - Helpers

    static func currentDomainState() -> String? {
        let context = LAContext()
        _ = context.canEvaluatePolicy(
.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.evaluatedPolicyDomainState?.base64EncodedString()
    }

    private static let metaPrefix = "meta:"
    private func secretAccount(_ key: String) -> String { "sec:\(key)" }
    private func metaAccount(_ key: String) -> String { "\(Self.metaPrefix)\(key)" }
}
