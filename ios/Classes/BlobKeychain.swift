import Foundation
import Security

/// Opaque ciphertext-blob persistence in the Keychain.
///
/// Blobs are already AES-256-GCM-encrypted by the Dart engine (the DEK lives in
/// a biometric-gated Keychain entry), so these items are non-gated and hold only
/// ciphertext — never key material (INV-2). They use a dedicated service so they
/// never mix with the DEK/key store, and a `ThisDeviceOnly` protection class so
/// they are excluded from backups and device migration (INV-5).
final class BlobKeychain {

    private let service: String

    init(namespace: String) {
        self.service = "bsec.\(namespace).blobs"
    }

    func put(key: String, data: Data) {
        remove(key: key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func get(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else {
            return nil
        }
        return out as? Data
    }

    func remove(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
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
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
