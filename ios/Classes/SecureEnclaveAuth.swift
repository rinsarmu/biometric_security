import CryptoKit
import Foundation
import LocalAuthentication

/// Implements `authenticate()` with the strongest practical mechanism.
///
/// When a Secure Enclave is present, it uses a biometric-gated Secure Enclave
/// P-256 signing key and proves authentication by signing a constant (INV-1: the
/// key is physically unusable without a successful biometric evaluation, so a
/// forged "success" cannot produce a valid signature). The key's persisted
/// `dataRepresentation` is a Secure-Enclave-wrapped blob — the private key never
/// leaves the Enclave and is never exposed to Dart (INV-2).
///
/// On devices without a Secure Enclave (e.g. the simulator), it falls back to a
/// LocalAuthentication policy evaluation, which is a weaker presence check — this
/// is documented rather than pretended away.
final class SecureEnclaveAuth {

    private let store: KeychainStore
    private static let proof = Data("biometric_security.auth".utf8)

    init(store: KeychainStore) {
        self.store = store
    }

    /// Runs the prompt and returns the Dart `AuthSession` map. Blocks the calling
    /// thread on biometric UI, so it must be called off the main thread.
    func authenticate(scope: String, policy: PolicyConfig, reason: String) throws
        -> [String: Any?]
    {
        if SecureEnclave.isAvailable {
            return try secureEnclaveSign(scope: scope, policy: policy, reason: reason)
        }
        // Enforce the policy: do not silently downgrade to the weaker,
        // presence-only LocalAuthentication path when the caller demanded secure
        // hardware (SECURITY_AUDIT.md H-2).
        if policy.requireSecureHardware {
            throw PluginError(
                SecurityCodes.policyUnsupported,
                "Secure hardware (Secure Enclave) was required but is not available.")
        }
        return try localAuthFallback(policy: policy, reason: reason)
    }

    /// Removes a scope's Secure Enclave key blob so it can be reprovisioned.
    func reset(scope: String) {
        store.removeRaw(account: keyAccount(scope))
    }

    // MARK: - Secure Enclave path

    private func secureEnclaveSign(scope: String, policy: PolicyConfig, reason: String)
        throws -> [String: Any?]
    {
        let context = LAContext()
        context.localizedReason = reason

        // Whether we are reusing a previously-provisioned key. A failure to use an
        // *existing* Secure Enclave key almost always means it was invalidated by a
        // biometric-enrollment change (iOS reports this as a generic CryptoTokenKit
        // error, not an LAError). See SECURITY_AUDIT.md M-4.
        let hadExistingKey = ((try? store.getRaw(account: keyAccount(scope), context: nil)) ?? nil) != nil

        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try loadOrCreateKey(scope: scope, policy: policy, context: context)
        } catch let error as PluginError {
            throw error
        } catch {
            throw mapSigningError(error, hadExistingKey: hadExistingKey, scope: scope)
        }

        do {
            let signature = try key.signature(for: Self.proof)
            return [
                "token": signature.rawRepresentation.base64EncodedString(),
                "authenticatedAtMs": Int(Date().timeIntervalSince1970 * 1000),
                // iOS does not report which modality performed the match.
                "usedModality": nil,
                "securityLevel": "secureEnclave",
            ]
        } catch {
            throw mapSigningError(error, hadExistingKey: hadExistingKey, scope: scope)
        }
    }

    /// Translates a Secure Enclave reconstruction/signing failure.
    ///
    /// Genuine LocalAuthentication outcomes (cancel, lockout, mismatch) are mapped
    /// as-is. A non-LAError failure on a *previously-provisioned* auth key is
    /// treated as invalidation: because the auth key protects no stored secret, we
    /// delete it (self-heal) so the next `authenticate()` re-provisions, and report
    /// a clean `KeyInvalidatedException` instead of a confusing `authFailed`.
    private func mapSigningError(_ error: Error, hadExistingKey: Bool, scope: String)
        -> PluginError
    {
        let nsError = error as NSError
        if nsError.domain == LAError.errorDomain {
            return ErrorMapper.fromAuthError(error)
        }
        if hadExistingKey {
            reset(scope: scope)  // clear the dead key; next authenticate() re-provisions
            return PluginError(
                SecurityCodes.keyInvalidated,
                "The authentication key was invalidated by a biometric change. "
                    + "Authenticate again to re-provision.")
        }
        return ErrorMapper.fromAuthError(error)
    }

    private func loadOrCreateKey(
        scope: String, policy: PolicyConfig, context: LAContext
    ) throws -> SecureEnclave.P256.Signing.PrivateKey {
        if let blob = try store.getRaw(account: keyAccount(scope), context: nil) {
            return try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob, authenticationContext: context)
        }
        let access = try policy.makeAccessControl(privateKeyUsage: true)
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: access, authenticationContext: context)
        // The blob is Secure-Enclave-wrapped and safe to persist in the Keychain.
        try store.addRaw(
            account: keyAccount(scope), data: key.dataRepresentation,
            accessControl: nil, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        return key
    }

    // MARK: - Fallback (no Secure Enclave)

    private func localAuthFallback(policy: PolicyConfig, reason: String) throws
        -> [String: Any?]
    {
        let context = LAContext()
        let laPolicy: LAPolicy =
            policy.deviceCredentialFallback
            ? .deviceOwnerAuthentication : .deviceOwnerAuthenticationWithBiometrics

        var evalError: Error?
        let semaphore = DispatchSemaphore(value: 0)
        context.evaluatePolicy(laPolicy, localizedReason: reason) { success, error in
            if !success { evalError = error }
            semaphore.signal()
        }
        semaphore.wait()

        if let evalError = evalError {
            throw ErrorMapper.fromAuthError(evalError)
        }
        return [
            "token": "presence",
            "authenticatedAtMs": Int(Date().timeIntervalSince1970 * 1000),
            "usedModality": nil,
            "securityLevel": "software",
        ]
    }

    private func keyAccount(_ scope: String) -> String { "se:\(scope)" }
}
