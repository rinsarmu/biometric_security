import Flutter
import LocalAuthentication
import UIKit

/// iOS implementation of the `biometric_security` plugin.
///
/// Orchestrates capability detection ([Capabilities]), biometric-gated Keychain
/// storage ([KeychainStore]), and Secure Enclave authentication
/// ([SecureEnclaveAuth]).
///
/// Threading: gated reads and authentication block on the biometric UI, so they
/// run on a background queue; their `FlutterResult` is delivered back on the main
/// queue. A single-flight guard serializes prompts (ARCHITECTURE.md §19).
///
/// Error handling: every failure is translated to a [SecurityCodes] value via
/// [ErrorMapper]; raw `OSStatus`/`LAError` values never cross the channel.
public class BiometricSecurityPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private var eventSink: FlutterEventSink?
    private var namespace = "default"
    private var authInProgress = false
    private let workQueue = DispatchQueue(label: "biometric_security.work", qos: .userInitiated)

    private lazy var store = KeychainStore(namespace: namespace)
    private lazy var auth = SecureEnclaveAuth(store: store)
    private lazy var blobs = BlobKeychain(namespace: namespace)

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "biometric_security", binaryMessenger: registrar.messenger())
        let eventChannel = FlutterEventChannel(
            name: "biometric_security/events", binaryMessenger: registrar.messenger())
        let instance = BiometricSecurityPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        eventChannel.setStreamHandler(instance)
    }

    // MARK: - Method routing

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any?]
        do {
            switch call.method {
            case "initialize":
                namespace = (args?["namespace"] as? String) ?? "default"
                store = KeychainStore(namespace: namespace)
                auth = SecureEnclaveAuth(store: store)
                blobs = BlobKeychain(namespace: namespace)
                result(nil)
            case "getAvailability":
                result(Capabilities.availabilityMap())
            case "getSecurityStatus":
                result(Capabilities.securityStatusMap())
            case "authenticate":
                try handleAuthenticate(args, result)
            case "write":
                try handleWrite(args, result)
            case "read":
                try handleRead(args, result)
            case "delete":
                store.remove(key: try requireKey(args))
                result(nil)
            case "deleteAll":
                store.clear()
                result(nil)
            case "contains":
                result(store.contains(key: try requireKey(args)))
            case "keys":
                result(store.keys())
            case "revoke":
                store.remove(key: try requireKey(args))
                result(nil)
            case "revokeAll":
                store.clear()
                result(nil)
            case "resetInvalidated":
                if let scope = args?["scope"] as? String { auth.reset(scope: scope) }
                result(nil)
            case "blobPut":
                guard let data = (args?["blob"] as? FlutterStandardTypedData)?.data else {
                    throw PluginError(SecurityCodes.storageError, "Missing blob.")
                }
                blobs.put(key: try requireKey(args), data: data)
                result(nil)
            case "blobGet":
                let data = blobs.get(key: try requireKey(args))
                result(data.map { FlutterStandardTypedData(bytes: $0) })
            case "blobDelete":
                blobs.remove(key: try requireKey(args))
                result(nil)
            case "blobKeys":
                result(blobs.keys())
            case "blobClear":
                blobs.clear()
                result(nil)
            default:
                result(FlutterMethodNotImplemented)
            }
        } catch let error as PluginError {
            result(FlutterError(code: error.code, message: error.message, details: nil))
        } catch {
            result(
                FlutterError(
                    code: SecurityCodes.storageError, message: error.localizedDescription,
                    details: nil))
        }
    }

    // MARK: - Handlers

    private func handleAuthenticate(_ args: [String: Any?]?, _ result: @escaping FlutterResult)
        throws
    {
        let policy = PolicyConfig.from(args)
        let reason = (args?["reason"] as? String) ?? "Authenticate"
        let scope = (args?["scope"] as? String) ?? "default"
        runGated(result) { [weak self] deliver in
            guard let self = self else { return }
            do {
                let session = try self.auth.authenticate(
                    scope: scope, policy: policy, reason: reason)
                deliver(.success(session))
            } catch let error as PluginError {
                deliver(.failure(error))
            } catch {
                deliver(.failure(ErrorMapper.fromAuthError(error)))
            }
        }
    }

    private func handleWrite(_ args: [String: Any?]?, _ result: @escaping FlutterResult) throws {
        let key = try requireKey(args)
        guard let data = (args?["value"] as? FlutterStandardTypedData)?.data else {
            throw PluginError(SecurityCodes.storageError, "Missing value.")
        }
        let policy = PolicyConfig.from(args)
        // Adding a Keychain item (even a gated one) does not require auth on iOS.
        try store.put(key: key, value: data, policy: policy)
        result(nil)
    }

    private func handleRead(_ args: [String: Any?]?, _ result: @escaping FlutterResult) throws {
        let key = try requireKey(args)
        let reason = (args?["reason"] as? String) ?? "Authenticate to unlock"
        runGated(result) { [weak self] deliver in
            guard let self = self else { return }
            do {
                let data = try self.store.read(key: key, reason: reason)
                deliver(.success(data.map { FlutterStandardTypedData(bytes: $0) }))
            } catch let error as PluginError {
                deliver(.failure(error))
            } catch {
                deliver(.failure(ErrorMapper.fromAuthError(error)))
            }
        }
    }

    // MARK: - Helpers

    private enum Delivery {
        case success(Any?)
        case failure(PluginError)
    }

    /// Serializes prompts and marshals the background result back to the main
    /// queue exactly once.
    private func runGated(
        _ result: @escaping FlutterResult, _ block: @escaping (@escaping (Delivery) -> Void) -> Void
    ) {
        if authInProgress {
            result(
                FlutterError(
                    code: SecurityCodes.unavailable,
                    message: "Another authentication is already in progress.", details: nil))
            return
        }
        authInProgress = true
        workQueue.async { [weak self] in
            block { delivery in
                DispatchQueue.main.async {
                    self?.authInProgress = false
                    switch delivery {
                    case .success(let value):
                        result(value)
                    case .failure(let error):
                        result(
                            FlutterError(
                                code: error.code, message: error.message, details: nil))
                    }
                }
            }
        }
    }

    private func requireKey(_ args: [String: Any?]?) throws -> String {
        guard let key = args?["key"] as? String else {
            throw PluginError(SecurityCodes.storageError, "Missing key.")
        }
        return key
    }

    // MARK: - FlutterStreamHandler

    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
        -> FlutterError?
    {
        eventSink = events
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        eventSink = nil
        return nil
    }
}
