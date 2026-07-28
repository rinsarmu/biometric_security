package com.example.biometric_security

import android.content.Context
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * Android implementation of the `biometric_security` plugin.
 *
 * Orchestrates capability detection ([Capabilities]), Keystore key management
 * ([KeystoreManager]), ciphertext storage ([SecureStore]), and biometric-gated
 * key operations ([BiometricAuthenticator]).
 *
 * Threading & concurrency: method calls arrive on the main thread; gated
 * operations schedule a `BiometricPrompt` and resolve their [Result] from the
 * prompt callback (also main thread). A single-flight guard serializes prompts,
 * because overlapping `BiometricPrompt`s are unsupported (ARCHITECTURE.md §19).
 *
 * Error handling: every failure is translated to a [SecurityCodes] value; raw
 * Android exceptions never cross the channel.
 */
class BiometricSecurityPlugin :
    FlutterPlugin,
    ActivityAware,
    MethodCallHandler,
    EventChannel.StreamHandler {

    private lateinit var channel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private lateinit var appContext: Context

    private var activity: FragmentActivity? = null
    private var eventSink: EventChannel.EventSink? = null

    private lateinit var keystore: KeystoreManager
    private val authenticator = BiometricAuthenticator()
    private var namespace: String = "default"

    @Volatile
    private var authInProgress = false

    // ---- FlutterPlugin ----

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        keystore = KeystoreManager()
        channel = MethodChannel(binding.binaryMessenger, "biometric_security")
        channel.setMethodCallHandler(this)
        eventChannel = EventChannel(binding.binaryMessenger, "biometric_security/events")
        eventChannel.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        eventSink = null
    }

    // ---- ActivityAware ----

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    // ---- EventChannel ----

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    // ---- Method routing ----

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "initialize" -> handleInitialize(call, result)
                "getAvailability" -> result.success(Capabilities(appContext).availabilityMap())
                "getSecurityStatus" ->
                    result.success(Capabilities(appContext).securityStatusMap())
                "authenticate" -> handleAuthenticate(call, result)
                "write" -> handleWrite(call, result)
                "read" -> handleRead(call, result)
                "delete" -> handleDelete(call, result)
                "deleteAll" -> handleDeleteAll(result)
                "contains" -> result.success(store().contains(requireKey(call)))
                "keys" -> result.success(store().keys().toList())
                "revoke" -> handleRevoke(call, result)
                "revokeAll" -> handleRevokeAll(result)
                "resetInvalidated" -> handleResetInvalidated(call, result)
                "blobPut" -> handleBlobPut(call, result)
                "blobGet" -> result.success(blobStore().get(requireKey(call)))
                "blobDelete" -> { blobStore().remove(requireKey(call)); result.success(null) }
                "blobKeys" -> result.success(blobStore().keys().toList())
                "blobClear" -> { blobStore().clear(); result.success(null) }
                else -> result.notImplemented()
            }
        } catch (e: PluginException) {
            result.error(e.code, e.message, null)
        } catch (e: Exception) {
            result.error(SecurityCodes.STORAGE_ERROR, e.message ?: "Unexpected error.", null)
        }
    }

    // ---- Handlers ----

    private fun handleInitialize(call: MethodCall, result: Result) {
        namespace = call.argument<String>("namespace") ?: "default"
        result.success(null)
    }

    private fun handleAuthenticate(call: MethodCall, result: Result) {
        val activity = requireActivity()
        val policy = PolicyConfig.fromMap(call.argument("policy"))
        val reason = call.argument<String>("reason") ?: "Authenticate"
        val cancelLabel = call.argument<String>("cancelLabel")
        val scope = call.argument<String>("scope") ?: "default"
        val alias = authAlias(scope)

        if (!keystore.keyExists(alias)) keystore.createKey(alias, gated = true, policy)
        val cipher = try {
            keystore.encryptCipher(alias)
        } catch (e: PluginException) {
            // Self-heal: the auth key protects no stored secret, so on invalidation
            // drop the dead key and let the next authenticate() re-provision. The
            // KEY_INVALIDATED exception still surfaces cleanly to Dart.
            if (e.code == SecurityCodes.KEY_INVALIDATED) keystore.deleteKey(alias)
            throw e
        }

        runGated(result) { safeResult ->
            authenticator.authenticate(
                activity, policy, reason, cancelLabel, cipher,
                onSuccess = { authedCipher ->
                    try {
                        val proof = authedCipher.doFinal(AUTH_PROOF)
                        safeResult.success(
                            mapOf(
                                "token" to android.util.Base64.encodeToString(
                                    proof, android.util.Base64.NO_WRAP,
                                ),
                                "authenticatedAtMs" to System.currentTimeMillis(),
                                "usedModality" to null,
                                "securityLevel" to keystore.securityLevelOf(alias),
                            ),
                        )
                    } catch (e: Exception) {
                        safeResult.error(SecurityCodes.CRYPTO_ERROR, "Auth proof failed.", null)
                    }
                },
                onError = { code, msg -> safeResult.error(code, msg, null) },
            )
        }
    }

    private fun handleWrite(call: MethodCall, result: Result) {
        val key = requireKey(call)
        val value = call.argument<ByteArray>("value")
            ?: throw PluginException(SecurityCodes.STORAGE_ERROR, "Missing value.")
        val policy = PolicyConfig.fromMap(call.argument("policy"))

        if (!policy.requiresAuthentication) {
            // Encrypted-at-rest only: shared namespace key, no prompt.
            val alias = kekAlias()
            if (!keystore.keyExists(alias)) keystore.createKey(alias, gated = false, policy)
            val cipher = keystore.encryptCipher(alias)
            val ct = cipher.doFinal(value)
            store().put(
                key,
                SecureStore.Blob(alias, false, cipher.iv, ct, keystore.securityLevelOf(alias)),
            )
            result.success(null)
            return
        }

        // Biometric-gated: per-secret key, encrypt inside the prompt callback.
        val activity = requireActivity()
        val reason = call.argument<String>("reason") ?: "Authenticate to save"
        val alias = secretAlias(key)
        keystore.deleteKey(alias) // fresh key for a fresh write
        keystore.createKey(alias, gated = true, policy)
        val cipher = keystore.encryptCipher(alias)

        runGated(result) { safeResult ->
            authenticator.authenticate(
                activity, policy, reason, null, cipher,
                onSuccess = { authedCipher ->
                    try {
                        val ct = authedCipher.doFinal(value)
                        store().put(
                            key,
                            SecureStore.Blob(
                                alias, true, authedCipher.iv, ct,
                                keystore.securityLevelOf(alias),
                            ),
                        )
                        safeResult.success(null)
                    } catch (e: Exception) {
                        safeResult.error(SecurityCodes.CRYPTO_ERROR, "Encryption failed.", null)
                    }
                },
                onError = { code, msg -> safeResult.error(code, msg, null) },
            )
        }
    }

    private fun handleRead(call: MethodCall, result: Result) {
        val key = requireKey(call)
        val blob = store().get(key)
        if (blob == null) {
            result.success(null)
            return
        }

        if (!blob.gated) {
            val cipher = keystore.decryptCipher(blob.alias, blob.iv)
            result.success(cipher.doFinal(blob.ciphertext))
            return
        }

        val activity = requireActivity()
        val reason = call.argument<String>("reason") ?: "Authenticate to unlock"
        val policy = PolicyConfig.secureDefault()
        val cipher = keystore.decryptCipher(blob.alias, blob.iv) // may throw KEY_INVALIDATED

        runGated(result) { safeResult ->
            authenticator.authenticate(
                activity, policy, reason, null, cipher,
                onSuccess = { authedCipher ->
                    try {
                        safeResult.success(authedCipher.doFinal(blob.ciphertext))
                    } catch (e: Exception) {
                        safeResult.error(SecurityCodes.CRYPTO_ERROR, "Decryption failed.", null)
                    }
                },
                onError = { code, msg -> safeResult.error(code, msg, null) },
            )
        }
    }

    private fun handleDelete(call: MethodCall, result: Result) {
        store().remove(requireKey(call))
        result.success(null)
    }

    private fun handleDeleteAll(result: Result) {
        store().clear()
        result.success(null)
    }

    private fun handleRevoke(call: MethodCall, result: Result) {
        val key = requireKey(call)
        val blob = store().get(key)
        if (blob != null) keystore.deleteKey(blob.alias)
        store().remove(key)
        result.success(null)
    }

    private fun handleRevokeAll(result: Result) {
        keystore.deleteNamespace("bsec.$namespace.")
        store().clear()
        result.success(null)
    }

    private fun handleResetInvalidated(call: MethodCall, result: Result) {
        val scope = call.argument<String>("scope")
        if (scope != null) {
            keystore.deleteKey(authAlias(scope))
            keystore.deleteKey(secretAlias(scope))
        } else {
            keystore.deleteNamespace("bsec.$namespace.")
        }
        result.success(null)
    }

    // ---- Helpers ----

    /** Serializes prompts and guards against a [Result] being resolved twice. */
    private fun runGated(result: Result, block: (SafeResult) -> Unit) {
        if (authInProgress) {
            result.error(
                SecurityCodes.UNAVAILABLE,
                "Another authentication is already in progress.",
                null,
            )
            return
        }
        authInProgress = true
        val safe = SafeResult(result) { authInProgress = false }
        block(safe)
    }

    private fun requireActivity(): FragmentActivity {
        return activity ?: throw PluginException(
            SecurityCodes.UNAVAILABLE,
            "No FragmentActivity available. The host Activity must extend " +
                "FlutterFragmentActivity to use biometric prompts.",
        )
    }

    private fun requireKey(call: MethodCall): String {
        return call.argument<String>("key")
            ?: throw PluginException(SecurityCodes.STORAGE_ERROR, "Missing key.")
    }

    private fun handleBlobPut(call: MethodCall, result: Result) {
        val blob = call.argument<ByteArray>("blob")
            ?: throw PluginException(SecurityCodes.STORAGE_ERROR, "Missing blob.")
        blobStore().put(requireKey(call), blob)
        result.success(null)
    }

    private fun store(): SecureStore = SecureStore(appContext, namespace)
    private fun blobStore(): BlobStore = BlobStore(appContext, namespace)

    private fun kekAlias(): String = "bsec.$namespace.kek"
    private fun secretAlias(key: String): String = "bsec.$namespace.secret.$key"
    private fun authAlias(scope: String): String = "bsec.$namespace.auth.$scope"

    companion object {
        private val AUTH_PROOF = "biometric_security.auth".toByteArray(Charsets.UTF_8)
    }
}

/**
 * Wraps a [Result] so it is resolved at most once and always clears the
 * single-flight guard, whichever way the prompt ends.
 */
private class SafeResult(private val result: Result, private val onDone: () -> Unit) {
    private var done = false

    fun success(value: Any?) {
        if (done) return
        done = true
        onDone()
        result.success(value)
    }

    fun error(code: String, message: String, details: Any?) {
        if (done) return
        done = true
        onDone()
        result.error(code, message, details)
    }
}
