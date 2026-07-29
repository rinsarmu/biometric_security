package com.robera.biometric_security

/**
 * The error-code contract shared with the Dart layer.
 *
 * Every value here maps 1:1 to a typed [BiometricSecurityException] subtype in
 * `lib/src/platform/method_channel.dart` (`mapPlatformException`). Raw Android
 * exceptions are never surfaced across the channel; they are translated into one
 * of these codes first.
 */
object SecurityCodes {
    const val AUTH_CANCELED = "auth_canceled"
    const val AUTH_FAILED = "auth_failed"
    const val LOCKED_OUT = "locked_out"
    const val LOCKED_OUT_PERMANENT = "locked_out_permanent"
    const val UNAVAILABLE = "unavailable"
    const val NOT_ENROLLED = "not_enrolled"
    const val KEY_INVALIDATED = "key_invalidated"
    const val ENROLLMENT_CHANGED = "enrollment_changed"
    const val STORAGE_ERROR = "storage_error"
    const val CRYPTO_ERROR = "crypto_error"
    const val POLICY_UNSUPPORTED = "policy_unsupported"
    const val NOT_INITIALIZED = "not_initialized"
}

/**
 * A translated, channel-safe failure. Carries a [SecurityCodes] value plus a
 * human-readable message. The original cause is retained for local logging only
 * and is never sent across the channel.
 */
class PluginException(
    val code: String,
    override val message: String,
    val cause0: Throwable? = null,
): Exception(message, cause0)
