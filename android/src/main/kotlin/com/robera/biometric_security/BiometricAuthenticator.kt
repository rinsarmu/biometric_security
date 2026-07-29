package com.robera.biometric_security

import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

/**
 * Presents `BiometricPrompt` and binds the authentication to a specific key
 * operation via a `CryptoObject`: the returned [Cipher] is only usable
 * after a successful authentication, so a forged "success" cannot unlock data.
 *
 * All `BiometricPrompt` error codes are translated to [SecurityCodes] here; raw
 * codes never cross the channel.
 */
class BiometricAuthenticator {

    /**
     * Runs a prompt for [cipher]. Exactly one of [onSuccess]/[onError] is
     * invoked on the main thread.
     */
    fun authenticate(
        activity: FragmentActivity,
        policy: PolicyConfig,
        reason: String,
        cancelLabel: String?,
        cipher: Cipher,
        onSuccess: (Cipher) -> Unit,
        onError: (String, String) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object: BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(
                result: BiometricPrompt.AuthenticationResult,
            ) {
                val authedCipher = result.cryptoObject?.cipher
                if (authedCipher == null) {
                    onError(SecurityCodes.CRYPTO_ERROR, "No authenticated cipher returned.")
                } else {
                    onSuccess(authedCipher)
                }
            }

            override fun onAuthenticationError(code: Int, message: CharSequence) {
                val (mapped, msg) = mapError(code, message.toString())
                onError(mapped, msg)
            }

            override fun onAuthenticationFailed() {
                // A single non-matching attempt; the prompt stays open. We do not
                // resolve here — the OS retries until success, error, or cancel.
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val info = buildPromptInfo(policy, reason, cancelLabel)
        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            onError(SecurityCodes.UNAVAILABLE, e.message ?: "Unable to show biometric prompt.")
        }
    }

    private fun buildPromptInfo(
        policy: PolicyConfig,
        reason: String,
        cancelLabel: String?,
    ): BiometricPrompt.PromptInfo {
        val builder = BiometricPrompt.PromptInfo.Builder()
.setTitle(reason)
.setConfirmationRequired(policy.requireConfirmation)

        if (policy.deviceCredentialFallback) {
            // A negative button is not allowed together with DEVICE_CREDENTIAL.
            builder.setAllowedAuthenticators(
                Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL,
            )
        } else {
            builder.setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            builder.setNegativeButtonText(cancelLabel ?: "Cancel")
        }
        return builder.build()
    }

    /** Translates a `BiometricPrompt` error code to the shared contract. */
    private fun mapError(code: Int, message: String): Pair<String, String> {
        return when (code) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
            BiometricPrompt.ERROR_CANCELED ->
                SecurityCodes.AUTH_CANCELED to "Authentication was canceled."

            BiometricPrompt.ERROR_LOCKOUT ->
                SecurityCodes.LOCKED_OUT to "Too many attempts. Try again later."

            BiometricPrompt.ERROR_LOCKOUT_PERMANENT ->
                SecurityCodes.LOCKED_OUT_PERMANENT to
                    "Biometrics are locked. Unlock with your device credential."

            BiometricPrompt.ERROR_NO_BIOMETRICS ->
                SecurityCodes.NOT_ENROLLED to "No biometric is enrolled."

            BiometricPrompt.ERROR_HW_NOT_PRESENT,
            BiometricPrompt.ERROR_HW_UNAVAILABLE,
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED ->
                SecurityCodes.UNAVAILABLE to "Biometric authentication is unavailable."

            else -> SecurityCodes.AUTH_FAILED to (message.ifEmpty { "Authentication failed." })
        }
    }
}
