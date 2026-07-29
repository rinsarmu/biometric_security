package com.robera.biometric_security

/**
 * The Android-side parsed form of a Dart `SecurityPolicy`.
 *
 * This class is deliberately free of Android framework references so it can be
 * unit-tested on the plain JVM. The framework mapping (to `KeyGenParameterSpec`
 * and `BiometricPrompt` authenticators) lives in [KeystoreManager] and
 * [BiometricAuthenticator].
 */
data class PolicyConfig(
    val minimumStrength: String,
    val deviceCredentialFallback: Boolean,
    val invalidateOnEnrollment: Boolean,
    val perOperation: Boolean,
    val authWindowSeconds: Int,
    val requireSecureHardware: Boolean,
    val requireConfirmation: Boolean,
) {
    /** Whether this policy needs a biometric/credential prompt at all. */
    val requiresAuthentication: Boolean
        get() = minimumStrength != "none"

    companion object {
        /** The secure-by-default policy, matching the Dart default constructor. */
        fun secureDefault(): PolicyConfig = PolicyConfig(
            minimumStrength = "strong",
            deviceCredentialFallback = false,
            invalidateOnEnrollment = true,
            perOperation = true,
            authWindowSeconds = 0,
            requireSecureHardware = false,
            requireConfirmation = false,
        )

        /**
         * Parses a policy map received over the method channel. Missing or
         * malformed fields fall back to the secure default (never to a weaker
         * value silently — the default *is* the strong value).
         */
        @Suppress("UNCHECKED_CAST")
        fun fromMap(map: Map<String, Any?>?): PolicyConfig {
            if (map == null) return secureDefault()
            val d = secureDefault()
            return PolicyConfig(
                minimumStrength = (map["minimumStrength"] as? String) ?: d.minimumStrength,
                deviceCredentialFallback =
                    (map["deviceCredentialFallback"] as? String) == "allow",
                invalidateOnEnrollment =
                    (map["enrollmentBinding"] as? String ?: "invalidateOnChange") ==
                        "invalidateOnChange",
                perOperation =
                    (map["authValidity"] as? String ?: "perOperation") == "perOperation",
                authWindowSeconds =
                    (map["authWindowSeconds"] as? Number)?.toInt() ?: d.authWindowSeconds,
                requireSecureHardware =
                    (map["hardwareRequirement"] as? String) == "requireSecureHardware",
                requireConfirmation = (map["requireConfirmation"] as? Boolean) ?: false,
            )
        }
    }
}
