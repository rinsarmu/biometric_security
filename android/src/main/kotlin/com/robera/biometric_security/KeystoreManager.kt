package com.robera.biometric_security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.InvalidKeyException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Owns all Android Keystore key material and the AES-256-GCM operations built on
 * top of it.
 *
 * Design decisions:
 * - Every key lives in the `AndroidKeyStore` provider. Private/secret key
 * material is non-exportable and never leaves secure hardware, and never
 * touches SharedPreferences, files, or any Dart-visible surface.
 * - Biometric-gated secrets use a **per-secret** Keystore key. Preferring
 * per-secret keys over an envelope KEK keeps the DEK out of software entirely
 * and gives clean per-secret revocation, at the cost of coarser rotation.
 * - Non-gated ("encrypted-only") secrets share one namespace key that is not
 * bound to user authentication, so reads/writes do not prompt.
 *
 * Only AES/GCM/NoPadding with a 256-bit Keystore key is used — no weak, custom,
 * or software-managed key material.
 */
class KeystoreManager {

    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    // ---- Key lifecycle ----

    fun keyExists(alias: String): Boolean = keyStore.containsAlias(alias)

    /**
     * Creates a hardware-backed AES-256-GCM key. When [gated] is true the key is
     * bound to user authentication per [policy]; otherwise it is an at-rest key.
     *
     * Throws [PluginException] with [SecurityCodes.POLICY_UNSUPPORTED] when the
     * device cannot satisfy a `requireSecureHardware` policy.
     */
    fun createKey(alias: String, gated: Boolean, policy: PolicyConfig): SecretKey {
        val key = try {
            buildKey(alias, gated, policy, useStrongBox = policy.requireSecureHardware)
        } catch (e: StrongBoxUnavailableException) {
            // StrongBox absent: fall back to the TEE (still secure hardware).
            buildKey(alias, gated, policy, useStrongBox = false)
        }

        // Enforce the policy: a requireSecureHardware key that landed in the
        // software fallback (no TEE/StrongBox) must be rejected, not silently
        // accepted.
        if (policy.requireSecureHardware && securityLevelOf(alias) == "software") {
            deleteKey(alias)
            throw PluginException(
                SecurityCodes.POLICY_UNSUPPORTED,
                "Secure hardware was required but is not available on this device.",
            )
        }
        return key
    }

    private fun buildKey(
        alias: String,
        gated: Boolean,
        policy: PolicyConfig,
        useStrongBox: Boolean,
    ): SecretKey {
        val purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
.setKeySize(256)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        if (gated) {
            builder.setUserAuthenticationRequired(true)
            // Enrollment-change invalidation. API 24+.
            builder.setInvalidatedByBiometricEnrollment(policy.invalidateOnEnrollment)
            applyAuthParameters(builder, policy)
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun applyAuthParameters(
        builder: KeyGenParameterSpec.Builder,
        policy: PolicyConfig,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            var authTypes = KeyProperties.AUTH_BIOMETRIC_STRONG
            if (policy.deviceCredentialFallback) {
                authTypes = authTypes or KeyProperties.AUTH_DEVICE_CREDENTIAL
            }
            // timeout 0 => per-use auth (CryptoObject bound); >0 => reuse window.
            val timeout = if (policy.perOperation) 0 else policy.authWindowSeconds
            builder.setUserAuthenticationParameters(timeout, authTypes)
        } else {
            // Pre-API-30 fallback: -1 => per-use auth required for every operation.
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(
                if (policy.perOperation) -1 else policy.authWindowSeconds,
            )
        }
    }

    fun deleteKey(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    /** Deletes every key whose alias belongs to [namespacePrefix]. */
    fun deleteNamespace(namespacePrefix: String) {
        val aliases = keyStore.aliases().toList()
        for (alias in aliases) {
            if (alias.startsWith(namespacePrefix)) keyStore.deleteEntry(alias)
        }
    }

    private fun getKey(alias: String): SecretKey {
        return keyStore.getKey(alias, null) as? SecretKey
            ?: throw PluginException(
                SecurityCodes.STORAGE_ERROR,
                "Key '$alias' is missing.",
            )
    }

    // ---- Cipher construction (may require a subsequent CryptoObject prompt) ----

    /**
     * Builds an encrypt cipher for [alias]. For a gated key this cipher must be
     * wrapped in a `BiometricPrompt.CryptoObject`; `doFinal` only succeeds after
     * a successful authentication.
     */
    fun encryptCipher(alias: String): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, getKey(alias))
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw PluginException(
                SecurityCodes.KEY_INVALIDATED,
                "The key was permanently invalidated by an enrollment or lock change.",
                e,
            )
        } catch (e: InvalidKeyException) {
            throw PluginException(SecurityCodes.CRYPTO_ERROR, "Key is unusable.", e)
        }
        return cipher
    }

    /** Builds a decrypt cipher for [alias] and the stored [iv]. */
    fun decryptCipher(alias: String, iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, getKey(alias), GCMParameterSpec(TAG_BITS, iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw PluginException(
                SecurityCodes.KEY_INVALIDATED,
                "The key was permanently invalidated by an enrollment or lock change.",
                e,
            )
        } catch (e: InvalidKeyException) {
            throw PluginException(SecurityCodes.CRYPTO_ERROR, "Key is unusable.", e)
        }
        return cipher
    }

    /** Reports the actual security level backing a key. */
    fun securityLevelOf(alias: String): String {
        return try {
            val key = getKey(alias)
            val factory = javax.crypto.SecretKeyFactory.getInstance(
                key.algorithm,
                ANDROID_KEYSTORE,
            )
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongBox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                        "trustedExecutionEnvironment"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                    else -> "trustedExecutionEnvironment"
                }
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) "trustedExecutionEnvironment"
                else "software"
            }
        } catch (e: Exception) {
            "software"
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
    }
}
