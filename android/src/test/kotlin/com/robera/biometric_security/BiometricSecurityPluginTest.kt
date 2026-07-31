package com.robera.biometric_security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/*
 * JVM unit tests for the framework-independent policy parsing. Keystore and
 * BiometricPrompt behavior require an instrumented device and are covered by
 * integration tests instead.
 *
 * Run with `./gradlew testDebugUnitTest` in `example/android/`.
 */
internal class BiometricSecurityPluginTest {

    @Test
    fun secureDefault_isStrongAndPerOperation() {
        val p = PolicyConfig.secureDefault()
        assertEquals("strong", p.minimumStrength)
        assertFalse(p.deviceCredentialFallback)
        assertTrue(p.invalidateOnEnrollment)
        assertTrue(p.perOperation)
        assertTrue(p.requiresAuthentication)
    }

    @Test
    fun fromMap_null_returnsSecureDefault() {
        assertEquals(PolicyConfig.secureDefault(), PolicyConfig.fromMap(null))
    }

    @Test
    fun fromMap_encryptedOnly_doesNotRequireAuthentication() {
        val p = PolicyConfig.fromMap(mapOf("minimumStrength" to "none"))
        assertFalse(p.requiresAuthentication)
    }

    @Test
    fun fromMap_parsesWeakerOptions() {
        val p = PolicyConfig.fromMap(
            mapOf(
                "minimumStrength" to "strong",
                "deviceCredentialFallback" to "allow",
                "enrollmentBinding" to "persistAcrossEnrollment",
                "authValidity" to "window",
                "authWindowSeconds" to 30,
                "hardwareRequirement" to "requireSecureHardware",
                "requireConfirmation" to true,
            ),
        )
        assertTrue(p.deviceCredentialFallback)
        assertFalse(p.invalidateOnEnrollment)
        assertFalse(p.perOperation)
        assertEquals(30, p.authWindowSeconds)
        assertTrue(p.requireSecureHardware)
        assertTrue(p.requireConfirmation)
    }
}
