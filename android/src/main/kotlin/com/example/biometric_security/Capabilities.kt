package com.example.biometric_security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators

/**
 * Read-only biometric capability detection (availability, supported modalities,
 * strength, secure-hardware presence).
 *
 * Answers the "supported / available" questions of the five-way distinction
 * (API_DESIGN.md §1). Android intentionally does **not** expose *which* modality
 * is enrolled, so [enrolledModalities] is left empty and callers must rely on
 * [status] and [strength] to know whether a biometric is enrolled — a documented
 * platform limitation.
 */
class Capabilities(private val context: Context) {

    fun availabilityMap(): Map<String, Any?> {
        val manager = BiometricManager.from(context)
        val strongResult = manager.canAuthenticate(Authenticators.BIOMETRIC_STRONG)
        val weakResult = manager.canAuthenticate(Authenticators.BIOMETRIC_WEAK)

        val strength = when {
            strongResult == BiometricManager.BIOMETRIC_SUCCESS -> "strong"
            weakResult == BiometricManager.BIOMETRIC_SUCCESS -> "weak"
            else -> "none"
        }

        val status = mapStatus(strongResult, weakResult)
        val canAuthenticate = status == "ready"

        return mapOf(
            "isSupported" to hasAnyBiometricHardware(),
            "supportedModalities" to supportedModalities(),
            // Android cannot enumerate which modalities are enrolled.
            "enrolledModalities" to emptyList<String>(),
            "strength" to strength,
            "canAuthenticate" to canAuthenticate,
            "status" to status,
            "guarantees" to guaranteesMap(),
            "hasStrongBox" to hasStrongBox(),
            "hasSecureEnclave" to false,
        )
    }

    fun securityStatusMap(): Map<String, Any?> = mapOf(
        "availability" to availabilityMap(),
        "achievableSecurityLevel" to if (hasStrongBox()) "strongBox"
            else "trustedExecutionEnvironment",
        "reprovisionRequired" to false,
        "integrityRisk" to false,
    )

    private fun mapStatus(strongResult: Int, weakResult: Int): String {
        // Prefer the strong result; fall back to weak only to distinguish
        // "nothing enrolled" from "no hardware".
        val result = if (strongResult == BiometricManager.BIOMETRIC_SUCCESS) {
            strongResult
        } else if (weakResult == BiometricManager.BIOMETRIC_SUCCESS) {
            weakResult
        } else {
            strongResult
        }
        return when (result) {
            BiometricManager.BIOMETRIC_SUCCESS -> "ready"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "notEnrolled"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "noHardware"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "hardwareUnavailable"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                "hardwareUnavailable"
            else -> "unknown"
        }
    }

    private fun supportedModalities(): List<String> {
        val pm = context.packageManager
        val modalities = mutableListOf<String>()
        if (pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            modalities.add("fingerprint")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (pm.hasSystemFeature(PackageManager.FEATURE_FACE)) modalities.add("face")
            if (pm.hasSystemFeature(PackageManager.FEATURE_IRIS)) modalities.add("iris")
        }
        return modalities
    }

    private fun hasAnyBiometricHardware(): Boolean = supportedModalities().isNotEmpty()

    private fun hasStrongBox(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE,
            )
    }

    private fun guaranteesMap(): Map<String, Any?> = mapOf(
        "canEnforceStrength" to true,
        "canBindKeyToAuthentication" to true,
        "canInvalidateOnEnrollmentChange" to true,
        // Never true: Android cannot force a specific modality (INV-4).
        "canForceSpecificModality" to false,
    )
}
