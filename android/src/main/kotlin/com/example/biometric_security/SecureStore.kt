package com.example.biometric_security

import android.content.Context
import android.util.Base64
import org.json.JSONObject

/**
 * Persists per-secret **ciphertext and metadata** in an app-private
 * SharedPreferences file.
 *
 * This never stores cryptographic keys — those live exclusively in the Android
 * Keystore (see [KeystoreManager]). Only GCM ciphertext, the GCM IV, the key
 * alias, and non-sensitive metadata are stored here, so plain SharedPreferences
 * is an appropriate container (INV-2 / ARCHITECTURE.md §5).
 */
class SecureStore(context: Context, namespace: String) {

    private val prefs =
        context.getSharedPreferences("bsec.$namespace.store", Context.MODE_PRIVATE)

    data class Blob(
        val alias: String,
        val gated: Boolean,
        val iv: ByteArray,
        val ciphertext: ByteArray,
        val securityLevel: String,
    )

    fun put(key: String, blob: Blob) {
        val json = JSONObject().apply {
            put("v", SCHEMA_VERSION)
            put("alias", blob.alias)
            put("gated", blob.gated)
            put("iv", Base64.encodeToString(blob.iv, Base64.NO_WRAP))
            put("ct", Base64.encodeToString(blob.ciphertext, Base64.NO_WRAP))
            put("securityLevel", blob.securityLevel)
        }
        prefs.edit().putString(key, json.toString()).apply()
    }

    fun get(key: String): Blob? {
        val raw = prefs.getString(key, null) ?: return null
        return try {
            val json = JSONObject(raw)
            Blob(
                alias = json.getString("alias"),
                gated = json.getBoolean("gated"),
                iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP),
                ciphertext = Base64.decode(json.getString("ct"), Base64.NO_WRAP),
                securityLevel = json.optString("securityLevel", "software"),
            )
        } catch (e: Exception) {
            throw PluginException(
                SecurityCodes.STORAGE_ERROR,
                "Stored entry for '$key' is corrupt.",
                e,
            )
        }
    }

    fun contains(key: String): Boolean = prefs.contains(key)

    fun keys(): Set<String> = prefs.all.keys

    fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val SCHEMA_VERSION = 1
    }
}
