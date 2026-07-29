package com.robera.biometric_security

import android.content.Context
import android.util.Base64

/**
 * Opaque ciphertext-blob persistence in an app-private SharedPreferences file.
 *
 * Blobs are already AES-256-GCM-encrypted by the Dart engine (the DEK is held in
 * the Android Keystore, not here), so this store holds only ciphertext and
 * non-sensitive metadata — never key material. It is deliberately kept
 * separate from the DEK/key store.
 */
class BlobStore(context: Context, namespace: String) {

    private val prefs =
        context.getSharedPreferences("bsec.$namespace.blobs", Context.MODE_PRIVATE)

    fun put(key: String, blob: ByteArray) {
        prefs.edit().putString(key, Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    fun get(key: String): ByteArray? {
        val encoded = prefs.getString(key, null) ?: return null
        return Base64.decode(encoded, Base64.NO_WRAP)
    }

    fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun keys(): Set<String> = prefs.all.keys

    fun clear() {
        prefs.edit().clear().apply()
    }
}
