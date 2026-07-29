/// Authenticated encryption for secret payloads.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../exceptions.dart';

/// The result of an authenticated encryption: a random nonce, the ciphertext,
/// and the authentication tag (MAC).
class SealedPayload {
  /// 96-bit random nonce, unique per encryption.
  final Uint8List nonce;

  /// The AES-GCM ciphertext.
  final Uint8List cipherText;

  /// The 128-bit GCM authentication tag.
  final Uint8List mac;

  const SealedPayload({
    required this.nonce,
    required this.cipherText,
    required this.mac,
  });
}

/// AES-256-GCM authenticated encryption over a data-encryption key (DEK).
///
/// This is the only cryptographic primitive in the Dart layer, provided by the
/// well-established `cryptography` package — no custom crypto.
/// It operates solely on software DEKs; hardware keys never reach it.
class PayloadCipher {
  PayloadCipher() : _algorithm = AesGcm.with256bits();

  final AesGcm _algorithm;

  /// The required DEK length in bytes (256-bit).
  static const int dekLength = 32;

  /// Encrypts [clearText] under [dek] with a fresh random nonce.
  Future<SealedPayload> seal({
    required Uint8List dek,
    required Uint8List clearText,
  }) async {
    _requireDekLength(dek);
    final secretKey = SecretKey(dek);
    // The library generates a cryptographically secure random nonce; a fresh
    // DEK+nonce per write makes nonce reuse under one key structurally impossible.
    final box = await _algorithm.encrypt(clearText, secretKey: secretKey);
    return SealedPayload(
      nonce: Uint8List.fromList(box.nonce),
      cipherText: Uint8List.fromList(box.cipherText),
      mac: Uint8List.fromList(box.mac.bytes),
    );
  }

  /// Decrypts a [SealedPayload] under [dek].
  ///
  /// Throws [CryptographicException] if the authentication tag does not verify
  /// (tampered ciphertext, wrong key, corruption). No plaintext is ever returned
  /// on failure.
  Future<Uint8List> open({
    required Uint8List dek,
    required SealedPayload payload,
  }) async {
    _requireDekLength(dek);
    final secretKey = SecretKey(dek);
    final box = SecretBox(
      payload.cipherText,
      nonce: payload.nonce,
      mac: Mac(payload.mac),
    );
    try {
      final clear = await _algorithm.decrypt(box, secretKey: secretKey);
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw const CryptographicException(
        'Authentication tag mismatch: the data is corrupt or was tampered with.',
      );
    }
  }

  void _requireDekLength(Uint8List dek) {
    if (dek.length != dekLength) {
      throw const CryptographicException('Invalid data-encryption key length.');
    }
  }
}
