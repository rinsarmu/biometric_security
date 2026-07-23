/// Result types returned by successful operations.
library;

import 'dart:typed_data';

import 'enums.dart';

/// Proof that a real, key-backed authentication succeeded.
///
/// This is intentionally not a bare boolean: a session is produced only when an
/// actual hardware key operation ran under the authentication (INV-1).
class AuthSession {
  /// An opaque, non-forgeable marker that a hardware key operation ran.
  final String token;

  /// When the authentication completed.
  final DateTime authenticatedAt;

  /// The modality the OS actually used, if it reported one (informational).
  final BiometricModality? usedModality;

  /// The security level of the key that backed this authentication.
  final SecurityLevel securityLevel;

  /// Creates an authentication session.
  const AuthSession({
    required this.token,
    required this.authenticatedAt,
    this.usedModality,
    required this.securityLevel,
  });

  /// Deserializes from a platform-channel map.
  factory AuthSession.fromMap(Map<Object?, Object?> map) {
    return AuthSession(
      token: map['token'] as String? ?? '',
      authenticatedAt: DateTime.fromMillisecondsSinceEpoch(
        (map['authenticatedAtMs'] as num?)?.toInt() ?? 0,
      ),
      usedModality: map['usedModality'] == null
          ? null
          : enumFromName(
              BiometricModality.values,
              map['usedModality'],
              BiometricModality.unknown,
            ),
      securityLevel: enumFromName(
        SecurityLevel.values,
        map['securityLevel'],
        SecurityLevel.none,
      ),
    );
  }
}

/// The result of signing a server-provided challenge with a hardware key.
class SignatureResult {
  /// The signature over the challenge.
  final Uint8List signature;

  /// The DER/SPKI-encoded public key, to be registered with a backend once.
  final Uint8List publicKey;

  /// The security level of the signing key.
  final SecurityLevel securityLevel;

  /// Creates a signature result.
  const SignatureResult({
    required this.signature,
    required this.publicKey,
    required this.securityLevel,
  });

  /// Deserializes from a platform-channel map.
  factory SignatureResult.fromMap(Map<Object?, Object?> map) {
    return SignatureResult(
      signature: map['signature'] as Uint8List? ?? Uint8List(0),
      publicKey: map['publicKey'] as Uint8List? ?? Uint8List(0),
      securityLevel: enumFromName(
        SecurityLevel.values,
        map['securityLevel'],
        SecurityLevel.none,
      ),
    );
  }
}
