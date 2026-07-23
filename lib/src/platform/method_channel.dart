/// The default [MethodChannel]-based platform implementation.
library;

import 'package:flutter/services.dart';

import '../enums.dart';
import '../exceptions.dart';
import '../models.dart';
import '../policy.dart';
import '../results.dart';
import 'platform_interface.dart';

/// Communicates with the host platform over a [MethodChannel] and an
/// [EventChannel].
///
/// In this foundation, only the read-only probes are wired end-to-end; the
/// native side returns stub data for [initialize] and [getAvailability] and
/// reports `notImplemented` for anything else.
class MethodChannelBiometricSecurity extends BiometricSecurityPlatform {
  /// The request/response channel.
  static const MethodChannel methodChannel = MethodChannel('biometric_security');

  /// The lifecycle-event channel.
  static const EventChannel eventChannel = EventChannel(
    'biometric_security/events',
  );

  @override
  Future<void> initialize(BiometricSecurityConfig config) async {
    try {
      await methodChannel.invokeMethod<void>('initialize', config.toMap());
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<BiometricAvailability> getAvailability() async {
    try {
      final result = await methodChannel.invokeMapMethod<Object?, Object?>(
        'getAvailability',
      );
      if (result == null) return const BiometricAvailability.unknown();
      return BiometricAvailability.fromMap(result);
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<SecurityStatus> getSecurityStatus() async {
    try {
      final result = await methodChannel.invokeMapMethod<Object?, Object?>(
        'getSecurityStatus',
      );
      if (result == null) {
        return const SecurityStatus(
          availability: BiometricAvailability.unknown(),
          achievableSecurityLevel: SecurityLevel.none,
          reprovisionRequired: false,
          integrityRisk: false,
        );
      }
      return SecurityStatus.fromMap(result);
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Stream<KeyLifecycleEvent> lifecycleEvents() {
    return eventChannel.receiveBroadcastStream().map((event) {
      if (event is Map) {
        return KeyLifecycleEvent.fromMap(event.cast<Object?, Object?>());
      }
      return const KeyLifecycleEvent(
        type: KeyLifecycleEventType.enrollmentChanged,
        message: 'Unrecognized lifecycle event.',
      );
    });
  }

  @override
  Future<AuthSession> authenticate({
    required String reason,
    required SecurityPolicy policy,
    String? cancelLabel,
    String scope = 'default',
  }) async {
    try {
      final result = await methodChannel.invokeMapMethod<Object?, Object?>(
        'authenticate',
        {
          'reason': reason,
          'policy': policy.toMap(),
          'cancelLabel': cancelLabel,
          'scope': scope,
        },
      );
      if (result == null) {
        throw const BiometricAuthFailedException('No session returned.');
      }
      return AuthSession.fromMap(result);
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> write({
    required String key,
    required Uint8List value,
    required SecurityPolicy policy,
    String? reason,
  }) async {
    try {
      await methodChannel.invokeMethod<void>('write', {
        'key': key,
        'value': value,
        'policy': policy.toMap(),
        'reason': reason,
      });
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<Uint8List?> read({required String key, String? reason}) async {
    try {
      return await methodChannel.invokeMethod<Uint8List?>('read', {
        'key': key,
        'reason': reason,
      });
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> delete({required String key}) async {
    try {
      await methodChannel.invokeMethod<void>('delete', {'key': key});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> deleteAll() async {
    try {
      await methodChannel.invokeMethod<void>('deleteAll');
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<bool> contains({required String key}) async {
    try {
      return await methodChannel.invokeMethod<bool>('contains', {'key': key}) ??
          false;
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<Set<String>> keys() async {
    try {
      final list = await methodChannel.invokeListMethod<String>('keys');
      return list?.toSet() ?? <String>{};
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> revoke({required String key}) async {
    try {
      await methodChannel.invokeMethod<void>('revoke', {'key': key});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> revokeAll() async {
    try {
      await methodChannel.invokeMethod<void>('revokeAll');
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> resetInvalidated({String? scope}) async {
    try {
      await methodChannel.invokeMethod<void>('resetInvalidated', {'scope': scope});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> blobPut({required String key, required Uint8List blob}) async {
    try {
      await methodChannel.invokeMethod<void>('blobPut', {'key': key, 'blob': blob});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<Uint8List?> blobGet({required String key}) async {
    try {
      return await methodChannel.invokeMethod<Uint8List?>('blobGet', {'key': key});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> blobDelete({required String key}) async {
    try {
      await methodChannel.invokeMethod<void>('blobDelete', {'key': key});
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<Set<String>> blobKeys() async {
    try {
      final list = await methodChannel.invokeListMethod<String>('blobKeys');
      return list?.toSet() ?? <String>{};
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }

  @override
  Future<void> blobClear() async {
    try {
      await methodChannel.invokeMethod<void>('blobClear');
    } on PlatformException catch (e) {
      throw mapPlatformException(e);
    }
  }
}

/// Maps a native [PlatformException] to a typed [BiometricSecurityException].
///
/// The `code` values here are the contract the native side must emit; they are
/// documented in `ARCHITECTURE.md` §12.
BiometricSecurityException mapPlatformException(PlatformException e) {
  final message = e.message ?? e.code;
  switch (e.code) {
    case 'auth_canceled':
      return BiometricAuthCanceledException(message);
    case 'auth_failed':
      return BiometricAuthFailedException(message);
    case 'locked_out':
      return BiometricLockedOutException(message: message);
    case 'locked_out_permanent':
      return BiometricLockedOutException(isPermanent: true, message: message);
    case 'unavailable':
      return BiometricUnavailableException(message: message);
    case 'not_enrolled':
      return const BiometricNotEnrolledException();
    case 'key_invalidated':
      return KeyInvalidatedException(message: message);
    case 'enrollment_changed':
      return EnrollmentChangedException(message);
    case 'storage_error':
      return SecureStorageException(message);
    case 'crypto_error':
      return CryptographicException(message);
    case 'policy_unsupported':
      return PolicyUnsupportedException(message);
    case 'not_initialized':
      return NotInitializedException(message);
    default:
      return SecureStorageException(message);
  }
}
