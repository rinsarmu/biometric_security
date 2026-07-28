import 'dart:io' show Platform;

import 'package:biometric_security/biometric_security.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const ExampleApp());
}

// ---------------------------------------------------------------------------
// Pure, unit-testable interpretation helpers (see example/test/).
// These contain the only *new* Dart-level enrollment logic in this example;
// the actual enrollment-change detection lives in the native layer and can only
// be exercised on a physical device.
// ---------------------------------------------------------------------------

/// The observable state of a biometric-protected secret, derived from the
/// outcome of a `read()`.
enum ProtectedKeyState { unknown, valid, invalidated, absent, error }

/// Classifies the state of a protected key from an exception thrown by `read()`.
ProtectedKeyState keyStateForError(Object error) {
  if (error is KeyInvalidatedException) return ProtectedKeyState.invalidated;
  if (error is BiometricAuthCanceledException) return ProtectedKeyState.unknown;
  return ProtectedKeyState.error;
}

/// A short, human-readable summary of the current enrollment state.
String enrollmentSummary(BiometricAvailability a) {
  final enrolled = a.enrolledModalities.isEmpty
      ? '(platform does not enumerate — use status/strength)'
      : a.enrolledModalities.map((m) => m.name).join(', ');
  final supported = a.supportedModalities.isEmpty
      ? 'none'
      : a.supportedModalities.map((m) => m.name).join(', ');
  return 'status=${a.status.name}, strength=${a.strength.name}, '
      'supported=[$supported], enrolled=$enrolled';
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: HomePage());
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final BiometricSecurity _security = BiometricSecurity();
  static const _pin = SecretKey('demo_payment_pin');

  String _status = 'Not initialized';
  String _log = '';
  BiometricAvailability? _availability;
  SecurityStatus? _securityStatus;

  ProtectedKeyState _keyState = ProtectedKeyState.unknown;
  bool? _pinAccessible;
  String _enrollmentChanged = 'Not tested yet';

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      await _security.initialize();
      await _checkEnrollment();
      if (mounted) setState(() => _status = 'Initialized');
    } catch (e) {
      if (mounted) setState(() => _status = 'Init error: $e');
    }
  }

  void _append(String line) => setState(() => _log = '$line\n$_log');

  Future<void> _run(String label, Future<void> Function() action) async {
    try {
      await action();
      _append('✓ $label');
    } on BiometricSecurityException catch (e) {
      _append('✗ $label → ${e.runtimeType}: ${e.message}');
    }
  }

  // --- Actions (all use the real package API) ---

  Future<void> _checkEnrollment() async {
    final a = await _security.getAvailability();
    if (!mounted) return;
    setState(() => _availability = a);
    _append('Enrollment: ${enrollmentSummary(a)}');
  }

  Future<void> _checkSecurityStatus() =>
      _run('check security status', () async {
        final s = await _security.getSecurityStatus();
        setState(() => _securityStatus = s);
      });

  Future<void> _storePin() => _run('store biometric-protected PIN', () async {
    await _security.write(
      key: _pin,
      value: '4321',
      policy: SecurityPolicy.strong(),
      reason: 'Confirm to save your PIN',
    );
    setState(() {
      _keyState = ProtectedKeyState.valid;
      _pinAccessible = null; // not yet verified by a read
      _enrollmentChanged = 'reset (freshly stored)';
    });
  });

  Future<void> _readPin() async {
    try {
      final value = await _security.read(key: _pin, reason: 'Unlock your PIN');
      if (!mounted) return;
      setState(() {
        if (value == null) {
          _keyState = ProtectedKeyState.absent;
          _pinAccessible = false;
          _enrollmentChanged = 'n/a (no PIN stored)';
        } else {
          _keyState = ProtectedKeyState.valid;
          _pinAccessible = true;
          _enrollmentChanged = 'No — read succeeded, key still valid';
        }
      });
      _append(value == null ? 'read → (absent)' : 'read → $value');
    } on KeyInvalidatedException catch (e) {
      if (!mounted) return;
      setState(() {
        _keyState = ProtectedKeyState.invalidated;
        _pinAccessible = false;
        _enrollmentChanged = 'YES — key invalidated (enrolled set changed)';
      });
      _append('✗ read → KeyInvalidatedException: ${e.message}');
    } on BiometricSecurityException catch (e) {
      if (!mounted) return;
      setState(() => _keyState = keyStateForError(e));
      _append('✗ read → ${e.runtimeType}: ${e.message}');
    }
  }

  Future<void> _revokePin() => _run('revoke protected PIN', () async {
    await _security.revoke(key: _pin);
    setState(() {
      _keyState = ProtectedKeyState.absent;
      _pinAccessible = false;
      _enrollmentChanged = 'n/a (revoked)';
    });
  });

  Future<void> _resetInvalidated() => _run('reset invalidated key', () async {
    await _security.resetInvalidated();
    setState(() => _keyState = ProtectedKeyState.unknown);
    _append('Cleared dead key material — re-store the PIN to recover.');
  });

  // --- UI ---

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('biometric_security example')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(
            'Status: $_status',
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),

          
          const SizedBox(height: 12),
          _availabilityCard(),
          const SizedBox(height: 12),
          _enrollmentCard(),
          const SizedBox(height: 12),
          _instructionsCard(),
          const SizedBox(height: 12),
          const Text('Log:', style: TextStyle(fontWeight: FontWeight.bold)),
          Text(_log, style: const TextStyle(fontFamily: 'monospace')),
        ],
      ),
    );
  }

  Widget _availabilityCard() {
    final a = _availability;
    return _card('Availability', [
      if (a == null)
        const Text('—')
      else ...[
        _row('Supported', a.supportedModalities.toString()),
        _row('Strength', a.strength.name),
        _row('Can authenticate', a.canAuthenticate.toString()),
        _row('Status', a.status.name),
        _row('Has StrongBox', a.hasStrongBox.toString()),
        _row('Has Secure Enclave', a.hasSecureEnclave.toString()),
        _row(
          'Can force modality',
          a.guarantees.canForceSpecificModality.toString(),
        ),
      ],
    ]);
  }

  Widget _enrollmentCard() {
    final s = _securityStatus;
    return _card('Biometric Enrollment', [
      _row(
        'Enrollment status',
        _availability == null ? '—' : _availability!.status.name,
      ),
      _row('Enrollment changed', _enrollmentChanged),
      _row('Secure key valid', _keyValidityText()),
      _row(
        'Protected PIN accessible',
        _pinAccessible == null ? 'Unknown (read to verify)' : '$_pinAccessible',
      ),
      _row(
        'Security status',
        s == null
            ? 'Unknown (tap "Check Security Status")'
            : 'level=${s.achievableSecurityLevel.name}, '
                  'reprovision=${s.reprovisionRequired}, '
                  'integrityRisk=${s.integrityRisk}',
      ),
      const SizedBox(height: 8),
      Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          _btn(
            'Check Enrollment',
            () => _run('check enrollment', _checkEnrollment),
          ),
          _btn('Check Security Status', _checkSecurityStatus),
          _btn('Store Biometric-Protected PIN', _storePin),
          _btn('Read Protected PIN', _readPin),
          _btn('Revoke Protected PIN', _revokePin),
          _btn('Reset Invalidated Key', _resetInvalidated),
        ],
      ),
    ]);
  }

  String _keyValidityText() {
    switch (_keyState) {
      case ProtectedKeyState.valid:
        return 'Valid';
      case ProtectedKeyState.invalidated:
        return 'INVALIDATED';
      case ProtectedKeyState.absent:
        return 'No key stored';
      case ProtectedKeyState.error:
        return 'Error / unavailable';
      case ProtectedKeyState.unknown:
        return 'Unknown (read to verify)';
    }
  }

  Widget _instructionsCard() {
    final isIOS = Platform.isIOS;
    final isAndroid = Platform.isAndroid;
    final platformNote = isIOS
        ? '• iOS: with the default policy the item is bound to the *current* '
              'biometric set (biometryCurrentSet). Adding OR removing a Face ID / '
              'Touch ID enrollment makes it inaccessible. The invalidation is '
              'detected on the next read WITHOUT a prompt.'
        : isAndroid
        ? '• Android: with the default policy the Keystore key is invalidated '
              'when a NEW biometric is enrolled (setInvalidatedByBiometricEnrollment). '
              'The next read throws before any prompt is shown.'
        : '• Run on a physical Android or iOS device to observe real behavior.';

    return _card('Enrollment Change Test (manual, physical device)', [
      const Text(
        'This exercises real hardware; it cannot be simulated. With the '
        'default SecurityPolicy.strong() the protecting key is bound to the '
        'enrolled biometric set, so an enrollment change invalidates it.',
      ),
      const SizedBox(height: 8),
      const Text('Steps:'),
      const Text('1. Tap "Store Biometric-Protected PIN".'),
      const Text('2. Tap "Read Protected PIN" — it should succeed.'),
      const Text(
        '3. Leave the app; in system Settings add or remove a fingerprint/face.',
      ),
      const Text('4. Return to the app.'),
      const Text('5. Tap "Check Enrollment" then "Read Protected PIN".'),
      const Text('6. Observe: read should throw KeyInvalidatedException →'),
      const Text(
        '   "Secure key valid" shows INVALIDATED, PIN not accessible.',
      ),
      const Text('7. Recover: "Reset Invalidated Key", then store again.'),
      const SizedBox(height: 8),
      Text(platformNote, style: const TextStyle(fontStyle: FontStyle.italic)),
      const SizedBox(height: 4),
      const Text(
        'Note: this does NOT guarantee every key configuration invalidates. '
        'A policy with EnrollmentBinding.persistAcrossEnrollment (Android '
        'setInvalidatedByBiometricEnrollment(false) / iOS biometryAny) survives '
        'new enrollments by design.',
        style: TextStyle(fontSize: 12),
      ),
    ]);
  }

  Widget _card(String title, List<Widget> children) => Card(
    child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
          ),
          const SizedBox(height: 8),
          ...children,
        ],
      ),
    ),
  );

  Widget _btn(String label, VoidCallback onPressed) =>
      FilledButton(onPressed: onPressed, child: Text(label));

  Widget _row(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 175,
          child: Text(
            label,
            style: const TextStyle(fontWeight: FontWeight.w600),
          ),
        ),
        Expanded(child: Text(value)),
      ],
    ),
  );
}
