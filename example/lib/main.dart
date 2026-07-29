import 'dart:io' show Platform;

import 'package:biometric_security/biometric_security.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const ExampleApp());
}

// ---------------------------------------------------------------------------
// Example-only constants and pure, unit-testable helpers (see example/test/).
// The test PIN lives ONLY in the example app, never in the package.
// ---------------------------------------------------------------------------

/// TEST-ONLY correct PIN for this demo. Never ship a hardcoded PIN.
const String kTestPin = '123654';

/// The logical key under which the biometric-protected login PIN is stored.
const SecretKey kLoginPinKey = SecretKey('biometric_login_pin');

/// The observable state of a biometric-protected secret, derived from a `read()`.
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
  Widget build(BuildContext context) => const MaterialApp(home: HomePage());
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final BiometricSecurity _security = BiometricSecurity();

  bool _initialized = false;
  BiometricAvailability? _availability;
  SecurityStatus? _securityStatus;

  bool _loginEnabled = false;
  ProtectedKeyState _keyState = ProtectedKeyState.unknown;
  String? _lastRetrievedPin;
  String _log = '';

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      await _security.initialize();
      _initialized = true;
      await _refreshState();
    } catch (e) {
      _append('Init error: $e');
    }
  }

  void _append(String line) {
    if (mounted) setState(() => _log = '$line\n$_log');
  }

  Future<void> _refreshState() async {
    if (!_initialized) return;
    final a = await _security.getAvailability();
    final enabled = await _security.contains(key: kLoginPinKey);
    if (!mounted) return;
    setState(() {
      _availability = a;
      _loginEnabled = enabled;
    });
  }

  // ------------------------------------------------------------------------
  // UC1 — Enable biometric login (validate PIN in-app, then protect it)
  // ------------------------------------------------------------------------

  Future<void> _enableBiometricLogin() async {
    final entered = await _askPin();
    if (entered == null) return; // sheet dismissed

    // Test 2: wrong PIN — reject, enable nothing, store nothing.
    if (entered != kTestPin) {
      _append(
        '✗ PIN incorrect. Biometric login remains disabled. Nothing stored.',
      );
      await _refreshState();
      return;
    }

    try {
      // iOS: a gated Keychain *write* does not prompt, so we explicitly
      // authenticate first to show the prompt during enable. Android's gated
      // write already prompts, so we skip the extra prompt there.
      if (Platform.isIOS) {
        await _security.authenticate(
          reason: 'Confirm to enable biometric login',
        );
      }
      await _security.write(
        key: kLoginPinKey,
        value: entered,
        policy: SecurityPolicy.strong(),
        reason: 'Enable biometric login',
      );
      setState(() {
        _loginEnabled = true;
        _keyState = ProtectedKeyState.valid;
      });
      _append('✓ Biometric login enabled. PIN securely protected.');
    } on BiometricAuthCanceledException {
      _append(
        '✗ Enable canceled. Biometric login not enabled; nothing stored.',
      );
    } on BiometricSecurityException catch (e) {
      _append('✗ Enable failed → ${e.runtimeType}: ${e.message}');
    }
    await _refreshState();
  }

  Future<void> _disableBiometricLogin() async {
    try {
      await _security.revoke(key: kLoginPinKey);
      setState(() {
        _loginEnabled = false;
        _keyState = ProtectedKeyState.absent;
        _lastRetrievedPin = null;
      });
      _append('✓ Biometric login disabled and revoked.');
    } on BiometricSecurityException catch (e) {
      _append('✗ Disable failed → ${e.message}');
    }
  }

  // ------------------------------------------------------------------------
  // UC2 — Biometric login (check state → authenticate → retrieve PIN)
  // ------------------------------------------------------------------------

  Future<void> _loginWithBiometrics() async {
    if (!await _security.contains(key: kLoginPinKey)) {
      _append('✗ Biometric login is not enabled. Enable it first.');
      return;
    }
    final a = await _security.getAvailability();
    if (!a.canAuthenticate) {
      _append('✗ Biometric login cannot proceed — reason: ${a.status.name}.');
      return;
    }

    try {
      // read() checks key validity FIRST (throws before prompting if
      // invalidated), then prompts, then returns the protected PIN.
      final pin = await _security.read(
        key: kLoginPinKey,
        reason: 'Log in with biometrics',
      );
      if (!mounted) return;
      if (pin == null) {
        setState(() {
          _loginEnabled = false;
          _keyState = ProtectedKeyState.absent;
        });
        _append(
          '✗ Login: no protected PIN found. Enable biometric login first.',
        );
        return;
      }
      setState(() {
        _keyState = ProtectedKeyState.valid;
        _lastRetrievedPin = pin;
      });
      _append(
        '✓ Authentication successful. Retrieved PIN: $pin (TEST-ONLY display)',
      );
    } on KeyInvalidatedException catch (e) {
      // Security event: enrollment/key changed → do NOT retrieve, revoke login.
      _append(
        '✗ Biometric login INVALIDATED (enrollment/key changed): ${e.message}',
      );
      await _security.revoke(key: kLoginPinKey);
      if (!mounted) return;
      setState(() {
        _loginEnabled = false;
        _keyState = ProtectedKeyState.invalidated;
        _lastRetrievedPin = null;
      });
      _append(
        ' → Biometric login disabled. Please enable it again with your PIN.',
      );
    } on BiometricAuthCanceledException {
      _append('✗ Login canceled by user.');
    } on BiometricSecurityException catch (e) {
      setState(() => _keyState = keyStateForError(e));
      _append('✗ Login failed → ${e.runtimeType}: ${e.message}');
    }
    await _refreshState();
  }

  // ------------------------------------------------------------------------
  // UC3 — Normal authentication (never touches the PIN)
  // ------------------------------------------------------------------------

  Future<void> _normalAuthenticate() async {
    final a = await _security.getAvailability();
    if (!a.canAuthenticate) {
      _append('✗ Cannot authenticate — reason: ${a.status.name}.');
      return;
    }
    try {
      final session = await _security.authenticate(
        reason: 'Verify your identity',
      );
      _append(
        '✓ Authentication successful (presence verified, level='
        '${session.securityLevel.name}). PIN was NOT accessed.',
      );
    } on BiometricAuthCanceledException {
      _append('✗ Authentication canceled.');
    } on BiometricSecurityException catch (e) {
      _append('✗ Authentication failed → ${e.runtimeType}: ${e.message}');
    }
  }

  Future<void> _checkSecurityStatus() async {
    try {
      final s = await _security.getSecurityStatus();
      if (mounted) setState(() => _securityStatus = s);
      _append('Security status refreshed.');
    } on BiometricSecurityException catch (e) {
      _append('✗ Security status → ${e.message}');
    }
  }

  Future<String?> _askPin() async {
    final controller = TextEditingController();
    return showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(
          left: 16,
          right: 16,
          top: 16,
          bottom: MediaQuery.of(ctx).viewInsets.bottom + 16,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Enter your PIN',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
            ),
            const SizedBox(height: 4),
            const Text('(test PIN: 123654)', style: TextStyle(fontSize: 12)),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              keyboardType: TextInputType.number,
              obscureText: true,
              autofocus: true,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'PIN',
              ),
              onSubmitted: (v) => Navigator.of(ctx).pop(v),
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(controller.text),
              child: const Text('Continue'),
            ),
          ],
        ),
      ),
    );
  }

  // ------------------------------------------------------------------------
  // UI
  // ------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Biometric Security Demo')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _availabilityCard(),
          const SizedBox(height: 12),
          _loginCard(),
          const SizedBox(height: 12),
          _normalAuthCard(),
          const SizedBox(height: 12),
          _securityStatusCard(),
          const SizedBox(height: 12),
          _retrievedPinCard(),
          const SizedBox(height: 12),
          _card('Logs', [
            Text(_log, style: const TextStyle(fontFamily: 'monospace')),
          ]),
        ],
      ),
    );
  }

  Widget _availabilityCard() {
    final a = _availability;
    return _card('Biometric Availability', [
      if (a == null)
        const Text('Checking…')
      else ...[
        _row('Supported', a.isSupported ? 'Yes' : 'No'),
        _row('Available', a.canAuthenticate ? 'Yes' : 'No'),
        _row('Enrolled', _enrolledText(a)),
        _row('Strength', a.strength.name),
        _row('Status', a.status.name),
      ],
      const SizedBox(height: 8),
      _btn('Refresh Availability', () async {
        await _refreshState();
        _append('Availability: ${a == null ? '' : enrollmentSummary(a)}');
      }),
    ]);
  }

  String _enrolledText(BiometricAvailability a) {
    if (a.enrolledModalities.isNotEmpty) {
      return a.enrolledModalities.map((m) => m.name).join(', ');
    }
    // Android can't enumerate; infer from status/strength.
    if (a.status == BiometricStatus.ready) return 'Yes (not enumerated)';
    if (a.status == BiometricStatus.notEnrolled) return 'No';
    return a.status.name;
  }

  Widget _loginCard() {
    return _card('Biometric Login', [
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('Enable Biometric Login'),
        subtitle: Text(_loginEnabled ? 'ON' : 'OFF'),
        value: _loginEnabled,
        onChanged: (v) =>
            v ? _enableBiometricLogin() : _disableBiometricLogin(),
      ),
      const SizedBox(height: 8),
      _btn('🔐 Login with Biometrics', _loginWithBiometrics),
    ]);
  }

  Widget _normalAuthCard() {
    return _card('Normal Authentication', [
      const Text('Proves the user is present. Does NOT read or write the PIN.'),
      const SizedBox(height: 8),
      _btn('Authenticate', _normalAuthenticate),
    ]);
  }

  Widget _securityStatusCard() {
    final s = _securityStatus;
    return _card('Security Status', [
      _row('Biometric Login', _loginEnabled ? 'Enabled' : 'Disabled'),
      _row(
        'Enrollment',
        _availability == null ? '—' : _availability!.status.name,
      ),
      _row('Key', _keyValidityText()),
      if (s != null) ...[
        _row('Achievable level', s.achievableSecurityLevel.name),
        _row('Reprovision required', s.reprovisionRequired.toString()),
        _row('Integrity risk', s.integrityRisk.toString()),
      ],
      const SizedBox(height: 8),
      _btn('Check Security Status', _checkSecurityStatus),
    ]);
  }

  String _keyValidityText() {
    switch (_keyState) {
      case ProtectedKeyState.valid:
        return 'Valid (verified at last login)';
      case ProtectedKeyState.invalidated:
        return 'INVALIDATED — re-enable required';
      case ProtectedKeyState.absent:
        return 'No key stored';
      case ProtectedKeyState.error:
        return 'Error / unavailable';
      case ProtectedKeyState.unknown:
        return 'Unknown — log in to verify';
    }
  }

  Widget _retrievedPinCard() {
    return _card('Last Retrieved PIN (TEST ONLY)', [
      const Text(
        'A real app would NEVER display the PIN. Shown here only to prove '
        'retrieval after biometric authentication.',
        style: TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
      ),
      const SizedBox(height: 8),
      Text(
        _lastRetrievedPin ?? '(none)',
        style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold),
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
          width: 165,
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
