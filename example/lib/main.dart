import 'package:biometric_security/biometric_security.dart';
import 'package:flutter/material.dart';

void main() {
  runApp(const ExampleApp());
}

class ExampleApp extends StatefulWidget {
  const ExampleApp({super.key});

  @override
  State<ExampleApp> createState() => _ExampleAppState();
}

class _ExampleAppState extends State<ExampleApp> {
  final BiometricSecurity _security = BiometricSecurity();
  static const _pin = SecretKey('demo_payment_pin');

  String _status = 'Not initialized';
  String _log = '';
  BiometricAvailability? _availability;

  @override
  void initState() {
    super.initState();
    _probe();
  }

  void _append(String line) {
    setState(() => _log = '$line\n$_log');
  }

  Future<void> _run(String label, Future<void> Function() action) async {
    try {
      await action();
      _append('✓ $label');
    } on BiometricSecurityException catch (e) {
      _append('✗ $label → ${e.runtimeType}: ${e.message}');
    }
  }

  Future<void> _probe() async {
    try {
      await _security.initialize();
      final availability = await _security.getAvailability();
      if (!mounted) return;
      setState(() {
        _status = 'Initialized';
        _availability = availability;
      });
    } on BiometricSecurityException catch (e) {
      if (!mounted) return;
      setState(() => _status = 'Error: ${e.message}');
    }
  }

  @override
  Widget build(BuildContext context) {
    final a = _availability;
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('biometric_security example')),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: ListView(
            children: [
              Text('Status: $_status',
                  style: const TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              if (a != null) ...[
                _row('Supported modalities', a.supportedModalities.toString()),
                _row('Strength', a.strength.name),
                _row('Can authenticate', a.canAuthenticate.toString()),
                _row('Status', a.status.name),
                _row('Has StrongBox', a.hasStrongBox.toString()),
                _row('Can force modality',
                    a.guarantees.canForceSpecificModality.toString()),
              ],
              const Divider(),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton(onPressed: _probe, child: const Text('Re-probe')),
                  FilledButton(
                    onPressed: () => _run(
                      'authenticate',
                      () => _security.authenticate(
                        reason: 'Verify it is you',
                      ),
                    ),
                    child: const Text('Authenticate'),
                  ),
                  FilledButton(
                    onPressed: () => _run(
                      'store protected PIN',
                      () => _security.write(
                        key: _pin,
                        value: '4321',
                        policy: SecurityPolicy.strong(),
                        reason: 'Confirm to save your PIN',
                      ),
                    ),
                    child: const Text('Store protected'),
                  ),
                  FilledButton(
                    onPressed: () => _run('read protected PIN', () async {
                      final value =
                          await _security.read(key: _pin, reason: 'Unlock PIN');
                      _append('  read → ${value ?? '(absent)'}');
                    }),
                    child: const Text('Read protected'),
                  ),
                  FilledButton(
                    onPressed: () =>
                        _run('revoke PIN', () => _security.revoke(key: _pin)),
                    child: const Text('Revoke'),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              const Text('Log:', style: TextStyle(fontWeight: FontWeight.bold)),
              Text(_log, style: const TextStyle(fontFamily: 'monospace')),
            ],
          ),
        ),
      ),
    );
  }

  Widget _row(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 170,
          child: Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
        ),
        Expanded(child: Text(value)),
      ],
    ),
  );
}
