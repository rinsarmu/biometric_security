// Basic Flutter integration test for the biometric_security foundation.
//
// Integration tests run in a full Flutter application, so they exercise the
// host-side (native) plugin implementation. This verifies the read-only probe
// wiring returns a well-formed availability snapshot.
//
// https://flutter.dev/to/integration-testing

import 'package:biometric_security/biometric_security.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('initialize and getAvailability return without error', (
    WidgetTester tester,
  ) async {
    final security = BiometricSecurity();
    await security.initialize();
    expect(security.isInitialized, isTrue);

    final availability = await security.getAvailability();
    // The foundation returns a structurally valid snapshot on both platforms.
    expect(availability.status, isA<BiometricStatus>());
    expect(availability.guarantees.canForceSpecificModality, isFalse);
  });
}
