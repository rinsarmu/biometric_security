// Basic widget test for the example app.

import 'package:biometric_security_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('example app renders the three-flow demo', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const ExampleApp());
    await tester.pump();

    // Title (app bar) and the login section (near the top of the list) render.
    expect(find.text('Biometric Security Demo'), findsOneWidget);
    expect(find.text('Enable Biometric Login'), findsOneWidget);
    expect(find.text('Biometric Availability'), findsOneWidget);
  });
}
