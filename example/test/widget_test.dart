// Basic widget test for the example app.

import 'package:biometric_security_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('example app renders a status line', (WidgetTester tester) async {
    await tester.pumpWidget(const ExampleApp());
    await tester.pump();

    expect(find.textContaining('Status:'), findsOneWidget);
  });
}
