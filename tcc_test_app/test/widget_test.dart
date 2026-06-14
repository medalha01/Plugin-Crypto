import 'package:flutter_test/flutter_test.dart';
import 'package:tcc_test_app/main.dart';

void main() {
  testWidgets('App builds without immediate crash', (WidgetTester tester) async {
    await tester.pumpWidget(const TCCTestApp());
    expect(find.byType(TCCTestApp), findsOneWidget);
  });
}
