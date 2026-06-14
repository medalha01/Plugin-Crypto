
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:plugin_crypto/plugin_crypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('getPlatformVersion test', (WidgetTester tester) async {
    final PluginCrypto plugin = PluginCrypto.instance;
    final String? version = await plugin.getPlatformVersion();
    expect(version?.isNotEmpty, true);
  });
}
