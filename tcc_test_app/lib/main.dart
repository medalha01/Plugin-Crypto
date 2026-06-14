import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:plugin_crypto/plugin_crypto.dart';

void main() {
  runApp(const TCCTestApp());
}

class TCCTestApp extends StatelessWidget {
  const TCCTestApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TCC Test App',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      home: const CryptoHomePage(title: 'PluginCrypto Test Suite'),
    );
  }
}

class CryptoHomePage extends StatefulWidget {
  const CryptoHomePage({super.key, required this.title});
  final String title;

  @override
  State<CryptoHomePage> createState() => _CryptoHomePageState();
}

class _CryptoHomePageState extends State<CryptoHomePage>
    with TickerProviderStateMixin {
  late final TabController _tabController;
  String _opensslVersion = 'Initializing...';
  String _platformVersion = '...';
  bool _initialized = false;
  String? _error;

  final _results = <String, List<String>>{};

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 6, vsync: this);
    _initCrypto();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _initCrypto() async {
    try {
      final plugin = PluginCrypto.instance;
      final platVersion = await plugin.getPlatformVersion();
      final crypto = plugin.api;
      final version = crypto.getOpenSSLVersion();
      if (mounted) {
        setState(() {
          _platformVersion = platVersion ?? 'Unknown';
          _opensslVersion = version;
          _initialized = true;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _initialized = true;
        });
      }
    }
  }

  void _addResult(String key, String value) {
    setState(() {
      _results.putIfAbsent(key, () => []).add(value);
    });
  }

  void _clearResults(String key) {
    setState(() {
      _results.remove(key);
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!_initialized) {
      return Scaffold(
        appBar: AppBar(title: Text(widget.title)),
        body: const Center(child: CircularProgressIndicator()),
      );
    }
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(title: Text(widget.title)),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.error_outline, size: 56, color: Colors.red),
                const SizedBox(height: 16),
                const Text('Failed to initialize PluginCrypto',
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                const SizedBox(height: 8),
                Text(_error!,
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: Colors.red, fontFamily: 'monospace')),
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: _showInfoDialog,
                  icon: const Icon(Icons.info),
                  label: const Text('Setup Instructions'),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        bottom: TabBar(
          controller: _tabController,
          isScrollable: true,
          tabAlignment: TabAlignment.start,
          tabs: const [
            Tab(text: 'Info'),
            Tab(text: 'Hash'),
            Tab(text: 'AES'),
            Tab(text: 'RSA'),
            Tab(text: 'ECDSA'),
            Tab(text: 'X509/CMS'),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: _showInfoDialog,
            tooltip: 'Version info',
          ),
        ],
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _InfoTab(
            platformVersion: _platformVersion,
            opensslVersion: _opensslVersion,
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
          _HashTab(
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
          _AesTab(
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
          _RsaTab(
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
          _EcdsaTab(
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
          _X509Tab(
            addResult: _addResult,
            clearResults: _clearResults,
            results: _results,
          ),
        ],
      ),
    );
  }

  void _showInfoDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Environment'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _infoRow('Platform', _platformVersion),
            _infoRow('OpenSSL', _opensslVersion),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 80, child: Text('$label:', style: const TextStyle(fontWeight: FontWeight.bold))),
          Expanded(child: Text(value, style: const TextStyle(fontFamily: 'monospace'))),
        ],
      ),
    );
  }
}



String _bytesToHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');

class _SectionCard extends StatelessWidget {
  final String title;
  final String description;
  final VoidCallback onRun;
  final IconData icon;
  final List<String> results;
  final String resultsKey;
  final VoidCallback onClear;

  const _SectionCard({
    required this.title,
    required this.description,
    required this.onRun,
    required this.icon,
    required this.results,
    required this.resultsKey,
    required this.onClear,
  });

  @override
  Widget build(BuildContext context) {
    final list = results;
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 22, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(title,
                      style: Theme.of(context).textTheme.titleMedium),
                ),
                IconButton(
                  icon: const Icon(Icons.play_arrow, size: 28),
                  onPressed: onRun,
                  tooltip: 'Run',
                ),
                if (list.isNotEmpty)
                  IconButton(
                    icon: const Icon(Icons.clear_all, size: 20),
                    onPressed: onClear,
                    tooltip: 'Clear',
                  ),
              ],
            ),
            if (description.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(description,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: Colors.grey)),
            ],
            if (list.isNotEmpty) ...[
              const Divider(height: 16),
              for (var i = 0; i < list.length; i++)
                Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: SelectableText(
                    list[i],
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 11),
                  ),
                ),
            ],
          ],
        ),
      ),
    );
  }
}


class _InfoTab extends StatelessWidget {
  final String platformVersion;
  final String opensslVersion;
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _InfoTab({
    required this.platformVersion,
    required this.opensslVersion,
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.devices),
            title: const Text('Platform'),
            subtitle:
                Text(platformVersion, style: const TextStyle(fontFamily: 'monospace')),
          ),
        ),
        Card(
          child: ListTile(
            leading: const Icon(Icons.lock),
            title: const Text('OpenSSL'),
            subtitle:
                Text(opensslVersion, style: const TextStyle(fontFamily: 'monospace')),
          ),
        ),
        _SectionCard(
          title: 'Secure Random Bytes',
          description: 'Generate cryptographically secure random bytes.',
          icon: Icons.shuffle,
          resultsKey: 'random',
          results: results['random'] ?? [],
          onClear: () => clearResults('random'),
          onRun: () {
            try {
              final crypto = PluginCrypto.instance.api;
              final bytes = crypto.randomBytes(32);
              final hex =
                  bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
              addResult('random', '32 bytes: $hex');
            } catch (e) {
              addResult('random', 'ERROR: $e');
            }
          },
        ),
      ],
    );
  }
}


class _HashTab extends StatelessWidget {
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _HashTab({
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        _SectionCard(
          title: 'SHA-256',
          description: 'Digest of "Hello from PluginCrypto!"',
          icon: Icons.fingerprint,
          resultsKey: 'sha256',
          results: results['sha256'] ?? [],
          onClear: () => clearResults('sha256'),
          onRun: () {
            try {
              final data = utf8.encode('Hello from PluginCrypto!');
              final hash = PluginCrypto.instance.api.sha256(data);
              addResult('sha256', 'SHA-256: ${_hex(hash)}');
            } catch (e) {
              addResult('sha256', 'ERROR: $e');
            }
          },
        ),
        _SectionCard(
          title: 'SHA-512',
          description: 'Digest of timestamped input.',
          icon: Icons.fingerprint,
          resultsKey: 'sha512',
          results: results['sha512'] ?? [],
          onClear: () => clearResults('sha512'),
          onRun: () {
            try {
              final data =
                  utf8.encode('SHA-512 test at ${DateTime.now().toIso8601String()}');
              final hash = PluginCrypto.instance.api.sha512(data);
              addResult('sha512', 'SHA-512: ${_hex(hash)}');
            } catch (e) {
              addResult('sha512', 'ERROR: $e');
            }
          },
        ),
        _SectionCard(
          title: 'SHA3-256',
          description: 'SHA-3 (Keccak) 256-bit digest.',
          icon: Icons.fingerprint,
          resultsKey: 'sha3_256',
          results: results['sha3_256'] ?? [],
          onClear: () => clearResults('sha3_256'),
          onRun: () {
            try {
              final data = utf8.encode('SHA3-256 test');
              final hash = PluginCrypto.instance.api.sha3_256(data);
              addResult('sha3_256', 'SHA3-256: ${_hex(hash)}');
            } catch (e) {
              addResult('sha3_256', 'ERROR: $e');
            }
          },
        ),
        _SectionCard(
          title: 'SHA3-512',
          description: 'SHA-3 (Keccak) 512-bit digest.',
          icon: Icons.fingerprint,
          resultsKey: 'sha3_512',
          results: results['sha3_512'] ?? [],
          onClear: () => clearResults('sha3_512'),
          onRun: () {
            try {
              final data = utf8.encode('SHA3-512 test');
              final hash = PluginCrypto.instance.api.sha3_512(data);
              addResult('sha3_512', 'SHA3-512: ${_hex(hash)}');
            } catch (e) {
              addResult('sha3_512', 'ERROR: $e');
            }
          },
        ),
      ],
    );
  }
}


class _AesTab extends StatelessWidget {
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _AesTab({
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join('');

  void _testAes128Cbc() {
    try {
      final api = PluginCrypto.instance.api;
      final key = api.randomBytes(16);
      final iv = api.randomBytes(16);
      final plaintext = utf8.encode('Secret message for AES-128-CBC test!');
      final ciphertext = api.aes128CbcEncrypt(key, iv, Uint8List.fromList(plaintext));
      final decrypted = api.aes128CbcDecrypt(key, iv, ciphertext);
      final success = utf8.decode(decrypted) == utf8.decode(plaintext);
      addResult('aes_cbc',
          'AES-128-CBC: ${success ? "PASS" : "FAIL"} (key=${_hex(key)}, iv=${_hex(iv)})');
    } catch (e) {
      addResult('aes_cbc', 'AES-128-CBC ERROR: $e');
    }
  }

  void _testAes256Cbc() {
    try {
      final api = PluginCrypto.instance.api;
      final key = api.randomBytes(32);
      final iv = api.randomBytes(16);
      final plaintext = utf8.encode('Secret message for AES-256-CBC test!');
      final ciphertext = api.aes256CbcEncrypt(key, iv, Uint8List.fromList(plaintext));
      final decrypted = api.aes256CbcDecrypt(key, iv, ciphertext);
      final success = utf8.decode(decrypted) == utf8.decode(plaintext);
      addResult('aes_cbc',
          'AES-256-CBC: ${success ? "PASS" : "FAIL"} (key=${_hex(key)})');
    } catch (e) {
      addResult('aes_cbc', 'AES-256-CBC ERROR: $e');
    }
  }

  void _testAes128Gcm() {
    try {
      final api = PluginCrypto.instance.api;
      final key = api.randomBytes(16);
      final iv = api.randomBytes(12); // GCM typically uses 12-byte IV
      final plaintext = utf8.encode('Secret GCM message!');
      final result =
          api.aes128GcmEncrypt(key, iv, Uint8List.fromList(plaintext));
      final decrypted = api.aes128GcmDecrypt(
          key, iv, result.ciphertext, result.tag);
      final success = utf8.decode(decrypted) == utf8.decode(plaintext);
      addResult('aes_gcm',
          'AES-128-GCM: ${success ? "PASS" : "FAIL"} (tag=${_hex(result.tag)})');
    } catch (e) {
      addResult('aes_gcm', 'AES-128-GCM ERROR: $e');
    }
  }

  void _testAes256Gcm() {
    try {
      final api = PluginCrypto.instance.api;
      final key = api.randomBytes(32);
      final iv = api.randomBytes(12);
      final plaintext = utf8.encode('Secret GCM-256 message!');
      final result =
          api.aes256GcmEncrypt(key, iv, Uint8List.fromList(plaintext));
      final decrypted = api.aes256GcmDecrypt(
          key, iv, result.ciphertext, result.tag);
      final success = utf8.decode(decrypted) == utf8.decode(plaintext);
      addResult('aes_gcm',
          'AES-256-GCM: ${success ? "PASS" : "FAIL"} (tag=${_hex(result.tag)})');
    } catch (e) {
      addResult('aes_gcm', 'AES-256-GCM ERROR: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        _SectionCard(
          title: 'AES-128-CBC Encrypt/Decrypt',
          description: 'Symmetric encryption with 128-bit key.',
          icon: Icons.enhanced_encryption,
          onRun: _testAes128Cbc,
          resultsKey: 'aes_cbc',
          results: results['aes_cbc'] ?? [],
          onClear: () => clearResults('aes_cbc'),
        ),
        _SectionCard(
          title: 'AES-256-CBC Encrypt/Decrypt',
          description: 'Symmetric encryption with 256-bit key.',
          icon: Icons.enhanced_encryption,
          onRun: _testAes256Cbc,
          resultsKey: 'aes_cbc',
          results: const [],
          onClear: () => clearResults('aes_cbc'),
        ),
        _SectionCard(
          title: 'AES-128-GCM Encrypt/Decrypt',
          description: 'Authenticated encryption with 128-bit key.',
          icon: Icons.security,
          onRun: _testAes128Gcm,
          resultsKey: 'aes_gcm',
          results: results['aes_gcm'] ?? [],
          onClear: () => clearResults('aes_gcm'),
        ),
        _SectionCard(
          title: 'AES-256-GCM Encrypt/Decrypt',
          description: 'Authenticated encryption with 256-bit key.',
          icon: Icons.security,
          onRun: _testAes256Gcm,
          resultsKey: 'aes_gcm',
          results: const [],
          onClear: () => clearResults('aes_gcm'),
        ),
      ],
    );
  }
}


class _RsaTab extends StatefulWidget {
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _RsaTab({
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  @override
  State<_RsaTab> createState() => _RsaTabState();
}

class _RsaTabState extends State<_RsaTab> {

  String? _rsaPrivKey;
  String? _rsaPubKey;


  void _generateKey() {
    try {
      final api = PluginCrypto.instance.api;
      final kp = api.generateRsaKeyPair(2048);
      _rsaPrivKey = kp.privateKeyPem;
      _rsaPubKey = kp.publicKeyPem;
      widget.addResult('rsa', 'RSA-2048 key generated.');
      widget.addResult('rsa', 'Public key: ${kp.publicKeyPem.substring(0, 60)}...');
    } catch (e) {
      widget.addResult('rsa', 'RSA keygen ERROR: $e');
    }
  }

  void _signAndVerify() {
    try {
      if (_rsaPrivKey == null || _rsaPubKey == null) {
        widget.addResult('rsa_sv', 'Run key generation first!');
        return;
      }
      final api = PluginCrypto.instance.api;
      final data = utf8.encode('Sign this RSA message');
      final sig = api.sign(
          Uint8List.fromList(data), Uint8List.fromList(utf8.encode(_rsaPrivKey!)));
      final ok = api.verify(Uint8List.fromList(data),
          Uint8List.fromList(utf8.encode(_rsaPubKey!)), sig);
      widget.addResult('rsa_sv',
          'RSA Sign+Verify: ${ok ? "PASS" : "FAIL"} (sig=${_bytesToHex(sig).substring(0, 32)}...)');
    } catch (e) {
      widget.addResult('rsa_sv', 'RSA Sign+Verify ERROR: $e');
    }
  }

  void _encryptDecrypt() {
    try {
      if (_rsaPrivKey == null || _rsaPubKey == null) {
        widget.addResult('rsa_enc', 'Run key generation first!');
        return;
      }
      final api = PluginCrypto.instance.api;
      final plaintext = utf8.encode('RSA OEAP test');
      final ct = api.rsaEncrypt(
          Uint8List.fromList(utf8.encode(_rsaPubKey!)), Uint8List.fromList(plaintext));
      final pt = api.rsaDecrypt(
          Uint8List.fromList(utf8.encode(_rsaPrivKey!)), ct);
      final ok = utf8.decode(pt) == utf8.decode(plaintext);
      widget.addResult(
          'rsa_enc', 'RSA Encrypt+Decrypt: ${ok ? "PASS" : "FAIL"}');
    } catch (e) {
      widget.addResult('rsa_enc', 'RSA Encrypt+Decrypt ERROR: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        _SectionCard(
          title: 'Generate RSA-2048 Key Pair',
          description: 'Creates a 2048-bit RSA key pair (may take a moment).',
          icon: Icons.vpn_key,
          onRun: _generateKey,
          resultsKey: 'rsa',
          results: widget.results['rsa'] ?? [],
          onClear: () => widget.clearResults('rsa'),
        ),
        _SectionCard(
          title: 'RSA Sign & Verify (SHA-256)',
          description: 'Signs data with private key, verifies with public key.',
          icon: Icons.draw,
          onRun: _signAndVerify,
          resultsKey: 'rsa_sv',
          results: widget.results['rsa_sv'] ?? [],
          onClear: () => widget.clearResults('rsa_sv'),
        ),
        _SectionCard(
          title: 'RSA-OAEP Encrypt & Decrypt',
          description: 'Encrypts with public key, decrypts with private key.',
          icon: Icons.lock_outline,
          onRun: _encryptDecrypt,
          resultsKey: 'rsa_enc',
          results: widget.results['rsa_enc'] ?? [],
          onClear: () => widget.clearResults('rsa_enc'),
        ),
      ],
    );
  }
}


class _EcdsaTab extends StatefulWidget {
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _EcdsaTab({
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  @override
  State<_EcdsaTab> createState() => _EcdsaTabState();
}

class _EcdsaTabState extends State<_EcdsaTab> {

  static const _curves = ['prime256v1', 'secp384r1', 'secp521r1'];
  String? _ecPrivKey;
  String? _ecPubKey;
  String _currentCurve = _curves[0];


  void _generateKey() {
    try {
      final api = PluginCrypto.instance.api;
      final kp = api.generateEcKeyPair(_currentCurve);
      _ecPrivKey = kp.privateKeyPem;
      _ecPubKey = kp.publicKeyPem;
      widget.addResult('ec',
          'EC $_currentCurve key generated.\nPublic: ${kp.publicKeyPem.substring(0, 60)}...');
    } catch (e) {
      widget.addResult('ec', 'EC keygen ERROR: $e');
    }
  }

  void _signAndVerify() {
    try {
      if (_ecPrivKey == null || _ecPubKey == null) {
        widget.addResult('ec_sv', 'Run key generation first!');
        return;
      }
      final api = PluginCrypto.instance.api;
      final data = utf8.encode('Sign this EC message');
      final sig = api.sign(
          Uint8List.fromList(data), Uint8List.fromList(utf8.encode(_ecPrivKey!)));
      final ok = api.verify(Uint8List.fromList(data),
          Uint8List.fromList(utf8.encode(_ecPubKey!)), sig);
      widget.addResult('ec_sv',
          'ECDSA Sign+Verify: ${ok ? "PASS" : "FAIL"} (curve=$_currentCurve, sig_len=${sig.length})');
    } catch (e) {
      widget.addResult('ec_sv', 'ECDSA Sign+Verify ERROR: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Card(
          margin: const EdgeInsets.all(6),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: DropdownButtonFormField<String>(
              initialValue: _currentCurve,
              decoration: const InputDecoration(
                  labelText: 'Curve', icon: Icon(Icons.show_chart)),
              items: _curves
                  .map((c) => DropdownMenuItem(value: c, child: Text(c)))
                  .toList(),
              onChanged: (v) {
                _currentCurve = v!;
                _clearAll();
              },
            ),
          ),
        ),
        _SectionCard(
          title: 'Generate EC Key Pair',
          description: 'Creates an EC key pair for $_currentCurve.',
          icon: Icons.vpn_key,
          onRun: _generateKey,
          resultsKey: 'ec',
          results: widget.results['ec'] ?? [],
          onClear: () => widget.clearResults('ec'),
        ),
        _SectionCard(
          title: 'ECDSA Sign & Verify',
          description: 'Signs data with private key, verifies with public key.',
          icon: Icons.draw,
          onRun: _signAndVerify,
          resultsKey: 'ec_sv',
          results: widget.results['ec_sv'] ?? [],
          onClear: () => widget.clearResults('ec_sv'),
        ),
      ],
    );
  }

  void _clearAll() {
    widget.clearResults('ec');
    widget.clearResults('ec_sv');
    _ecPrivKey = null;
    _ecPubKey = null;
  }
}


/// Self-signed test certificate (PEM) for X.509 and CMS testing.
const String _testCertPem = '-----BEGIN CERTIFICATE-----\n'
    'MIIBzDCCAXOgAwIBAgIUH54hr75+amZlGPVbIOu9q5sI+EcwCgYIKoZIzj0EAwIw\n'
    'PDEWMBQGA1UEAwwNVENDIFRlc3QgQ2VydDEVMBMGA1UECgwMUGx1Z2luQ3J5cHRv\n'
    'MQswCQYDVQQGEwJCUjAeFw0yNjA0MzAyMTIxMzhaFw0yNzA0MzAyMTIxMzhaMDwx\n'
    'FjAUBgNVBAMMDVRDQyBUZXN0IENlcnQxFTATBgNVBAoMDFBsdWdpbkNyeXB0bzEL\n'
    'MAkGA1UEBhMCQlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQB66E/jM6bhlxJ\n'
    'mr2CxRGmAhjqkWoV+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oH\n'
    'Ut6+DVYto1MwUTAdBgNVHQ4EFgQUtpQurNbwHoYUVW7AI1xr4+2IdRYwHwYDVR0j\n'
    'BBgwFoAUtpQurNbwHoYUVW7AI1xr4+2IdRYwDwYDVR0TAQH/BAUwAwEB/zAKBggq\n'
    'hkjOPQQDAgNHADBEAiBQxobhr3wdWEFsVLDv2IeI/NFKw/O3W3nf0jYm9kDRsAIg\n'
    'fy6XTViHpFXzM0Rgfl1sJ7i26Haehg32D3x11tzBbMg=\n'
    '-----END CERTIFICATE-----\n';

/// Private key corresponding to [_testCertPem] (PEM, unencrypted).
const String _testKeyPem = '-----BEGIN PRIVATE KEY-----\n'
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuXtpWM2SqBrFzQj\n'
    '/4wlOs6BJb1WzvA8uLnjdlWoWAehRANCAAQB66E/jM6bhlxJmr2CxRGmAhjqkWoV\n'
    '+vHM0skuGup80eaZnL/DNfZVL+jztysG+hwTqcz0FNMQF2oHUt6+DVYt\n'
    '-----END PRIVATE KEY-----\n';

class _X509Tab extends StatelessWidget {
  final void Function(String, String) addResult;
  final void Function(String) clearResults;
  final Map<String, List<String>> results;

  const _X509Tab({
    required this.addResult,
    required this.clearResults,
    required this.results,
  });

  void _testCmsSignVerify() {
    try {
      final api = PluginCrypto.instance.api;
      final data = utf8.encode('CMS test data — sign & verify');
      final certBytes = utf8.encode(_testCertPem);
      final keyBytes = utf8.encode(_testKeyPem);
      final cmsDer = api.cmsSign(
          Uint8List.fromList(data),
          Uint8List.fromList(certBytes),
          Uint8List.fromList(keyBytes));
      final ok = api.cmsVerify(cmsDer);
      addResult('cms_sv',
          'CMS Sign+Verify: ${ok ? "PASS" : "FAIL"} (${cmsDer.length} bytes DER)');
    } catch (e) {
      addResult('cms_sv', 'CMS Sign+Verify ERROR: $e');
    }
  }

  void _testCmsEncryptDecrypt() {
    try {
      final api = PluginCrypto.instance.api;
      final plaintext = utf8.encode('CMS encrypted secret message!');
      final certBytes = utf8.encode(_testCertPem);
      final keyBytes = utf8.encode(_testKeyPem);
      final encrypted = api.cmsEncrypt(
          Uint8List.fromList(plaintext), Uint8List.fromList(certBytes));
      final decrypted = api.cmsDecrypt(
          encrypted, Uint8List.fromList(certBytes), Uint8List.fromList(keyBytes));
      final ok = utf8.decode(decrypted) == utf8.decode(plaintext);
      addResult('cms_enc',
          'CMS Encrypt+Decrypt: ${ok ? "PASS" : "FAIL"} (${encrypted.length} bytes DER)');
    } catch (e) {
      addResult('cms_enc', 'CMS Encrypt+Decrypt ERROR: $e');
    }
  }

  void _testX509Parsing() {
    try {
      final api = PluginCrypto.instance.api;
      final cert = api.parseX509Certificate(
          Uint8List.fromList(utf8.encode(_testCertPem)));
      addResult('x509', 'X.509 Certificate Parsed:');
      addResult('x509', '  Subject   : ${cert.subject}');
      addResult('x509', '  Issuer    : ${cert.issuer}');
      addResult('x509', '  Serial    : ${cert.serialNumber}');
      addResult('x509', '  Not Before: ${cert.notBefore.toUtc().toString()}');
      addResult('x509', '  Not After : ${cert.notAfter.toUtc().toString()}');
      addResult('x509', '  DER size  : ${cert.rawDer.length} bytes');
    } catch (e) {
      addResult('x509', 'X.509 parse ERROR: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        _SectionCard(
          title: 'CMS/PKCS#7 Sign & Verify',
          description: 'Creates CMS signed data with test cert, then verifies it.',
          icon: Icons.verified_user,
          onRun: _testCmsSignVerify,
          resultsKey: 'cms_sv',
          results: results['cms_sv'] ?? [],
          onClear: () => clearResults('cms_sv'),
        ),
        _SectionCard(
          title: 'CMS/PKCS#7 Encrypt & Decrypt',
          description: 'Encrypts data to test cert, then decrypts with private key.',
          icon: Icons.enhanced_encryption,
          onRun: _testCmsEncryptDecrypt,
          resultsKey: 'cms_enc',
          results: results['cms_enc'] ?? [],
          onClear: () => clearResults('cms_enc'),
        ),
        _SectionCard(
          title: 'X.509 Certificate Parsing',
          description:
              'Parses a self-signed test certificate. Displays subject, issuer, validity dates.',
          icon: Icons.description,
          onRun: _testX509Parsing,
          resultsKey: 'x509',
          results: results['x509'] ?? [],
          onClear: () => clearResults('x509'),
        ),
      ],
    );
  }
}
