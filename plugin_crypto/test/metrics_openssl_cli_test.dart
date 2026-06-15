import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

const _opensslBinary =
    '/mnt/c/Users/hiper/Workstation/TCC/_extracted/openssl_4.0.0_full/openssl-4.0.0/apps/openssl';
const _libPath =
    '/mnt/c/Users/hiper/Workstation/TCC/plugin_crypto/native/linux/x86_64';
const _warmupIter = 3;
const _iter = 20;

Map<String, dynamic> _runRaw(String command, {Map<String, String>? env}) {
  final envMap = <String, String>{
    'LD_LIBRARY_PATH':
        '$_libPath:${Platform.environment['LD_LIBRARY_PATH'] ?? ''}',
    if (env != null) ...env,
  };
  final stopwatch = Stopwatch()..start();
  final result = Process.runSync(
      'bash', ['-c', command],
      environment: envMap, runInShell: false);
  stopwatch.stop();
  return {
    'exitCode': result.exitCode,
    'stdout': (result.stdout as String).trim(),
    'stderr': (result.stderr as String).trim(),
    'elapsedUs': stopwatch.elapsedMicroseconds,
  };
}

String _tmpfile(String prefix) {
  final dir = Directory.systemTemp;
  return '${dir.path}/$prefix';
}

List<double> _measureOp(String command, int iterations, {int warmup = 3}) {
  final times = <double>[];
  for (var i = 0; i < warmup + iterations; i++) {
    final r = _runRaw(command);
    if (r['exitCode'] != 0) {
      throw StateError(
          'Command failed (exit ${r['exitCode']}): $command\nstderr: ${r['stderr']}');
    }
    if (i >= warmup) {
      times.add((r['elapsedUs'] as int).toDouble() / 1000.0);
    }
  }
  times.sort();
  return times;
}

void _reportStats(List<double> times, Map<String, dynamic> out) {
  times.sort();
  final n = times.length;
  final mean = times.reduce((a, b) => a + b) / n;
  final variance =
      times.map((t) => (t - mean) * (t - mean)).reduce((a, b) => a + b) / n;
  final stddev = n > 1 ? _sqrt(variance) : 0.0;

  out['mean_ms'] = mean;
  out['stddev_ms'] = stddev;
  out['min_ms'] = times.first;
  out['max_ms'] = times.last;
  out['p5_ms'] = times[(n * 0.05).floor()];
  out['p95_ms'] = times[(n * 0.95).floor().clamp(0, n - 1)];
  out['samples'] = n;
  out['raw_times_ms'] = times;
}

double _sqrt(double x) {
  if (x <= 0) return 0;
  var guess = x / 2;
  for (var i = 0; i < 20; i++) {
    guess = (guess + x / guess) / 2;
  }
  return guess;
}

void main() {
  final allResults = <String, dynamic>{};

  setUpAll(() {
    final v = _runRaw('$_opensslBinary version');
    allResults['openssl_version'] = v['stdout'];
  });

  test('baseline - empty process spawn overhead', () {
    final times = <double>[];
    for (var i = 0; i < _warmupIter + _iter; i++) {
      final r = _runRaw('true');
      if (i >= _warmupIter) {
        times.add((r['elapsedUs'] as int).toDouble() / 1000.0);
      }
    }
    _reportStats(times, (allResults['baseline_empty_process'] = <String, dynamic>{}));
    (allResults['baseline_empty_process'] as Map<String, dynamic>)['description'] =
        'Process.runSync(true) overhead ~27ms per spawn';
  });

  test('SHA-256 (1KB) via openssl speed', () {
    final r = _runRaw(
        '$_opensslBinary speed -seconds 2 -bytes 1024 -evp sha256 2>&1');
    final lines = (r['stdout'] as String)
        .split('\n')
        .where((l) => l.toLowerCase().contains('sha256'))
        .toList();
    double? opsPerSec;
    for (final line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].endsWith('k')) {
          final val = double.tryParse(parts[i].replaceAll('k', ''));
          if (val != null && val > 1000) opsPerSec = val * 1000;
        }
      }
    }
    final entry = allResults['sha256_1kb_openssl_speed'] = <String, dynamic>{};
    if (opsPerSec != null) {
      entry['ops_per_sec'] = opsPerSec;
      entry['us_per_op'] = 1e6 / (opsPerSec / 1024);
    } else {
      entry['error'] = 'Could not parse openssl speed output';
    }
  });

  test('SHA-256 (1KB) via dgst batch', () {
    final tf = _tmpfile('sha_in.bin');
    Process.runSync('dd', ['if=/dev/urandom', 'of=$tf', 'bs=1024', 'count=1']);
    const n = 100;
    final times = <double>[];
    for (var w = 0; w < _warmupIter; w++) {
      var cmd = '';
      for (var j = 0; j < n; j++) {
        cmd += '$_opensslBinary dgst -sha256 -binary $tf > /dev/null; ';
      }
      _runRaw(cmd);
    }
    for (var iter = 0; iter < 5; iter++) {
      var cmd = '';
      for (var j = 0; j < n; j++) {
        cmd += '$_opensslBinary dgst -sha256 -binary $tf > /dev/null; ';
      }
      final r = _runRaw(cmd);
      times.add((r['elapsedUs'] as int) / n / 1000.0);
    }
    times.sort();
    final entry = allResults['sha256_1kb_dgst_batch'] = <String, dynamic>{};
    _reportStats(times, entry);
    entry['description'] = 'openssl dgst -sha256 1KB, 100x batch, per-op ms';
    Process.runSync('rm', ['-f', tf]);
  });

  test('AES-256-GCM encrypt (1KB) via openssl speed', () {
    final r = _runRaw(
        '$_opensslBinary speed -seconds 2 -bytes 1024 -evp aes-256-gcm 2>&1');
    final lines = (r['stdout'] as String)
        .split('\n')
        .where((l) => l.toLowerCase().contains('aes-256-gcm'))
        .toList();
    double? opsPerSec;
    for (final line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));
      for (var i = 0; i < parts.length; i++) {
        if (parts[i].endsWith('k')) {
          final val = double.tryParse(parts[i].replaceAll('k', ''));
          if (val != null && val > 100) opsPerSec = val * 1000;
        }
      }
    }
    final entry = allResults['aes256gcm_1kb_openssl_speed'] = <String, dynamic>{};
    if (opsPerSec != null) {
      entry['ops_per_sec'] = opsPerSec;
      entry['us_per_op'] = 1e6 / (opsPerSec / 1024);
    } else {
      entry['error'] = 'Could not parse openssl speed output';
    }
  });

  test('AES-256-GCM (1KB) via enc batch', () {
    const keyHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const ivHex = '0123456789abcdef0123456789abcdef';
    final tf = _tmpfile('aes_in.bin');
    Process.runSync('dd', ['if=/dev/urandom', 'of=$tf', 'bs=1024', 'count=1']);
    const n = 50;
    final times = <double>[];
    for (var w = 0; w < _warmupIter; w++) {
      var cmd = '';
      for (var j = 0; j < n; j++) {
        cmd += '$_opensslBinary enc -aes-256-gcm -K $keyHex -iv $ivHex -in $tf -out /dev/null; ';
      }
      _runRaw(cmd);
    }
    for (var iter = 0; iter < 5; iter++) {
      var cmd = '';
      for (var j = 0; j < n; j++) {
        cmd += '$_opensslBinary enc -aes-256-gcm -K $keyHex -iv $ivHex -in $tf -out /dev/null; ';
      }
      final r = _runRaw(cmd);
      times.add((r['elapsedUs'] as int) / n / 1000.0);
    }
    times.sort();
    final entry = allResults['aes256gcm_1kb_enc_batch'] = <String, dynamic>{};
    _reportStats(times, entry);
    entry['description'] = 'openssl enc -aes-256-gcm 1KB, 50x batch, per-op ms';
    Process.runSync('rm', ['-f', tf]);
  });

  test('RSA-2048 keygen', () {
    final times = _measureOp(
        '$_opensslBinary genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null',
        _iter);
    final entry = allResults['rsa2048_keygen_openssl_cli'] = <String, dynamic>{};
    _reportStats(times, entry);
    entry['description'] = 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048';
  });

  test('ECDSA P-256 keygen + sign + verify', () {
    final kf = _tmpfile('eckey.pem');
    final df = _tmpfile('ecdata.bin');
    final sf = _tmpfile('ecsig.bin');
    Process.runSync('dd', ['if=/dev/urandom', 'of=$df', 'bs=32', 'count=1']);
    _runRaw('$_opensslBinary ecparam -name prime256v1 -genkey -noout -out $kf');

    var times = _measureOp('$_opensslBinary dgst -sha256 -sign $kf -out $sf $df', _iter);
    final se = allResults['ecdsa_p256_sign_cli'] = <String, dynamic>{};
    _reportStats(times, se);
    se['description'] = 'openssl dgst -sha256 -sign (ECDSA P-256)';

    times = _measureOp('$_opensslBinary dgst -sha256 -verify $kf -signature $sf $df', _iter);
    final ve = allResults['ecdsa_p256_verify_cli'] = <String, dynamic>{};
    _reportStats(times, ve);
    ve['description'] = 'openssl dgst -sha256 -verify (ECDSA P-256)';

    Process.runSync('rm', ['-f', kf, df, sf]);
  });

  test('ML-KEM-768 keygen + encaps + decaps', () {
    final kf = _tmpfile('mlkem_key.pem');
    final pf = _tmpfile('mlkem_pub.pem');
    final cf = _tmpfile('mlkem_ct.bin');
    final sk = _tmpfile('mlkem_sec.bin');
    final dk = _tmpfile('mlkem_dsec.bin');

    var times = _measureOp('$_opensslBinary genpkey -algorithm ML-KEM-768 -out $kf', _iter);
    final ke = allResults['mlkem768_keygen_cli'] = <String, dynamic>{};
    _reportStats(times, ke);
    ke['description'] = 'openssl genpkey -algorithm ML-KEM-768';

    _runRaw('$_opensslBinary pkey -in $kf -pubout -out $pf');
    times = _measureOp(
        '$_opensslBinary pkeyutl -encap -pubin -inkey $pf -out $cf -secret $sk', _iter);
    final ee = allResults['mlkem768_encaps_cli'] = <String, dynamic>{};
    _reportStats(times, ee);
    ee['description'] = 'openssl pkeyutl -encap ML-KEM-768';

    times = _measureOp(
        '$_opensslBinary pkeyutl -decap -inkey $kf -in $cf -secret $dk', _iter);
    final de = allResults['mlkem768_decaps_cli'] = <String, dynamic>{};
    _reportStats(times, de);
    de['description'] = 'openssl pkeyutl -decap ML-KEM-768';

    Process.runSync('rm', ['-f', kf, pf, cf, sk, dk]);
  });

  test('ML-DSA-44 keygen + sign + verify', () {
    final kf = _tmpfile('mldsa_key.pem');
    final df = _tmpfile('mldsa_data.bin');
    final sf = _tmpfile('mldsa_sig.bin');
    Process.runSync('dd', ['if=/dev/urandom', 'of=$df', 'bs=32', 'count=1']);

    var times = _measureOp('$_opensslBinary genpkey -algorithm ML-DSA-44 -out $kf', _iter);
    final ke = allResults['mldsa44_keygen_cli'] = <String, dynamic>{};
    _reportStats(times, ke);
    ke['description'] = 'openssl genpkey -algorithm ML-DSA-44';

    times = _measureOp('$_opensslBinary dgst -sign $kf -out $sf $df', _iter);
    final se = allResults['mldsa44_sign_cli'] = <String, dynamic>{};
    _reportStats(times, se);
    se['description'] = 'openssl dgst -sign (ML-DSA-44)';

    times = _measureOp('$_opensslBinary dgst -verify $kf -signature $sf $df', _iter);
    final ve = allResults['mldsa44_verify_cli'] = <String, dynamic>{};
    _reportStats(times, ve);
    ve['description'] = 'openssl dgst -verify (ML-DSA-44)';

    Process.runSync('rm', ['-f', kf, df, sf]);
  });

  tearDownAll(() {
    final outFile = Platform.environment['TCC_OPENSSL_CLI_OUTPUT'] ??
        '/tmp/tcc_openssl_cli_metrics.json';
    final encoded = const JsonEncoder.withIndent('  ').convert(allResults);
    File(outFile).writeAsStringSync(encoded);
  });
}
