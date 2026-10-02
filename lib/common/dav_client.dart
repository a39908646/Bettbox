import 'dart:async';
import 'dart:io';

import 'package:bett_box/common/common.dart';
import 'package:bett_box/models/models.dart';
import 'package:bett_box/plugins/app.dart';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:webdav_client/webdav_client.dart';

class DAVClient {
  static const _userAgent =
      'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/126.0.0.0 Mobile Safari/537.36';

  late Client client;
  Completer<bool> pingCompleter = Completer();
  late String fileName;
  late final Uri _serverUri;

  DAVClient(DAV dav) {
    client = newClient(dav.uri, user: dav.user, password: dav.password);
    fileName = dav.fileName;
    _serverUri = Uri.parse(dav.uri);
    client.c.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          if (!_hasSameOrigin(options.uri, _serverUri)) {
            options.headers.remove('authorization');
            options.headers.remove('Authorization');
          }
          handler.next(options);
        },
        onResponse: (response, handler) {
          final challenges = response.headers['www-authenticate'];
          if (response.statusCode == 401 &&
              challenges != null &&
              challenges.length > 1) {
            response.headers.set('www-authenticate', challenges.join(', '));
          }
          handler.next(response);
        },
      ),
    );
    client.setHeaders({
      'accept-charset': 'utf-8',
      'Content-Type': 'text/xml',
      // Some WebDAV endpoints sit behind an edge/WAF that resets requests
      // carrying tool-like User-Agents (dio/webdav_client defaults), so send a
      // regular browser UA.
      'User-Agent': _userAgent,
    });
    client.setConnectTimeout(15000);
    client.setSendTimeout(120000);
    client.setReceiveTimeout(120000);
    pingCompleter.complete(_ping());
  }

  /// Diagnostic summary appended to user-visible errors, so the failure can
  /// be told apart without digging into the log page.
  Future<String> _diagSummary() async {
    final buf = StringBuffer();
    if (system.isAndroid) {
      try {
        buf.write(
          'LNP-permission: ${await app.hasLocalNetworkPermission()} | ',
        );
      } catch (_) {}
    }
    try {
      final addresses = await InternetAddress.lookup(_serverUri.host)
          .timeout(const Duration(seconds: 5));
      buf.write(
        'DNS: ${addresses.map((e) => '${e.address}(${e.type == InternetAddressType.IPv6 ? 'v6' : 'v4'})').join(', ')}',
      );
    } catch (e) {
      buf.write('DNS lookup failed: $e');
    }
    try {
      final interfaces = await NetworkInterface.list(
        includeLinkLocal: false,
        type: InternetAddressType.any,
      );
      buf.write(
        ' | ifaces: ${interfaces.map((e) => '${e.name}[${e.addresses.map((a) => a.type == InternetAddressType.IPv6 ? 'v6' : 'v4').toSet().join('/')}]').join(', ')}',
      );
    } catch (_) {}
    buf.write(
      ' | url: $_serverUri | ${await _connectDiag()}',
    );
    final text = buf.toString();
    // Copy to clipboard so the diagnostic survives the toast/dialog.
    try {
      await Clipboard.setData(ClipboardData(text: text));
    } catch (_) {}
    return text;
  }

  /// Control targets used to tell "this server is unreachable" apart from
  /// "the app cannot reach any IPv6 host at all" (both are public DoH
  /// endpoints that accept TCP on 443 over IPv6).
  static const _v6ControlTargets = <String>[
    '2606:4700:4700::1111',
    '2400:3200:baba::1',
  ];

  /// Diagnostic: bisect HTTP vs TLS vs TCP vs other-IPv6-hosts, so a stuck
  /// handshake can be told apart from an unreachable address and from an
  /// app-wide IPv6 problem.
  Future<String> _connectDiag() async {
    final host = _serverUri.host;
    final port = _serverUri.port;
    final out = StringBuffer();

    final results = await Future.wait<String>([
      _httpDiag(),
      _tcpDiag(host, port),
      _tlsDiag(host, port),
      _controlDiag(),
      _sourceAddressDiag(host, port),
    ]);
    out.write(results.where((e) => e.isNotEmpty).join(' | '));
    return out.toString();
  }

  Future<String> _httpDiag() async {
    try {
      final httpClient = HttpClient()
        ..connectionTimeout = const Duration(seconds: 6);
      final request = await httpClient.getUrl(_serverUri);
      final response = await request.close().timeout(
        const Duration(seconds: 8),
      );
      httpClient.close(force: true);
      return 'HTTP[GET ${_serverUri.path}] -> ${response.statusCode}';
    } catch (e) {
      return 'HTTP[GET ${_serverUri.path}] FAIL ${e.runtimeType}: $e';
    }
  }

  Future<String> _tcpDiag(String host, int port) async {
    try {
      final target = await _firstAddress(host);
      final watch = Stopwatch()..start();
      final socket = await Socket.connect(
        target,
        port,
        timeout: const Duration(seconds: 6),
      );
      socket.destroy();
      return 'TCP[$host:$port -> ${target.address}] ok ${watch.elapsedMilliseconds}ms';
    } catch (e) {
      return 'TCP[$host:$port] FAIL ${e.runtimeType}: $e';
    }
  }

  Future<String> _tlsDiag(String host, int port) async {
    try {
      final watch = Stopwatch()..start();
      final socket = await SecureSocket.connect(
        host,
        port,
        timeout: const Duration(seconds: 8),
      );
      socket.destroy();
      return 'TLS ok ${watch.elapsedMilliseconds}ms';
    } catch (e) {
      return 'TLS FAIL ${e.runtimeType}: $e';
    }
  }

  Future<String> _controlDiag() async {
    final parts = <String>[];
    for (final control in _v6ControlTargets) {
      try {
        final socket = await Socket.connect(
          InternetAddress(control),
          443,
          timeout: const Duration(seconds: 6),
        );
        socket.destroy();
        parts.add('TCP[$control:443] ok');
      } catch (e) {
        parts.add('TCP[$control:443] FAIL ${e.runtimeType}');
      }
    }
    return parts.join(' , ');
  }

  Future<InternetAddress> _firstAddress(String host) async {
    final addresses = await InternetAddress.lookup(
      host,
    ).timeout(const Duration(seconds: 5));
    return addresses.firstWhere(
      (e) => e.type == InternetAddressType.IPv6,
      orElse: () => addresses.first,
    );
  }

  /// Source-address selection: the device may have several global IPv6
  /// interfaces (wlan0 + mobile data). Bind each candidate source address
  /// explicitly to the same server, to tell an unreachable server apart from
  /// a socket routed out of the wrong interface.
  Future<String> _sourceAddressDiag(String host, int port) async {
    final parts = <String>[];
    try {
      final target = await _firstAddress(host);
      if (target.type != InternetAddressType.IPv6) return '';
      final interfaces = await NetworkInterface.list(
        includeLinkLocal: false,
        type: InternetAddressType.IPv6,
      );
      var tried = 0;
      for (final itf in interfaces) {
        for (final address in itf.addresses) {
          if (address.type != InternetAddressType.IPv6) continue;
          final raw = address.rawAddress;
          final isUniqueLocal = raw.isNotEmpty && (raw[0] & 0xfe) == 0xfc;
          if (isUniqueLocal) continue;
          if (tried >= 4) break;
          tried++;
          try {
            final socket = await Socket.connect(
              target,
              port,
              sourceAddress: address,
              timeout: const Duration(seconds: 5),
            );
            socket.destroy();
            parts.add('SRC[${itf.name} ${address.address}] ok');
          } catch (e) {
            parts.add('SRC[${itf.name} ${address.address}] FAIL');
          }
        }
      }
    } catch (_) {}
    return parts.join(' , ');
  }

  Future<bool> _ping() async {
    try {
      await client.ping();
      commonPrint.log('WebDAV ping successful');
      return true;
    } catch (e) {
      commonPrint.log('WebDAV ping failed: ${e.runtimeType}: $e');
      await _logResolvedAddresses();
      return false;
    }
  }

  /// Diagnostic: record what the platform resolver returns for the server
  /// host, so IPv4/IPv6 reachability issues can be told apart from a
  /// routing/proxy problem.
  Future<void> _logResolvedAddresses() async {
    final host = _serverUri.host;
    try {
      final addresses = await InternetAddress.lookup(host)
          .timeout(const Duration(seconds: 5));
      if (addresses.isEmpty) {
        commonPrint.log('WebDAV diag: $host resolved to no address');
        return;
      }
      final list = addresses
          .map(
            (e) =>
                '${e.address}(${e.type == InternetAddressType.IPv6 ? 'v6' : 'v4'})',
          )
          .join(', ');
      commonPrint.log('WebDAV diag: $host -> $list');
    } catch (e) {
      commonPrint.log('WebDAV diag: lookup $host failed: $e');
    }
    await _logInterfaces();
  }

  /// Diagnostic: dump the active network interfaces so we can tell whether the
  /// request is being captured by the VPN tun device and whether the physical
  /// interface actually carries a global IPv6 address.
  Future<void> _logInterfaces() async {
    try {
      final interfaces = await NetworkInterface.list(
        includeLinkLocal: false,
        type: InternetAddressType.any,
      );
      for (final itf in interfaces) {
        final addrs = itf.addresses
            .map((e) => e.address)
            .take(4)
            .join(', ');
        commonPrint.log('WebDAV diag: iface ${itf.name} -> $addrs');
      }
    } catch (e) {
      commonPrint.log('WebDAV diag: interface dump failed: $e');
    }
  }

  String get root => '/$appName';

  String get baseName =>
      fileName.replaceAll(RegExp(r'\.zip$', caseSensitive: false), '');

  String get backupFile => '$root/$fileName';

  Future<List<File>> getBackupFiles() async {
    try {
      await client.mkdir(root);
    } catch (_) {}
    final List<File> rawFiles;
    try {
      rawFiles = await client.readDir(root);
    } catch (e) {
      commonPrint.log('WebDAV readDir failed: ${e.runtimeType}: $e');
      await _logResolvedAddresses();
      final diag = await _diagSummary();
      throw 'WebDAV readDir failed: ${_formatError(e)}\n[$diag]\n[${e.runtimeType}: $e]';
    }
    final reg = RegExp(
      '^${RegExp.escape(baseName)}(?:_(\\d{8})_(\\d{2}))?\\.zip\$',
      caseSensitive: false,
    );
    final validFiles = rawFiles.where((f) {
      if (f.isDir == true) return false;
      final name = f.name;
      if (name == null || name.isEmpty) return false;
      return reg.hasMatch(name);
    }).toList();

    validFiles.sort((a, b) {
      final nameA = a.name ?? '';
      final nameB = b.name ?? '';
      final matchA = reg.firstMatch(nameA);
      final matchB = reg.firstMatch(nameB);
      final dateA = matchA?.group(1);
      final seqA = matchA?.group(2);
      final dateB = matchB?.group(1);
      final seqB = matchB?.group(2);
      if (dateA != null && seqA != null && dateB != null && seqB != null) {
        final cmpDate = dateB.compareTo(dateA);
        if (cmpDate != 0) return cmpDate;
        return seqB.compareTo(seqA);
      }
      if (dateA != null && dateB == null) return -1;
      if (dateA == null && dateB != null) return 1;
      final timeA = a.mTime ?? DateTime.fromMillisecondsSinceEpoch(0);
      final timeB = b.mTime ?? DateTime.fromMillisecondsSinceEpoch(0);
      return timeB.compareTo(timeA);
    });

    return validFiles;
  }

  Future<String> getNextBackupFileName() async {
    final now = DateTime.now();
    final dateStr =
        '${now.year.toString().padLeft(4, '0')}${now.month.toString().padLeft(2, '0')}${now.day.toString().padLeft(2, '0')}';
    final reg = RegExp(
      '^${RegExp.escape(baseName)}_${dateStr}_(\\d{2})\\.zip\$',
      caseSensitive: false,
    );
    var maxSeq = 0;
    try {
      final files = await getBackupFiles();
      for (final f in files) {
        final match = reg.firstMatch(f.name ?? '');
        if (match != null) {
          final seq = int.tryParse(match.group(1) ?? '') ?? 0;
          if (seq > maxSeq) {
            maxSeq = seq;
          }
        }
      }
    } catch (_) {}
    final nextSeq = (maxSeq + 1).toString().padLeft(2, '0');
    return '${baseName}_${dateStr}_$nextSeq.zip';
  }

  Future<void> _pruneOldBackups() async {
    final files = await getBackupFiles();
    if (files.length > 10) {
      final toRemove = files.sublist(10);
      for (final f in toRemove) {
        final name = f.name;
        if (name != null && name.isNotEmpty) {
          try {
            await client.remove('$root/$name');
          } catch (e) {
            commonPrint.log('Prune backup failed: $e');
          }
        }
      }
    }
  }

  Future<bool> backup(Uint8List data) async {
    return await _retryOperation(() async {
      try {
        await client.mkdir(root);
      } catch (e) {
        commonPrint.log('WebDAV mkdir warning (may already exist): $e');
      }

      final targetName = await getNextBackupFileName();
      final targetPath = '$root/$targetName';
      commonPrint.log(
        'WebDAV backup: uploading ${data.length} bytes to $targetPath',
      );

      await client.write(targetPath, data);
      commonPrint.log('WebDAV backup successful');

      try {
        await _pruneOldBackups();
      } catch (_) {}

      return true;
    }, operationName: 'backup');
  }

  Future<List<int>> recovery([String? targetFileName]) async {
    return await _retryOperation(() async {
      final target = targetFileName ?? backupFile;
      final targetPath = target.startsWith('/') ? target : '$root/$target';
      commonPrint.log('WebDAV recovery: downloading from $targetPath');

      try {
        await client.mkdir(root);
      } catch (e) {
        commonPrint.log('WebDAV mkdir warning: $e');
      }

      final data = await client.read(targetPath);
      commonPrint.log('WebDAV recovery successful: ${data.length} bytes');
      return data;
    }, operationName: 'recovery');
  }

  bool _hasSameOrigin(Uri left, Uri right) {
    return left.scheme.toLowerCase() == right.scheme.toLowerCase() &&
        left.host.toLowerCase() == right.host.toLowerCase() &&
        left.port == right.port;
  }

  Future<T> _retryOperation<T>(
    Future<T> Function() operation, {
    required String operationName,
    int maxAttempts = 3,
  }) async {
    int attempt = 0;
    Duration delay = const Duration(seconds: 2);

    while (attempt < maxAttempts) {
      attempt++;

      try {
        return await operation();
      } catch (e) {
        final isLastAttempt = attempt >= maxAttempts;

        if (isLastAttempt) {
          commonPrint.log(
            'WebDAV $operationName failed after $maxAttempts attempts: $e',
          );
          await _logResolvedAddresses();
          final diag = await _diagSummary();
          throw 'WebDAV $operationName failed: ${_formatError(e)}\n[$diag]\n[${e.runtimeType}: $e]';
        }

        commonPrint.log(
          'WebDAV $operationName attempt $attempt failed: $e, retrying in ${delay.inSeconds}s...',
        );
        await Future.delayed(delay);

        delay *= 2;
      }
    }

    throw 'WebDAV $operationName failed: unexpected error';
  }

  String _formatError(dynamic error) {
    final errorStr = error.toString();

    if (errorStr.contains('SocketException') ||
        errorStr.contains('Connection')) {
      return 'Network connection failed. Please check your internet connection and WebDAV server address.';
    }

    if (errorStr.contains('401') || errorStr.contains('Unauthorized')) {
      return 'Authentication failed. Please check your username and password.';
    }

    if (errorStr.contains('403') || errorStr.contains('Forbidden')) {
      return 'Access denied. Please check your account permissions.';
    }

    if (errorStr.contains('404') || errorStr.contains('Not Found')) {
      return 'Backup file not found on server.';
    }

    if (errorStr.contains('timeout') || errorStr.contains('Timeout')) {
      return 'Operation timed out. Please check your network connection or try again later.';
    }

    if (errorStr.contains('507') || errorStr.contains('Insufficient Storage')) {
      return 'Server storage is full. Please free up space on your WebDAV server.';
    }

    return errorStr;
  }
}
