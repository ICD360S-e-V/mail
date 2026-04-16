import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

import 'package:dart_pg/dart_pg.dart';

/// Long-lived background isolate for PGP decryption.
///
/// Holds the parsed private key in isolate memory — avoids re-parsing
/// per email. Accepts batch decrypt requests via SendPort.
/// UI thread is never blocked by OpenPGP.decrypt().
class PgpIsolateWorker {
  final SendPort _commands;
  final ReceivePort _responses;
  final Map<int, Completer<List<String?>>> _pending = {};
  int _nextId = 0;
  bool _closed = false;

  PgpIsolateWorker._(this._responses, this._commands) {
    _responses.listen(_onResponse);
  }

  /// Spawn the worker and send key material. Call once at vault unlock.
  static Future<PgpIsolateWorker> spawn({
    required String armoredKey,
    required String passphrase,
  }) async {
    final initPort = RawReceivePort();
    final completer = Completer<(ReceivePort, SendPort)>.sync();

    initPort.handler = (dynamic msg) {
      completer.complete((
        ReceivePort.fromRawReceivePort(initPort),
        msg as SendPort,
      ));
    };

    await Isolate.spawn(_isolateEntry, initPort.sendPort);
    final (responses, commands) = await completer.future;

    // Send key material once — isolate parses and caches it
    commands.send({'init': true, 'armoredKey': armoredKey, 'passphrase': passphrase});

    return PgpIsolateWorker._(responses, commands);
  }

  /// Decrypt a batch of armored ciphertexts off the UI thread.
  Future<List<String?>> decryptBatch(List<String> ciphertexts) {
    if (_closed) throw StateError('Worker is closed');
    final id = _nextId++;
    final completer = Completer<List<String?>>.sync();
    _pending[id] = completer;
    _commands.send({'id': id, 'ciphertexts': ciphertexts});
    return completer.future;
  }

  void _onResponse(dynamic message) {
    if (message is! Map) return;
    // Diagnostic messages from isolate (key init, errors)
    if (message.containsKey('diag')) {
      diagCallback?.call(message['diag'] as String);
      return;
    }
    final id = message['id'] as int;
    final completer = _pending.remove(id);
    if (completer == null) return;
    final plaintexts = (message['plaintexts'] as List).cast<String?>();
    // Log decrypt errors for any failed messages
    final errors = message['errors'] as List?;
    if (errors != null) {
      for (var i = 0; i < errors.length; i++) {
        if (errors[i] != null) {
          diagCallback?.call('Decrypt error [$i]: ${errors[i]}');
        }
      }
    }
    completer.complete(plaintexts);
    if (_closed && _pending.isEmpty) _responses.close();
  }

  void Function(String)? diagCallback;

  void close() {
    if (_closed) return;
    _closed = true;
    _commands.send('shutdown');
    if (_pending.isEmpty) _responses.close();
  }

  // ── Isolate entry point (static — required for Isolate.spawn) ────

  static void _isolateEntry(SendPort mainPort) {
    final receivePort = ReceivePort();
    mainPort.send(receivePort.sendPort);

    dynamic privateKey; // PrivateKeyInterface — held in isolate memory

    receivePort.listen((dynamic message) {
      if (message == 'shutdown') {
        receivePort.close();
        return;
      }

      final msg = message as Map;

      // Init: parse and cache key
      if (msg.containsKey('init')) {
        try {
          privateKey = OpenPGP.decryptPrivateKey(
            msg['armoredKey'] as String,
            msg['passphrase'] as String,
          );
          // Log the key fingerprint so we can verify which key the worker holds
          final fp = privateKey.fingerprint;
          mainPort.send({'diag': 'Worker initialized with key fingerprint: ${fp.toList().map((b) => b.toRadixString(16).padLeft(2, "0")).join().toUpperCase()}'});
        } catch (ex) {
          mainPort.send({'diag': 'Worker key parse FAILED: $ex'});
        }
        return;
      }

      // Batch decrypt
      if (msg.containsKey('id')) {
        final id = msg['id'] as int;
        final ciphertexts = (msg['ciphertexts'] as List).cast<String>();
        final plaintexts = <String?>[];
        final errors = <String?>[];

        for (final ct in ciphertexts) {
          try {
            if (privateKey == null) {
              plaintexts.add(null);
              errors.add('no private key loaded');
              continue;
            }
            final result = OpenPGP.decrypt(ct, decryptionKeys: [privateKey]);
            final literal = result.literalData;
            plaintexts.add(literal != null
                ? utf8.decode(literal.binary, allowMalformed: true)
                : null);
            errors.add(null);
          } catch (ex) {
            plaintexts.add(null);
            errors.add(ex.toString());
          }
        }

        mainPort.send({'id': id, 'plaintexts': plaintexts, 'errors': errors});
      }
    });
  }
}
