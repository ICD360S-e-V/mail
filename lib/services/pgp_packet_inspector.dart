import 'dart:convert';
import 'dart:typed_data';

class PgpPacketInfo {
  final int tag;
  final int length;
  final String note;
  PgpPacketInfo({required this.tag, required this.length, this.note = ''});

  @override
  String toString() => 'Tag$tag ${_tagName(tag)} | ${length}B | $note';

  static String _tagName(int tag) => const {
    1: 'PKESK', 2: 'Sig', 3: 'SKESK', 4: 'OnePassSig',
    8: 'Compressed', 11: 'Literal', 18: 'SEIPD', 19: 'MDC',
    20: 'AEADEncData',
  }[tag] ?? '';
}

class PgpPacketInspector {
  final Uint8List _data;
  int _pos = 0;

  PgpPacketInspector._(this._data);

  static Uint8List dearmor(String armored) {
    final lines = armored.split('\n');
    final b64 = StringBuffer();
    bool inBody = false;
    for (final line in lines) {
      final t = line.trim();
      if (t.isEmpty && !inBody) { inBody = true; continue; }
      if (t.startsWith('-----')) { inBody = false; continue; }
      if (t.startsWith('=') && t.length <= 5) continue;
      if (inBody) b64.write(t);
    }
    return base64Decode(b64.toString());
  }

  static List<PgpPacketInfo> inspect(String armoredMessage) {
    try {
      final bytes = dearmor(armoredMessage);
      return PgpPacketInspector._(bytes)._parseAll();
    } catch (e) {
      return [PgpPacketInfo(tag: -1, length: 0, note: 'Parse error: $e')];
    }
  }

  static String summary(String armoredMessage) {
    final packets = inspect(armoredMessage);
    final buf = StringBuffer();
    for (final p in packets) {
      buf.writeln('  $p');
    }

    final seipd = packets.where((p) => p.tag == 18).firstOrNull;
    if (seipd != null) {
      if (seipd.note.contains('v1')) {
        buf.writeln('  → SEIPD v1 (CFB+MDC) — safe, no AEAD bug');
      } else if (seipd.note.contains('v2')) {
        buf.writeln('  → SEIPD v2 (AEAD) — vulnerable to OCB multi-chunk bug on large messages');
      }
    }
    return buf.toString().trimRight();
  }

  List<PgpPacketInfo> _parseAll() {
    final packets = <PgpPacketInfo>[];
    _pos = 0;
    while (_pos < _data.length) {
      try {
        packets.add(_parsePacket());
      } catch (_) {
        break;
      }
    }
    return packets;
  }

  PgpPacketInfo _parsePacket() {
    final hdr = _data[_pos++];
    if ((hdr & 0x80) == 0) throw FormatException('Bad packet tag');

    int tag;
    int bodyLen;
    if ((hdr & 0x40) != 0) {
      tag = hdr & 0x3F;
      bodyLen = _readNewLen();
    } else {
      tag = (hdr & 0x3C) >> 2;
      bodyLen = _readOldLen(hdr & 0x03);
    }

    final bodyStart = _pos;
    String note = '';

    if (tag == 1 && bodyLen >= 1) {
      final v = _data[_pos];
      if (v == 3 && bodyLen >= 10) {
        final kid = _data.sublist(_pos + 1, _pos + 9)
            .map((b) => b.toRadixString(16).padLeft(2, '0')).join();
        final algo = _data[_pos + 9];
        note = 'v3 keyID=$kid algo=${_pkAlgo(algo)}';
      } else if (v == 6) {
        note = 'v6 (RFC 9580)';
      } else {
        note = 'v$v';
      }
    } else if (tag == 18 && bodyLen >= 1) {
      final v = _data[_pos];
      if (v == 1) {
        note = 'v1 (CFB+MDC)';
      } else if (v == 2 && bodyLen >= 4) {
        final cipher = _data[_pos + 1];
        final aead = _data[_pos + 2];
        final cs = _data[_pos + 3];
        final chunkSize = 1 << (cs + 6);
        note = 'v2 (AEAD) cipher=${_symAlgo(cipher)} aead=${_aeadAlgo(aead)} chunk=${chunkSize}B';
      } else {
        note = 'v$v';
      }
    }

    _pos = bodyStart + bodyLen;
    return PgpPacketInfo(tag: tag, length: bodyLen, note: note);
  }

  int _readNewLen() {
    final f = _data[_pos++];
    if (f < 192) return f;
    if (f < 224) return ((f - 192) << 8) + _data[_pos++] + 192;
    if (f == 255) {
      final l = (_data[_pos] << 24) | (_data[_pos+1] << 16) |
                (_data[_pos+2] << 8) | _data[_pos+3];
      _pos += 4;
      return l;
    }
    return 1 << (f & 0x1F);
  }

  int _readOldLen(int t) {
    switch (t) {
      case 0: return _data[_pos++];
      case 1: final l = (_data[_pos] << 8) | _data[_pos+1]; _pos += 2; return l;
      case 2: final l = (_data[_pos]<<24)|(_data[_pos+1]<<16)|(_data[_pos+2]<<8)|_data[_pos+3]; _pos += 4; return l;
      default: return _data.length - _pos;
    }
  }

  static String _pkAlgo(int a) => const {
    1: 'RSA', 16: 'ElGamal', 22: 'ECDH', 25: 'X25519',
  }[a] ?? 'Algo$a';

  static String _symAlgo(int a) => const {
    7: 'AES128', 8: 'AES192', 9: 'AES256',
  }[a] ?? 'Sym$a';

  static String _aeadAlgo(int a) => const {
    1: 'EAX', 2: 'OCB', 3: 'GCM',
  }[a] ?? 'AEAD$a';
}
