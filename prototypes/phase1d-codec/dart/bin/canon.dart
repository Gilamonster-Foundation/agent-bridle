// Phase-1d codec — Dart prototype (non-normative).
// Mirrors ../../rust/src/main.rs exactly. Emits a golden vector to diff.
import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:blake3_dart/blake3_dart.dart';

sealed class V {}

class VUint extends V {
  final int n;
  VUint(this.n);
}

class VText extends V {
  final String s;
  VText(this.s);
}

class VBytes extends V {
  final List<int> b;
  VBytes(this.b);
}

class VArray extends V {
  final List<V> a;
  VArray(this.a);
}

class VMap extends V {
  final List<MapEntry<String, V>> m;
  VMap(this.m);
}

class VCid extends V {
  final List<int> c;
  VCid(this.c);
}

void head(int major, int arg, List<int> out) {
  final mt = major << 5;
  if (arg < 24) {
    out.add(mt | arg);
  } else if (arg < 0x100) {
    out.addAll([mt | 24, arg]);
  } else if (arg < 0x10000) {
    out.addAll([mt | 25, (arg >> 8) & 0xff, arg & 0xff]);
  } else if (arg < 0x100000000) {
    out.addAll([mt | 26, (arg >> 24) & 0xff, (arg >> 16) & 0xff, (arg >> 8) & 0xff, arg & 0xff]);
  } else {
    for (var i = 7; i >= 0; i--) {
      if (i == 7) out.add(mt | 27);
      out.add((arg >> (i * 8)) & 0xff);
    }
  }
}

int cmpBytes(List<int> a, List<int> b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

void encode(V v, List<int> out) {
  switch (v) {
    case VUint(:final n):
      head(0, n, out);
    case VText(:final s):
      final b = utf8.encode(s);
      head(3, b.length, out);
      out.addAll(b);
    case VBytes(:final b):
      head(2, b.length, out);
      out.addAll(b);
    case VArray(:final a):
      head(4, a.length, out);
      for (final e in a) {
        encode(e, out);
      }
    case VMap(:final m):
      final entries = m.map((e) {
        final kb = <int>[];
        encode(VText(e.key), kb);
        return MapEntry(kb, e.value);
      }).toList();
      entries.sort((x, y) => cmpBytes(x.key, y.key));
      for (var i = 1; i < entries.length; i++) {
        if (cmpBytes(entries[i - 1].key, entries[i].key) == 0) {
          throw StateError('duplicate map key');
        }
      }
      head(5, entries.length, out);
      for (final e in entries) {
        out.addAll(e.key);
        encode(e.value, out);
      }
    case VCid(:final c):
      head(6, 42, out);
      final bs = <int>[0x00, ...c];
      head(2, bs.length, out);
      out.addAll(bs);
  }
}

List<int> canonical(V v) {
  final out = <int>[];
  encode(v, out);
  return out;
}

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

List<int> cidv1(List<int> body) {
  final digest = blake3(Uint8List.fromList(body)); // 32 bytes, pure Dart
  return [0x01, 0x71, 0x1e, 0x20, ...digest];
}


void main() {
  const profile = 'agent-bridle/permission-request/v1';
  const codec = 'dag-cbor';
  final domainTuple = VArray([
    VText('agent-bridle/permission-request/record/v1'),
    VBytes([0x00]), // store_id = STORE_ID_SELF
    VText('thread-genesis'),
    VUint(0), // generation
    VMap([MapEntry('action', VText('read')), MapEntry('effect', VText('allow')), MapEntry('x', VUint(1))]),
  ]);

  final priv = ed.newKeyFromSeed(Uint8List(32)); // all-zero seed
  final pubkey = ed.public(priv).bytes;
  final signer = <int>[0xed, 0x01, ...pubkey]; // multicodec ed25519-pub

  final body = canonical(domainTuple);
  final cid = cidv1(body);
  final protected = canonical(VArray([
    VText('agent-bridle/signed-object/v1'),
    VText(profile),
    VText(codec),
    VCid(cid),
    VBytes(signer),
  ]));
  final sig = ed.sign(priv, Uint8List.fromList(protected)); // deterministic RFC 8032
  print(const JsonEncoder.withIndent('  ').convert({
    'lang': 'dart',
    'body': hex(body),
    'cid': hex(cid),
    'protected': hex(protected),
    'sig': hex(sig),
    'signer': hex(signer),
  }));
}
