// Phase-1d codec — TypeScript/JS prototype (non-normative).
// Mirrors ../rust/src/main.rs exactly. Pure-JS crypto via @noble (no native
// deps → best cross-platform reproducibility). Emits a golden vector to diff.
import { blake3 } from '@noble/hashes/blake3';
import { ed25519 } from '@noble/curves/ed25519';

// Value: {t:'uint',v} | {t:'text',v} | {t:'bytes',v:Uint8Array} |
//        {t:'array',v:[..]} | {t:'map',v:[[k,val],..]} | {t:'cid',v:Uint8Array}
const U = (v) => ({ t: 'uint', v });
const T = (v) => ({ t: 'text', v });
const B = (v) => ({ t: 'bytes', v });
const A = (v) => ({ t: 'array', v });
const M = (v) => ({ t: 'map', v });
const C = (v) => ({ t: 'cid', v });

function head(major, arg, out) {
  const mt = major << 5;
  if (arg < 24) out.push(mt | arg);
  else if (arg < 0x100) { out.push(mt | 24, arg); }
  else if (arg < 0x10000) { out.push(mt | 25, (arg >>> 8) & 0xff, arg & 0xff); }
  else if (arg < 0x100000000) {
    out.push(mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
  } else {
    const hi = Math.floor(arg / 0x100000000), lo = arg >>> 0;
    out.push(mt | 27, (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
             (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
  }
}

function encode(v, out) {
  switch (v.t) {
    case 'uint': head(0, v.v, out); break;
    case 'text': {
      const b = new TextEncoder().encode(v.v);
      head(3, b.length, out); for (const x of b) out.push(x); break;
    }
    case 'bytes': head(2, v.v.length, out); for (const x of v.v) out.push(x); break;
    case 'array': head(4, v.v.length, out); for (const e of v.v) encode(e, out); break;
    case 'map': {
      const entries = v.v.map(([k, val]) => {
        const kb = []; encode(T(k), kb); return [Uint8Array.from(kb), val];
      });
      entries.sort((a, b) => cmpBytes(a[0], b[0]));
      for (let i = 1; i < entries.length; i++)
        if (cmpBytes(entries[i - 1][0], entries[i][0]) === 0) throw new Error('duplicate map key');
      head(5, entries.length, out);
      for (const [kb, val] of entries) { for (const x of kb) out.push(x); encode(val, out); }
      break;
    }
    case 'cid': {
      head(6, 42, out);
      const bs = [0x00, ...v.v];
      head(2, bs.length, out); for (const x of bs) out.push(x); break;
    }
    default: throw new Error('forbidden value type: ' + v.t);
  }
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

const canonical = (v) => { const out = []; encode(v, out); return Uint8Array.from(out); };
const hex = (u8) => Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');

function cidv1(body) {
  const digest = blake3(body); // 32 bytes
  return Uint8Array.from([0x01, 0x71, 0x1e, 0x20, ...digest]);
}

const profile = 'agent-bridle/permission-request/v1';
const codec = 'dag-cbor';
const domainTuple = A([
  T('agent-bridle/permission-request/record/v1'),
  B(Uint8Array.from([0x00])),          // store_id = STORE_ID_SELF
  T('thread-genesis'),
  U(0),                                 // generation
  M([['action', T('read')], ['effect', T('allow')], ['x', U(1)]]),
]);

const sk = new Uint8Array(32);          // all-zero seed
const pubkey = ed25519.getPublicKey(sk);
const signer = Uint8Array.from([0xed, 0x01, ...pubkey]); // multicodec ed25519-pub

const body = canonical(domainTuple);
const cid = cidv1(body);
const protected_ = canonical(A([
  T('agent-bridle/signed-object/v1'), T(profile), T(codec), C(cid), B(signer),
]));
const sig = ed25519.sign(protected_, sk); // deterministic RFC 8032

console.log(JSON.stringify({
  lang: 'ts', body: hex(body), cid: hex(cid),
  protected: hex(protected_), sig: hex(sig), signer: hex(signer),
}, null, 2));
