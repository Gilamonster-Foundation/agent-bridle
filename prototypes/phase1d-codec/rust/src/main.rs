//! Phase-1d codec — RUST REFERENCE prototype (non-normative).
//!
//! Implements the constrained canonical DAG-CBOR encoder + the signed-object
//! construction from ../README.md, and emits a golden vector for a FIXED input
//! and a FIXED Ed25519 seed. The Python/Dart/TS prototypes must reproduce this
//! byte-for-byte. `diff` the emitted vectors; any divergence is a codec bug.

use ed25519_dalek::{Signer, SigningKey};

/// The only value types allowed on the wire (see README value-space table).
enum Value {
    Uint(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    /// map with string keys; canonicalized (sorted, dedup) at encode time.
    Map(Vec<(String, Value)>),
    /// a CIDv1 link (the raw CID bytes, WITHOUT the 0x00 multibase prefix).
    Cid(Vec<u8>),
}

/// CBOR head: major type (0..7) + argument, in the SMALLEST length form.
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg < 0x100 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg < 0x1_0000 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => head(0, *n, out),
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(a) => {
            head(4, a.len() as u64, out);
            for e in a {
                encode(e, out);
            }
        }
        Value::Map(m) => {
            // canonical: sort entries by their ENCODED-KEY bytes; reject dups.
            let mut entries: Vec<(Vec<u8>, &Value)> = m
                .iter()
                .map(|(k, val)| {
                    let mut kb = Vec::new();
                    encode(&Value::Text(k.clone()), &mut kb);
                    (kb, val)
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for w in entries.windows(2) {
                assert_ne!(w[0].0, w[1].0, "duplicate map key — fail closed");
            }
            head(5, entries.len() as u64, out);
            for (kb, val) in entries {
                out.extend_from_slice(&kb);
                encode(val, out);
            }
        }
        Value::Cid(cid) => {
            // tag 42 wrapping a byte string = 0x00 (multibase identity) ++ CID.
            head(6, 42, out);
            let mut bs = vec![0x00];
            bs.extend_from_slice(cid);
            head(2, bs.len() as u64, out);
            out.extend_from_slice(&bs);
        }
    }
}

fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode(v, &mut out);
    out
}

/// CIDv1 binary: 0x01 (version) ++ 0x71 (dag-cbor) ++ 0x1e 0x20 (blake3-256, 32) ++ digest.
fn cidv1_dagcbor_blake3(body: &[u8]) -> Vec<u8> {
    let digest = blake3::hash(body);
    let mut cid = vec![0x01, 0x71, 0x1e, 0x20];
    cid.extend_from_slice(digest.as_bytes());
    cid
}

fn main() {
    // ── FIXED input (the Python/Dart/TS prototypes copy this exactly) ──
    let profile = "agent-bridle/permission-request/v1";
    let codec = "dag-cbor";
    let domain_tuple = Value::Array(vec![
        Value::Text(format!("agent-bridle/permission-request/record/v1")),
        Value::Bytes(vec![0x00]), // store_id = STORE_ID_SELF (genesis)
        Value::Text("thread-genesis".to_string()),
        Value::Uint(0), // generation
        Value::Map(vec![
            ("action".to_string(), Value::Text("read".to_string())),
            ("effect".to_string(), Value::Text("allow".to_string())),
            ("x".to_string(), Value::Uint(1)),
        ]),
    ]);

    // ── FIXED key (all-zero 32-byte seed → deterministic pubkey/sig) ──
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    let pubkey = sk.verifying_key().to_bytes(); // 32 bytes
    let mut signer = vec![0xed, 0x01]; // multicodec ed25519-pub
    signer.extend_from_slice(&pubkey);

    // ── construction ──
    let body = canonical(&domain_tuple);
    let cid = cidv1_dagcbor_blake3(&body);
    let protected = canonical(&Value::Array(vec![
        Value::Text("agent-bridle/signed-object/v1".to_string()),
        Value::Text(profile.to_string()),
        Value::Text(codec.to_string()),
        Value::Cid(cid.clone()),
        Value::Bytes(signer.clone()),
    ]));
    let sig = sk.sign(&protected).to_bytes(); // 64 bytes, deterministic

    let vector = serde_json::json!({
        "lang": "rust",
        "body": hex::encode(&body),
        "cid": hex::encode(&cid),
        "protected": hex::encode(&protected),
        "sig": hex::encode(&sig),
        "signer": hex::encode(&signer),
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
