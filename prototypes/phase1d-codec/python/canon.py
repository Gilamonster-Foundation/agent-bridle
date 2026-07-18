#!/usr/bin/env python3
"""Phase-1d codec — PYTHON prototype (non-normative).

Mirrors ../rust/src/main.rs exactly: same constrained canonical DAG-CBOR
encoder, same signed-object construction, same FIXED input + FIXED Ed25519
seed. Emits a golden vector to diff against the Rust reference. Pure-stdlib
encoder; only blake3 + ed25519 are external.
"""
import json
import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Value representation: ("uint", n) | ("text", s) | ("bytes", b) |
# ("array", [..]) | ("map", [(k, v), ..]) | ("cid", cid_bytes)


def head(major, arg, out):
    mt = major << 5
    if arg < 24:
        out.append(mt | arg)
    elif arg < 0x100:
        out.append(mt | 24)
        out.append(arg)
    elif arg < 0x10000:
        out.append(mt | 25)
        out += arg.to_bytes(2, "big")
    elif arg < 0x100000000:
        out.append(mt | 26)
        out += arg.to_bytes(4, "big")
    else:
        out.append(mt | 27)
        out += arg.to_bytes(8, "big")


def encode(v, out):
    tag = v[0]
    if tag == "uint":
        head(0, v[1], out)
    elif tag == "text":
        b = v[1].encode("utf-8")
        head(3, len(b), out)
        out += b
    elif tag == "bytes":
        head(2, len(v[1]), out)
        out += v[1]
    elif tag == "array":
        head(4, len(v[1]), out)
        for e in v[1]:
            encode(e, out)
    elif tag == "map":
        entries = []
        for (k, val) in v[1]:
            kb = bytearray()
            encode(("text", k), kb)
            entries.append((bytes(kb), val))
        entries.sort(key=lambda e: e[0])  # bytewise on encoded key
        for i in range(1, len(entries)):
            assert entries[i - 1][0] != entries[i][0], "duplicate map key"
        head(5, len(entries), out)
        for (kb, val) in entries:
            out += kb
            encode(val, out)
    elif tag == "cid":
        head(6, 42, out)
        bs = bytes([0x00]) + v[1]  # 0x00 multibase-identity ++ CID
        head(2, len(bs), out)
        out += bs
    else:
        raise ValueError(f"forbidden value type: {tag}")


def canonical(v):
    out = bytearray()
    encode(v, out)
    return bytes(out)


def cidv1_dagcbor_blake3(body):
    digest = blake3.blake3(body).digest()  # 32 bytes
    return bytes([0x01, 0x71, 0x1E, 0x20]) + digest


def main():
    profile = "agent-bridle/permission-request/v1"
    codec = "dag-cbor"
    domain_tuple = ("array", [
        ("text", "agent-bridle/permission-request/record/v1"),
        ("bytes", bytes([0x00])),          # store_id = STORE_ID_SELF
        ("text", "thread-genesis"),
        ("uint", 0),                        # generation
        ("map", [("action", ("text", "read")), ("effect", ("text", "allow")), ("x", ("uint", 1))]),
    ])

    sk = Ed25519PrivateKey.from_private_bytes(bytes(32))
    pubkey = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = bytes([0xED, 0x01]) + pubkey  # multicodec ed25519-pub

    body = canonical(domain_tuple)
    cid = cidv1_dagcbor_blake3(body)
    protected = canonical(("array", [
        ("text", "agent-bridle/signed-object/v1"),
        ("text", profile),
        ("text", codec),
        ("cid", cid),
        ("bytes", signer),
    ]))
    sig = sk.sign(protected)  # deterministic (RFC 8032)

    print(json.dumps({
        "lang": "python",
        "body": body.hex(),
        "cid": cid.hex(),
        "protected": protected.hex(),
        "sig": sig.hex(),
        "signer": signer.hex(),
    }, indent=2))


if __name__ == "__main__":
    main()
