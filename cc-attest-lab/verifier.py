"""
Remote verifier: decides whether a chip deserves a secret.

It trusts two published facts and nothing the chip says about itself:
  endorsed   the manufacturer's list of genuine DeviceID public keys
  reference  the firmware vendor's reference measurement

The chip's messages reach it through the host, which may be hostile: every check below works even
if the host reads or rewrites the messages on the way.
"""
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SECRET = b"tenant-42 disk key: open sesame!"  # what the verifier guards (32 bytes)

def log(msg):
    print(f"[verifier] {msg}", flush=True)

def signed_by(public_key, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False

def appraise(evidence, nonce, endorsed, reference):
    """The four checks. Returns the report's key-release public key, or None."""
    device_id, cert, report, report_sig = (bytes.fromhex(x) for x in evidence)
    alias_pub, measurement, cert_sig = cert[:32], cert[32:64], cert[64:]
    report_nonce, wrap_pub = report[:32], report[32:]

    checks = [
        (device_id.hex() in endorsed,
         "the DeviceID key belongs to a genuine chip (manufacturer's list)"),
        (signed_by(device_id, cert_sig, alias_pub + measurement),
         "that chip's ROM signed the Alias certificate"),
        (measurement.hex() == reference,
         f"the certified measurement {measurement.hex()[:16]}... is the vendor's firmware"),
        (report_nonce == nonce and signed_by(alias_pub, report_sig, report),
         "the report carries our nonce and is signed by the certified Alias key"),
    ]
    for ok, what in checks:
        log(f"  {'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            return None
    return wrap_pub

def wrap(secret, wrap_pub):
    """Encrypt the secret to the X25519 key from the report. Returns (our public key, ciphertext)."""
    mine = X25519PrivateKey.generate()
    pad = hashlib.sha512(mine.exchange(X25519PublicKey.from_public_bytes(wrap_pub))).digest()
    return mine.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), bytes(a ^ b for a, b in zip(secret, pad))

def attest(lines, send, endorsed, reference):
    """Run one attestation. `lines` yields the chip's protocol lines, `send` delivers a line to it."""
    assert next(lines) == "HELLO"
    nonce = os.urandom(32)
    send(f"NONCE {nonce.hex()}")
    log(f"chip said HELLO, sent nonce {nonce.hex()[:16]}...")

    kind, *evidence = next(lines).split()
    assert kind == "EVIDENCE" and len(evidence) == 4, f"unexpected message {kind}"
    log("got evidence, appraising:")
    wrap_pub = appraise(evidence, nonce, endorsed, reference)
    if wrap_pub is None:
        send("DENIED evidence failed appraisal")
        log("secret NOT released")
        return
    their_pub, wrapped = wrap(SECRET, wrap_pub)
    send(f"SECRET {their_pub.hex()} {wrapped.hex()}")
    log("secret released, encrypted to the key in the report")
