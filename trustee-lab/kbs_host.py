"""
The host side of the lab, talking to a Trustee KBS over HTTP.

  provision()  the tenant sets up Trustee: reference values, the secret, the resource policy
  attest()     the untrusted host relays the KBS protocol between Trustee and the chip's UART

The host never sees anything secret. It forwards the chip's evidence, which binds the KBS nonce
and the chip's TEE key, and it forwards a JWE that only the chip can decrypt.
"""
import base64
import http.cookiejar
import json
import urllib.error
import urllib.request

KBS = "http://127.0.0.1:8080/kbs/v0"
SECRET_PATH = "default/key/tenant-42"          # <repository>/<type>/<tag>

# Release a secret only if every appraised part of the evidence is "affirming".
# Same rule as Trustee's kbs/sample_policies/affirming.rego.
RESOURCE_POLICY = """package policy
import rego.v1

default allow = false

allow if {
    not any_not_affirming
    count(input.submods) > 0
}

any_not_affirming if {
    some _, submod in input.submods
    submod["ear.status"] != "affirming"
}
"""

def log(msg):
    print(f"[host] {msg}", flush=True)

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

class Kbs:
    def __init__(self):
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))  # keeps kbs-session-id

    def post(self, path, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(f"{KBS}/{path}", data=data, headers={"Content-Type": content_type})
        with self.http.open(req) as r:
            return r.read()

    def get(self, path):
        with self.http.open(f"{KBS}/{path}") as r:
            return r.read()

def provision(kbs, device_id, measurement, secret):
    """The tenant's setup. Reference values go to the RVPS, the secret to the KBS."""
    for name, value in (("litexdice_device_id", device_id), ("litexdice_firmware_measurement", measurement)):
        payload = base64.b64encode(json.dumps({name: [value]}).encode()).decode()
        kbs.post("reference-value", {"version": "0.1.0", "type": "sample", "payload": payload})
    kbs.post(f"resource/{SECRET_PATH}", secret, "application/octet-stream")
    kbs.post("resource-policy", {"policy": b64url(RESOURCE_POLICY.encode())})
    print(f"[tenant] Trustee knows DeviceID {device_id[:16]}... and firmware {measurement[:16]}..., "
          f"holds the secret at {SECRET_PATH}", flush=True)

def ear_summary(token):
    """The appraisal inside the attestation token (an EAR JWT): status and trust vector per submodule."""
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    return "; ".join(f"{name}: {sub['ear.status']}, " +
                     ", ".join(f"{k} {v}" for k, v in sub["ear.trustworthiness-vector"].items() if v)
                     for name, sub in claims["submods"].items())

def attest(kbs, chip_lines, send, tamper_evidence=None):
    """One RCAR exchange (Request, Challenge, Attestation, Response), then fetch the secret."""
    assert next(chip_lines) == "HELLO"                     # the firmware is ready to attest
    challenge = json.loads(kbs.post("auth", {"version": "0.4.0", "tee": "litexdice", "extra-params": {}}))
    log(f"KBS challenge, nonce {challenge['nonce'][:16]}...")
    send(f"NONCE {challenge['nonce']}")

    _, x, y = next(chip_lines).split()                     # TEEPUBKEY <x> <y>
    evidence = json.loads(next(chip_lines).split(" ", 1)[1])  # EVIDENCE <json>
    if tamper_evidence:
        tamper_evidence(evidence)
    attestation = {
        "runtime-data": {
            "nonce": challenge["nonce"],
            "tee-pubkey": {"kty": "EC", "crv": "P-256", "alg": "ECDH-ES+A256KW", "x": x, "y": y},
        },
        "tee-evidence": {"primary_evidence": evidence, "additional_evidence": ""},
    }
    try:
        token = json.loads(kbs.post("attest", attestation))["token"]
    except urllib.error.HTTPError as e:
        reason = e.read().decode(errors="replace")[:300]
        log(f"KBS rejected the evidence: {reason}")
        send("DENIED attestation failed")
        return
    log(f"KBS accepted the evidence. Appraisal: {ear_summary(token)}")

    try:
        jwe = json.loads(kbs.get(f"resource/{SECRET_PATH}"))
    except urllib.error.HTTPError as e:
        log(f"KBS refused the secret: HTTP {e.code}, the resource policy said no")
        send("DENIED resource policy")
        return
    log("KBS released the secret as a JWE encrypted to the chip's TEE key, forwarding it")
    send("JWE " + " ".join(jwe[k] for k in ("protected", "encrypted_key", "iv", "ciphertext", "tag")))
