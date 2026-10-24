"""
The host side of the lab.

  provision()  the tenant sets up Trustee over HTTPS: reference values, the secret, the resource policy
  pipe()       the untrusted host carries the chip's TCP bytes to a server, without understanding them

The firmware runs the KBS client itself, inside a TLS session that ends in the chip. The host sees
encrypted bytes and can't change them.
"""
import base64
import json
import queue
import socket
import ssl
import threading
import urllib.request

KBS_ADDR = ("127.0.0.1", 8080)
KBS = "https://localhost:8080/kbs/v0"
SECRET_PATH = "default/key/tenant-42"

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
    """The tenant's admin client. It trusts the lab's KBS certificate."""
    def __init__(self, cafile):
        self.http = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))

    def post(self, path, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(f"{KBS}/{path}", data=data, headers={"Content-Type": content_type})
        with self.http.open(req) as r:
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

def pipe(chip_lines, send, address, random_bytes):
    """Carry the chip's TCP bytes to `address` and back, as hex lines over the UART.

    The simulator's UART bridge buffers only 2 KiB of input, so the host sends the chip one chunk
    of server bytes each time the chip asks for more."""
    assert next(chip_lines) == "TCP OPEN"
    sock = socket.create_connection(address)
    log(f"connected the chip to {address[0]}:{address[1]}, relaying bytes it can't read")
    send(f"TCP OPENED {random_bytes.hex()}")

    from_server = queue.Queue()
    def server_reader():
        while data := sock.recv(256):
            from_server.put(data)
        from_server.put(None)
    threading.Thread(target=server_reader, daemon=True).start()

    for line in chip_lines:
        if line == "TCP CLOSE":
            break
        if line == "TCP MORE":
            data = from_server.get()
            send(f"TCP {data.hex()}" if data else "TCP CLOSED")
            if data is None:
                from_server.put(None)                     # stays closed for later reads
        else:
            sock.sendall(bytes.fromhex(line[4:]))
    sock.close()

def fake_kbs(cert, key):
    """A hostile host's own TLS server, posing as Trustee with a certificate of its own."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = socket.create_server(("127.0.0.1", 0))

    def serve():
        conn, _ = server.accept()
        try:
            ctx.wrap_socket(conn, server_side=True).recv(1)   # the chip aborts during the handshake
        except (ssl.SSLError, OSError) as e:
            log(f"fake KBS: the chip ended the handshake ({e.__class__.__name__})")
        conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()
