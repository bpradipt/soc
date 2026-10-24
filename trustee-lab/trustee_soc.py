#!/usr/bin/env python3
#
# The DICE lab chip from cc-attest-lab, attesting to a Trustee KBS that knows the "litexdice" TEE type.
#
#   ./trustee_soc.py            official firmware  -> Trustee appraises the evidence and releases the secret
#   ./trustee_soc.py --tamper   modified firmware  -> appraisal "warning", the resource policy refuses
#   ./trustee_soc.py --tamper --replay
#                               modified firmware, and the host swaps in the certificate from an official
#                               boot -> the litexdice verifier rejects the evidence
#
# Roles played by this script:
#   fab        burns a unique device secret (UDS) into the chip's OTP, publishes the chip's DeviceID key
#   vendor     publishes the measurement (SHA-256) of its official firmware
#   tenant     loads those two values and the secret into Trustee (kbs_host.provision)
#   attacker   optionally patches the firmware in RAM before boot (--tamper)
#   host       runs the simulator and relays the KBS protocol (kbs_host.attest);
#              with --replay it rewrites the evidence on the way
#
# Trustee runs next to it: trustee/setup.sh builds the KBS into build/trustee-src/kbs (or set KBS_BIN).

import argparse
import hashlib
import os
import shutil
import socket
import subprocess
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from migen import *

from litex.gen import LiteXModule
from litex.build.generic_platform import Pins, Subsignal
from litex.build.io import CRG
from litex.build.sim import SimPlatform
from litex.build.sim.config import SimConfig
from litex.build.sim import verilator
from litex.soc.interconnect.csr import CSRStorage, CSRStatus
from litex.soc.integration.soc_core import SoCCore
from litex.soc.integration.builder import Builder

import kbs_host

FW_PARTITION = 0x10000  # the ROM measures this many bytes of firmware, starting at main RAM
SECRET       = b"tenant-42 disk key: open sesame!"

# Platform: just a clock and a UART that the simulator connects to its stdin/stdout. ---------------

_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),
    ("serial", 0,
        Subsignal("source_valid", Pins(1)), Subsignal("source_ready", Pins(1)), Subsignal("source_data", Pins(8)),
        Subsignal("sink_valid",   Pins(1)), Subsignal("sink_ready",   Pins(1)), Subsignal("sink_data",   Pins(8)),
    ),
]

# The Root of Trust block. -------------------------------------------------------------------------

class RootOfTrust(LiteXModule):
    """
    uds    : the Unique Device Secret, read from OTP fuses programmed at manufacturing.
             Readable only until `lock` is set.
    lock   : write 1 once; sticky until reset. Nothing software does afterwards can clear it.
    """
    def __init__(self, uds_words):
        self.uds    = CSRStatus(256, description="Unique Device Secret (OTP). Reads 0 once locked.")
        self.lock   = CSRStorage(1)
        self.locked = CSRStatus(1)

        # OTP fuse array: 8 words of UDS. The simulator loads it from build/gateware/sim_otp.init at power-on.
        otp   = Memory(32, len(uds_words), init=uds_words, name="otp")
        ports = [otp.get_port(async_read=True) for _ in uds_words]
        self.specials += otp, *ports
        self.comb += [port.adr.eq(i) for i, port in enumerate(ports)]

        locked = Signal()
        self.sync += If(self.lock.re & self.lock.storage[0], locked.eq(1))
        self.comb += [
            self.locked.status.eq(locked),
            self.uds.status.eq(Mux(locked, 0, Cat(*reversed([port.dat_r for port in ports])))),  # word 0 = MSW
        ]

# SoC. ---------------------------------------------------------------------------------------------

def to_words(data):
    data += b"\0" * (-len(data) % 4)
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]

def make_soc(rom=None, ram=None, uds=bytes(32)):
    platform = SimPlatform("SIM", _io)
    soc = SoCCore(platform, clk_freq=int(1e6),
        cpu_type                 = "vexriscv",
        uart_name                = "sim",
        integrated_rom_size      = 0x10000,
        integrated_rom_init      = to_words(rom) if rom else [],
        integrated_sram_size     = 0x4000,
        integrated_main_ram_size = 0x20000,                          # firmware, as a loader left it in RAM
        integrated_main_ram_init = to_words(ram) if ram else [],
    )
    soc.crg = CRG(platform.request("sys_clk"))
    soc.rot = RootOfTrust([int.from_bytes(uds[i:i+4], "big") for i in range(0, 32, 4)])
    platform.add_debug(soc)                                         # sim_finish CSR
    return soc

# LiteX re-runs Verilator on every build. ROM, RAM and OTP contents live in .init files that the
# simulator reads at start-up, so switching scenarios only needs a recompile if the RTL itself changed.
_compile_sim = verilator._compile_sim
def _compile_sim_if_changed(build_name, verbose):
    rtl = b"".join(l for l in open(f"{build_name}.v", "rb") if not l.lstrip().startswith(b"//"))  # skip comments: they hold timestamps
    key = hashlib.sha256(rtl + open(f"build_{build_name}.sh", "rb").read()).hexdigest()
    stamp = f"{build_name}.rtl.sha256"
    if os.path.exists("obj_dir/Vsim") and os.path.exists(stamp) and open(stamp).read() == key:
        print("[build] RTL unchanged, reusing the compiled simulator")
        return
    _compile_sim(build_name, verbose)
    open(stamp, "w").write(key)
verilator._compile_sim = _compile_sim_if_changed

# The fab's view of DICE: the same key derivation the boot ROM runs (sw/bootrom.c). --------------

def dice_key(secret, label):
    seed = HKDF(algorithm=SHA512(), length=32, salt=None, info=label).derive(secret)
    return Ed25519PrivateKey.from_private_bytes(seed)

def raw(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def start_kbs():
    """Start a fresh Trustee KBS (built-in AS and RVPS) and wait until it listens."""
    shutil.rmtree("build/kbs", ignore_errors=True)
    os.makedirs("build/kbs")
    kbs = subprocess.Popen([os.environ.get("KBS_BIN", "build/trustee-src/kbs"), "--config-file", "kbs-config.toml"],
        stdout=open("build/kbs.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", 8080)).close()
            return kbs
        except OSError:
            if kbs.poll() is not None:
                raise SystemExit("KBS exited, see build/kbs.log")
            time.sleep(0.2)
    raise SystemExit("KBS did not start, see build/kbs.log")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tamper", action="store_true", help="Patch the firmware in RAM before boot.")
    p.add_argument("--replay", action="store_true", help="Hostile host: replace the chip's certificate with "
                                                         "one recorded from an official boot.")
    args = p.parse_args()
    if args.replay and not os.path.exists("build/official_cert.txt"):
        p.error("--replay replays a recording: run ./trustee_soc.py once without --tamper first")

    # 1. Elaborate the SoC once to get its memory map/CSR headers, then compile ROM + firmware against them.
    soc = make_soc()
    soc.integrated_rom_initialized = True  # our boot ROM replaces the LiteX BIOS: don't build the BIOS
    Builder(soc, output_dir="build", compile_gateware=False).build(run=False)
    subprocess.run(["make", "-C", "sw", "BUILD_DIR=../build"], check=True)

    # 2. Fab: give this chip a random UDS, once. The fab publishes the chip's DeviceID public key.
    #    (Real chips create the UDS on-die, e.g. with a PUF, and only the public key ever leaves the chip.)
    os.makedirs("build/fab", exist_ok=True)
    if not os.path.exists("build/fab/uds.bin"):
        open("build/fab/uds.bin", "wb").write(os.urandom(32))
    uds = open("build/fab/uds.bin", "rb").read()
    device_id = raw(dice_key(uds, b"DeviceID").public_key())
    print(f"[fab] chip provisioned, DeviceID public key {device_id.hex()}")

    # 3. Vendor: publish the reference measurement of the official firmware partition.
    fw = open("sw/firmware.bin", "rb").read()
    assert len(fw) <= FW_PARTITION, f"firmware is {len(fw)} bytes, partition is {FW_PARTITION}"
    image = fw + bytes(FW_PARTITION - len(fw))
    reference = hashlib.sha256(image).hexdigest()
    print(f"[vendor] reference measurement {reference}")

    # 4. Attacker (optional): what sits in RAM at boot may not be what the vendor shipped.
    if args.tamper:
        image = image.replace(b"official firmware", b"EVIL  firmware!!!")
        print(f"[attacker] patched firmware, it now measures {hashlib.sha256(image).hexdigest()}")

    # 5. Build the chip.
    rom = open("sw/bootrom.bin", "rb").read()
    soc = make_soc(rom, image, uds)
    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(1e6))
    sim_config.add_module("serial2console", "serial")
    Builder(soc, output_dir="build").build(sim_config=sim_config, run=False)
    os.chdir("build/gateware")
    _compile_sim_if_changed("sim", verbose=True)  # LiteX compiles the simulator only when it also runs it
    os.chdir("../..")

    # 6. Tenant: start Trustee and load the reference values and the secret.
    kbs = start_kbs()
    trustee = kbs_host.Kbs()
    kbs_host.provision(trustee, device_id.hex(), reference, SECRET)

    # 7. Host: power the chip on and relay. Log lines go to your terminal, protocol lines to Trustee.
    chip = subprocess.Popen(["obj_dir/Vsim"], cwd="build/gateware", text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    def protocol_lines():
        for line in chip.stdout:
            line = line.strip()  # the console ends lines with \n\r
            if line == "HELLO" or line.startswith(("TEEPUBKEY ", "EVIDENCE ")):
                yield line
            else:
                print(line, flush=True)
    def send(line):
        chip.stdin.write(line + "\n")
        chip.stdin.flush()
    def tamper_evidence(evidence):
        if not args.tamper:
            open("build/official_cert.txt", "w").write(evidence["alias_cert"])
        if args.replay:
            evidence["alias_cert"] = open("build/official_cert.txt").read()
            kbs_host.log("swapped in the Alias certificate recorded from an official boot")
    try:
        lines = protocol_lines()
        kbs_host.attest(trustee, lines, send, tamper_evidence)
        for _ in lines:   # print the rest of the chip's log until it powers off
            pass
        chip.wait()
    finally:
        chip.kill()       # if the host stops early, so does the chip
        kbs.terminate()

if __name__ == "__main__":
    main()
