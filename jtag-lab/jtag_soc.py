#!/usr/bin/env python3
#
# The DICE SoC from the attestation lab, now with strap pins, a debug-disable fuse and a JTAG port.
#
#   ./jtag_soc.py                                    production board: the probe finds a locked TAP
#   ./jtag_soc.py --strap debug --stepping A0        debug strap on first silicon: the probe steals the UDS
#   ./jtag_soc.py --strap debug                      same board, fixed silicon: the UDS reads as zeros
#   ./jtag_soc.py --strap debug --fuse debug-disable production fuse: the strap is ignored
#   ./jtag_soc.py --strap uart-boot [--tamper]       recovery boot: the host sends the firmware over the UART
#
# Roles played by this script:
#   fab        burns the UDS and the configuration fuses into OTP, publishes the DeviceID key
#   board      ties the strap pins high or low (--strap)
#   vendor     publishes the measurement of its official firmware
#   attacker   optionally patches the firmware (--tamper), and clips a JTAG probe onto the board
#   host       runs the simulator, serves recovery images, relays messages to the verifier

import argparse
import hashlib
import json
import os
import subprocess

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
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.csr import CSRStorage, CSRStatus
from litex.soc.integration.soc_core import SoCCore
from litex.soc.integration.builder import Builder

import jtag_probe
import verifier

FW_PARTITION = 0x8000  # the ROM measures this many bytes of firmware, starting at main RAM
JTAG_PORT    = 44853   # the simulator's jtagremote module listens here for the probe

STRAPS = {"debug": 1 << 0, "uart-boot": 1 << 1}  # strap pins, as bits of the RoT's straps register
FUSES  = {"debug-disable": 1 << 0}               # configuration fuses, as bits of the RoT's fuses register

# JTAG IDCODE: version 1, part number 0xD1CE, manufacturer 0x7F (a JEDEC continuation code, so it can't
# name a real vendor), and bit 0 set as the JTAG standard requires.
IDCODE = (1 << 28) | (0xD1CE << 12) | (0x7F << 1) | 1

# Platform: a clock, a UART that the simulator connects to stdin/stdout, and JTAG pins. ------------

_io = [
    ("sys_clk", 0, Pins(1)),
    ("sys_rst", 0, Pins(1)),
    ("serial", 0,
        Subsignal("source_valid", Pins(1)), Subsignal("source_ready", Pins(1)), Subsignal("source_data", Pins(8)),
        Subsignal("sink_valid",   Pins(1)), Subsignal("sink_ready",   Pins(1)), Subsignal("sink_data",   Pins(8)),
    ),
    ("jtag", 0,
        Subsignal("tck", Pins(1)), Subsignal("tms", Pins(1)), Subsignal("tdi", Pins(1)),
        Subsignal("tdo", Pins(1)), Subsignal("ntrst", Pins(1)),
    ),
]

# The Root of Trust block, now with straps and a configuration fuse. -------------------------------

class RootOfTrust(LiteXModule):
    """
    uds    : the Unique Device Secret from OTP. Reads 0 once `lock` is set. From stepping B0 on, it also
             reads 0 whenever the debug port is enabled.
    lock   : write 1 once; sticky until reset.
    straps : the strap pins, latched when reset is released.
    fuses  : the configuration fuse word from OTP.
    debug  : 1 if the JTAG port may master the bus: debug strap set and DEBUG_DISABLE fuse intact.
    """
    def __init__(self, uds_words, fuses, straps, mask_uds_in_debug):
        self.uds    = CSRStatus(256, description="Unique Device Secret (OTP).")
        self.lock   = CSRStorage(1)
        self.locked = CSRStatus(1)
        self.straps = CSRStatus(2,  description="Strap pins latched at reset. Bit 0: debug, bit 1: UART boot.")
        self.fuses  = CSRStatus(32, description="Configuration fuses (OTP). Bit 0: DEBUG_DISABLE.")
        self.debug  = CSRStatus(1,  description="1 if the JTAG port has bus access.")
        self.debug_en = Signal()  # to the JTAG TAP

        # OTP: 8 words of UDS, then 1 word of configuration fuses. The simulator loads sim_otp.init at power-on.
        otp   = Memory(32, 9, init=uds_words + [fuses], name="otp")
        ports = [otp.get_port(async_read=True) for _ in range(9)]
        self.specials += otp, *ports
        self.comb += [port.adr.eq(i) for i, port in enumerate(ports)]
        fuse_word = ports[8].dat_r

        # Strap pins. A real board ties each one high or low with a resistor. The simulator has no board,
        # so it reads the resistors from sim_straps.init at power-on: one 1-bit entry per pin.
        board = Memory(1, 2, init=[straps >> i & 1 for i in range(2)], name="straps")
        pins  = [board.get_port(async_read=True) for _ in range(2)]
        self.specials += board, *pins
        self.comb += [pin.adr.eq(i) for i, pin in enumerate(pins)]

        # Sample the pins once, on the first clock after reset. Whatever the pins do later is ignored.
        sampled, latched = Signal(2), Signal()
        self.sync += If(~latched, sampled.eq(Cat(*[pin.dat_r for pin in pins])), latched.eq(1))

        # The fuse wins over the strap: once DEBUG_DISABLE is blown, no resistor can enable the port.
        self.comb += self.debug_en.eq(latched & sampled[0] & ~fuse_word[0])

        locked = Signal()
        self.sync += If(self.lock.re & self.lock.storage[0], locked.eq(1))
        hidden = locked | self.debug_en if mask_uds_in_debug else locked
        self.comb += [
            self.locked.status.eq(locked),
            self.straps.status.eq(sampled),
            self.fuses.status.eq(fuse_word),
            self.debug.status.eq(self.debug_en),
            self.uds.status.eq(Mux(hidden, 0, Cat(*reversed([port.dat_r for port in ports[:8]])))),  # word 0 = MSW
        ]

# The JTAG TAP: IEEE 1149.1 state machine, IDCODE, BYPASS, and a debug bus-read port. -------------

class JTAGTap(LiteXModule):
    """
    Instructions (4-bit IR):
      IDCODE  0x1  32-bit DR: the chip's IDCODE. Selected after reset.
      ADDR    0x8  32-bit DR: the bus address for MEMREAD.              } only when debug_en,
      MEMREAD 0x9  32-bit DR: the word at ADDR; each read advances ADDR. } otherwise they act as BYPASS
      BYPASS  0xF  1-bit DR. Any other IR value also selects it.
    Capture-IR loads 0b?001: bit 3 is debug_en, so the probe sees whether debug access is open.
    """
    IDCODE, ADDR, MEMREAD, BYPASS = 0x1, 0x8, 0x9, 0xF

    def __init__(self, pads, debug_en, idcode):
        self.bus = bus = wishbone.Interface(data_width=32, adr_width=30)

        # A real TAP runs on TCK as its own clock. This one samples TCK with the system clock and acts on
        # its rising edges, which keeps the lab in one clock domain. It works because the simulator's
        # jtagremote module holds each TCK level for 10 system clocks.
        tck_d, rise = Signal(), Signal()
        self.sync += tck_d.eq(pads.tck)
        self.comb += rise.eq(pads.tck & ~tck_d)

        # The 16-state TAP controller. Each entry: state -> (next if TMS=0, next if TMS=1).
        (TLR, RTI, SELDR, CAPDR, SHDR, EX1DR, PDR, EX2DR, UPDR,
         SELIR, CAPIR, SHIR, EX1IR, PIR, EX2IR, UPIR) = range(16)
        next_state = {
            TLR:   (RTI,   TLR),   RTI:   (RTI,  SELDR), SELDR: (CAPDR, SELIR), CAPDR: (SHDR, EX1DR),
            SHDR:  (SHDR,  EX1DR), EX1DR: (PDR,  UPDR),  PDR:   (PDR,   EX2DR), EX2DR: (SHDR, UPDR),
            UPDR:  (RTI,   SELDR), SELIR: (CAPIR, TLR),  CAPIR: (SHIR,  EX1IR), SHIR:  (SHIR, EX1IR),
            EX1IR: (PIR,   UPIR),  PIR:   (PIR,  EX2IR), EX2IR: (SHIR,  UPIR),  UPIR:  (RTI,  SELDR),
        }
        state = Signal(4, reset=TLR)
        self.sync += If(rise, Case(state, {s: state.eq(Mux(pads.tms, t1, t0)) for s, (t0, t1) in next_state.items()}))

        # Instruction register, and the instruction actually in effect: debug ones need debug_en.
        ir, ir_shift, insn = Signal(4, reset=self.IDCODE), Signal(4), Signal(4)
        self.comb += [
            insn.eq(self.BYPASS),
            If(ir == self.IDCODE, insn.eq(self.IDCODE)),
            If(debug_en & ((ir == self.ADDR) | (ir == self.MEMREAD)), insn.eq(ir)),
        ]

        # Data registers, and the bus-read engine behind MEMREAD.
        dr, bypass, addr, data, read = Signal(32), Signal(), Signal(32), Signal(32), Signal()
        self.sync += [
            read.eq(0),
            If(rise, Case(state, {
                TLR:   ir.eq(self.IDCODE),
                CAPIR: ir_shift.eq(Cat(1, 0, 0, debug_en)),
                SHIR:  ir_shift.eq(Cat(ir_shift[1:], pads.tdi)),
                UPIR:  ir.eq(ir_shift),
                CAPDR: [
                    bypass.eq(0),
                    If(insn == self.IDCODE, dr.eq(idcode)),
                    If(insn == self.MEMREAD, dr.eq(data), addr.eq(addr + 4), read.eq(1)),  # prefetch next word
                ],
                SHDR:  [bypass.eq(pads.tdi), dr.eq(Cat(dr[1:], pads.tdi))],
                UPDR:  If(insn == self.ADDR, addr.eq(dr), read.eq(1)),
            })),
            # One Wishbone read per request. It finishes long before the probe's next Capture-DR.
            If(read, bus.cyc.eq(1), bus.stb.eq(1)),
            If(bus.ack, bus.cyc.eq(0), bus.stb.eq(0), data.eq(bus.dat_r)),
        ]
        self.comb += [
            bus.adr.eq(addr[2:]),
            bus.sel.eq(0xF),
            bus.we.eq(0),
            pads.tdo.eq(Mux(state == SHIR, ir_shift[0], Mux(insn == self.BYPASS, bypass, dr[0]))),
        ]

# SoC. ---------------------------------------------------------------------------------------------

def to_words(data):
    data += b"\0" * (-len(data) % 4)
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]

def make_soc(rom=None, ram=None, uds=bytes(32), fuses=0, straps=0, stepping="B0"):
    platform = SimPlatform("SIM", _io)
    soc = SoCCore(platform, clk_freq=int(1e6),
        cpu_type                 = "vexriscv",
        uart_name                = "sim",
        integrated_rom_size      = 0x10000,
        integrated_rom_init      = to_words(rom) if rom else [],
        integrated_sram_size     = 0x4000,
        integrated_main_ram_size = 0x10000,                          # firmware, as a loader left it in RAM
        integrated_main_ram_init = to_words(ram) if ram else [],
    )
    soc.crg = CRG(platform.request("sys_clk"))
    soc.rot = RootOfTrust([int.from_bytes(uds[i:i+4], "big") for i in range(0, 32, 4)], fuses, straps,
                          mask_uds_in_debug=(stepping != "A0"))
    soc.tap = JTAGTap(platform.request("jtag"), soc.rot.debug_en, IDCODE)
    soc.bus.add_master(name="jtag", master=soc.tap.bus)             # the probe reads the same bus as the CPU
    platform.add_debug(soc)                                         # sim_finish CSR
    return soc

# LiteX re-runs Verilator on every build. ROM, RAM, OTP and strap contents live in .init files that the
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

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--strap", action="append", default=[], choices=STRAPS, help="Pull this strap pin high on the board.")
    p.add_argument("--fuse", action="append", default=[], choices=FUSES, help="Blow this configuration fuse at the fab.")
    p.add_argument("--stepping", default="B0", choices=["A0", "B0"],
                   help="Silicon revision. A0 leaves the UDS readable while debug is enabled.")
    p.add_argument("--tamper", action="store_true", help="Patch the firmware before boot.")
    args = p.parse_args()
    straps = sum(STRAPS[s] for s in set(args.strap))
    fuses  = sum(FUSES[f] for f in set(args.fuse))
    gateware = f"build/gateware-{args.stepping}"  # one compiled simulator per silicon revision

    # 1. Elaborate the SoC once to get its memory map/CSR headers, then compile ROM + firmware against them.
    soc = make_soc()
    soc.integrated_rom_initialized = True  # our boot ROM replaces the LiteX BIOS: don't build the BIOS
    Builder(soc, output_dir="build", gateware_dir=gateware, compile_gateware=False).build(run=False)
    subprocess.run(["make", "-C", "sw", "BUILD_DIR=../build"], check=True)

    # 2. Fab: give this chip a random UDS, once, and publish its DeviceID public key.
    os.makedirs("build/fab", exist_ok=True)
    if not os.path.exists("build/fab/uds.bin"):
        open("build/fab/uds.bin", "wb").write(os.urandom(32))
    uds = open("build/fab/uds.bin", "rb").read()
    device_id = raw(dice_key(uds, b"DeviceID").public_key())
    print(f"[fab] {args.stepping} chip provisioned, DeviceID public key {device_id.hex()}")
    print(f"[fab] configuration fuses blown: {', '.join(args.fuse) or 'none'}")
    print(f"[board] strap pins pulled high: {', '.join(args.strap) or 'none'}")

    # 3. Vendor: publish the reference measurement of the official firmware partition.
    fw = open("sw/firmware.bin", "rb").read()
    assert len(fw) <= FW_PARTITION, f"firmware is {len(fw)} bytes, partition is {FW_PARTITION}"
    image = fw + bytes(FW_PARTITION - len(fw))
    reference = hashlib.sha256(image).hexdigest()
    print(f"[vendor] reference measurement {reference}")

    # 4. Attacker (optional): what the chip boots may not be what the vendor shipped.
    if args.tamper:
        image = image.replace(b"official firmware", b"EVIL  firmware!!!")
        print(f"[attacker] patched firmware, it now measures {hashlib.sha256(image).hexdigest()}")

    # 5. Build the chip. With the UART-boot strap, flash is blank: the host serves the image instead.
    uart_boot = "uart-boot" in args.strap
    rom = open("sw/bootrom.bin", "rb").read()
    soc = make_soc(rom, None if uart_boot else image, uds, fuses, straps, args.stepping)
    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(1e6))
    sim_config.add_module("serial2console", "serial")
    sim_config.add_module("jtagremote", "jtag", args={"port": JTAG_PORT})
    Builder(soc, output_dir="build", gateware_dir=gateware).build(sim_config=sim_config, run=False)
    os.chdir(gateware)
    _compile_sim_if_changed("sim", verbose=True)  # LiteX compiles the simulator only when it also runs it
    os.chdir("../..")
    csr = json.load(open("build/csr.json"))["csr_registers"]

    # 6. Host: power the chip on.
    print()
    chip = subprocess.Popen(["obj_dir/Vsim"], cwd=gateware, text=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    def send(line):
        chip.stdin.write(line + "\n")
        chip.stdin.flush()
    try:
        # 7. Attacker: clip a probe onto the JTAG header as soon as the chip has power. The ROM is still
        #    measuring the firmware, so it has not locked the RoT yet. (The chip's log waits in the pipe.)
        stolen = jtag_probe.attack(JTAG_PORT, csr)
        if stolen is not None:
            if stolen == bytes(32):
                print("[attacker] the UDS reads as zeros: nothing to steal")
            else:
                key = raw(dice_key(stolen, b"DeviceID").public_key())
                print(f"[attacker] DeviceID derived from the stolen UDS: {key.hex()}")
                if key == device_id:
                    print("[attacker] it matches the fab's published key: I can now sign anything as this chip")

        # 8. Host: serve recovery images, relay protocol lines to the verifier, print the rest.
        chunks = (image[i:i+512] for i in range(0, len(fw), 512))
        def protocol_lines():
            for line in chip.stdout:
                line = line.strip()  # the console ends lines with \n\r
                if line == "LOAD":
                    send(next(chunks, b"").hex())  # an empty line ends the image
                elif line in ("HELLO",) or line.startswith("EVIDENCE"):
                    yield line
                elif line.startswith(("[rom]", "[fw]")):  # skip blank lines and the simulator's own chatter
                    print(line, flush=True)
        lines = protocol_lines()
        verifier.attest(lines, send, endorsed=[device_id.hex()], reference=reference)
        for _ in lines:   # print the rest of the chip's log until it powers off
            pass
        chip.wait()
    finally:
        chip.kill()       # if the host stops early, so does the chip

if __name__ == "__main__":
    main()
