#!/usr/bin/env python3
#
# A tiny LiteX SoC with a hardware Root of Trust, simulated with Verilator.
#
#   ./rot_soc.py                 good firmware, secure boot enforced  -> boots
#   ./rot_soc.py --tamper        modified firmware, enforced          -> ROM refuses to boot
#   ./rot_soc.py --tamper --measured-only
#                                modified firmware, not enforced      -> boots, but the
#                                                                        measurement gives it away

import argparse
import hashlib
import math
import os
import subprocess

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

# Platform: just a clock and a UART that the simulator connects to your terminal. -----------------

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
    fuse_*      : values read from the OTP fuse array, programmed at manufacturing.
                  Readable only until `lock` is set.
    meas_stage  : scratch register the boot ROM writes the firmware digest into.
    measurement : copy of meas_stage taken at the moment of locking. Read-only, frozen until reset.
    lock        : write 1 once; sticky until reset. Nothing software does afterwards can clear it.
    """
    def __init__(self, fuse_words):
        self.fuse_digest  = CSRStatus(256, description="Golden SHA-256 of the firmware (OTP).")
        self.fuse_len     = CSRStatus(32,  description="Firmware length in bytes (OTP).")
        self.fuse_enforce = CSRStatus(1,   description="1: secure boot (halt on mismatch), 0: measured boot only.")
        self.meas_stage   = CSRStorage(256)
        self.measurement  = CSRStatus(256)
        self.lock         = CSRStorage(1)
        self.locked       = CSRStatus(1)

        # OTP fuse array: 8 digest words, length, enforce. Like real fuses, its contents are not part of
        # the logic design: the simulator loads them from build/gateware/sim_otp.init at power-on.
        otp   = Memory(32, len(fuse_words), init=fuse_words, name="otp")
        ports = [otp.get_port(async_read=True) for _ in fuse_words]
        self.specials += otp, *ports
        self.comb += [port.adr.eq(i) for i, port in enumerate(ports)]
        fuse = [port.dat_r for port in ports]

        locked = Signal()
        self.sync += If(self.lock.re & self.lock.storage[0] & ~locked,
            locked.eq(1),
            self.measurement.status.eq(self.meas_stage.storage),
        )
        self.comb += [
            self.locked.status.eq(locked),
            self.fuse_digest.status.eq(Mux(locked, 0, Cat(*reversed(fuse[:8])))),  # word 0 = MSW
            self.fuse_len.status.eq(Mux(locked, 0, fuse[8])),
            self.fuse_enforce.status.eq(fuse[9][0]),
        ]

# SoC. ---------------------------------------------------------------------------------------------

def to_words(data):
    data += b"\0" * (-len(data) % 4)
    return [int.from_bytes(data[i:i+4], "little") for i in range(0, len(data), 4)]

def make_soc(rom=None, flash=None, fw_digest=bytes(32), fw_len=0, enforce=1):
    platform = SimPlatform("SIM", _io)
    soc = SoCCore(platform, clk_freq=int(1e6),
        cpu_type                 = "vexriscv",
        uart_name                = "sim",
        integrated_rom_size      = 0x8000,
        integrated_rom_init      = to_words(rom) if rom else [],
        integrated_sram_size     = 0x2000,
        integrated_main_ram_size = 0x10000,                          # stands in for external flash
        integrated_main_ram_init = to_words(flash) if flash else [],
    )
    soc.crg = CRG(platform.request("sys_clk"))
    fuse_words = [int.from_bytes(fw_digest[i:i+4], "big") for i in range(0, 32, 4)] + [fw_len, enforce]
    soc.rot = RootOfTrust(fuse_words)
    platform.add_debug(soc)                                         # sim_finish/sim_trace CSRs
    return soc

# LiteX re-runs Verilator on every build. ROM, flash and OTP contents live in .init files that the
# simulator reads at start-up, so switching scenarios only needs a recompile if the RTL itself changed.
_compile_sim = verilator._compile_sim
def _compile_sim_if_changed(build_name, verbose):
    rtl = b"".join(l for l in open(f"{build_name}.v", "rb") if not l.lstrip().startswith(b"//"))  # skip comments: they hold timestamps
    key = hashlib.sha256(rtl + open(f"build_{build_name}.sh", "rb").read()).hexdigest()  # script has trace flags
    stamp = f"{build_name}.rtl.sha256"
    if os.path.exists("obj_dir/Vsim") and os.path.exists(stamp) and open(stamp).read() == key:
        print("[build] RTL unchanged, reusing the compiled simulator")
        return
    _compile_sim(build_name, verbose)
    open(stamp, "w").write(key)
verilator._compile_sim = _compile_sim_if_changed

# --trace: summarize the waveform. ----------------------------------------------------------------

TRACE_SIGNALS = ["lock_wr_stb", "lock_storage", "locked", "fuse_digest_status", "meas_stage_storage", "measurement_status"]
CLK_PS = 1_000_000  # 1 MHz clock, VCD timescale is 1 ps

def show_trace(vcd="build/gateware/sim.vcd", gtkw="build/gateware/rot.gtkw"):
    """Print every change of the RoT signals, and write a GTKWave view zoomed on the lock."""
    ids, changes, t = {}, [], 0
    for line in open(vcd):
        line = line.strip()
        if line.startswith("$var"):
            ident, name = line.split()[3:5]
            if name[len("make_soc_rot_"):] in TRACE_SIGNALS:
                ids[ident] = name[len("make_soc_rot_"):]
        elif line.startswith("#"):
            t = int(line[1:])
        elif line[:1] in ("0", "1") and line[1:] in ids:
            changes.append((t, ids[line[1:]], line[0]))
        elif line[:1] == "b" and line.split()[1] in ids and set(line.split()[0][1:]) <= {"0", "1"}:
            changes.append((t, ids[line.split()[1]], f"{int(line.split()[0][1:], 2):x}"))

    start = changes[0][0]
    print("\n[trace] cycle  signal              value")
    for t, name, val in changes:
        print(f"[trace] {(t - start) // CLK_PS:5}  {name:19} {val}")

    # Open the view 20 cycles before the lock, about 200 cycles wide. GTKWave zoom = -log2(ps per pixel).
    lock_t   = next(t for t, n, v in changes if n == "locked" and v == "1")
    attack_t = next(t for t, n, v in changes if n == "lock_storage" and v == "0" and t > lock_t)
    with open(gtkw, "w") as f:
        f.write(f"[timestart] {lock_t - 20 * CLK_PS}\n[size] 1600 700\n")
        f.write(f"*{-math.log2(200 * CLK_PS / 1200):.6f} {lock_t} {attack_t}" + " -1" * 25 + "\n")
        f.write("[treeopen] TOP.\n[treeopen] TOP.sim.\n@28\nTOP.sim.sys_clk\n")
        for s in TRACE_SIGNALS:
            wide = s in ("fuse_digest_status", "meas_stage_storage", "measurement_status")
            f.write(f"{'@22' if wide else '@28'}\nTOP.sim.make_soc_rot_{s}{'[255:0]' if wide else ''}\n")
    print(f"\n[trace] GTKWave view: gtkwave build/gateware/sim.vcd {gtkw}")
    print(f"[trace]   marker 1 (primary) = the lock edge, marker A = the first attack")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tamper",        action="store_true", help="Modify the firmware after its digest was fused.")
    p.add_argument("--measured-only", action="store_true", help="Fuse enforce=0: boot anything, just measure it.")
    p.add_argument("--trace",         action="store_true", help="Dump a waveform (build/gateware/sim.vcd) from just before the lock until the firmware finishes its attacks.")
    args = p.parse_args()

    # 1. Elaborate the SoC once to get its memory map/CSR headers, then compile ROM + firmware against them.
    soc = make_soc()
    soc.integrated_rom_initialized = True  # our boot ROM replaces the LiteX BIOS: don't build the BIOS
    Builder(soc, output_dir="build", compile_gateware=False).build(run=False)
    subprocess.run(["make", "-C", "sw", "BUILD_DIR=../build"], check=True)

    # 2. "Manufacturing": hash the official firmware and burn the digest into the fuses.
    fw = open("sw/firmware.bin", "rb").read()
    digest = hashlib.sha256(fw).digest()
    print(f"[fab] fusing firmware digest {digest.hex()} ({len(fw)} bytes)")

    # 3. "In the field": what is actually in flash may not be what was fused.
    flash = fw
    if args.tamper:
        flash = fw.replace(b"official firmware", b"EVIL  firmware!!!")
        assert flash != fw
        print(f"[attacker] flash now hashes to  {hashlib.sha256(flash).hexdigest()}")

    rom = open("sw/bootrom.bin", "rb").read()
    soc = make_soc(rom, flash, digest, len(fw), enforce=0 if args.measured_only else 1)
    sim_config = SimConfig()
    sim_config.add_clocker("sys_clk", freq_hz=int(1e6))
    sim_config.add_module("serial2console", "serial")
    Builder(soc, output_dir="build").build(sim_config=sim_config, interactive=False,
        trace=args.trace)                       # VCD: plain text, every waveform viewer reads it
    if args.trace:
        show_trace()

if __name__ == "__main__":
    main()
