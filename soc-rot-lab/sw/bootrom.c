/*
 * Boot ROM: the first instructions the CPU executes after reset.
 * It is baked into the chip (read-only), so it is trusted by construction.
 *
 *   1. measure  : SHA-256 the firmware sitting in (untrusted) flash
 *   2. record   : stage the digest into the RoT measurement register
 *   3. verify   : compare against the digest fused at manufacturing
 *   4. lock     : freeze the measurement and hide the fuses
 *   5. hand off : jump to the firmware, or halt if verification failed and enforce=1
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <generated/csr.h>
#include <generated/mem.h>
#include <libbase/uart.h>
#include <system.h>

void sha256(const uint8_t *msg, size_t len, uint32_t h[8]);

static void print_digest(const char *label, const uint32_t d[8])
{
	printf("%s", label);
	for (int i = 0; i < 8; i++)
		printf("%08lx", (unsigned long)d[i]);
	printf("\n");
}

int main(void)
{
	uint32_t meas[8], golden[8];
	int match = 1;

	uart_init();
	printf("\n[rom] reset vector reached, boot ROM running\n");

	uint32_t len = csr_read_simple(CSR_ROT_FUSE_LEN_ADDR);
	int enforce  = rot_fuse_enforce_read();

	sha256((const uint8_t *)MAIN_RAM_BASE, len, meas);
	print_digest("[rom] measured firmware : ", meas);

	for (int i = 0; i < 8; i++) {
		golden[i] = csr_read_simple(CSR_ROT_FUSE_DIGEST_ADDR + 4 * i);
		csr_write_simple(meas[i], CSR_ROT_MEAS_STAGE_ADDR + 4 * i);
		match &= golden[i] == meas[i];
	}
	print_digest("[rom] fused golden      : ", golden);

	sim_trace_enable_write(1);	/* start the waveform here when run with --trace */
	rot_lock_write(1);
	printf("[rom] RoT locked: fuses hidden, measurement frozen\n");

	if (!match && enforce) {
		printf("[rom] SECURE BOOT FAILURE: firmware is not the one this chip was provisioned for. Halting.\n");
		sim_finish_finish_write(1);
		for (;;);
	}
	printf("[rom] %s, jumping to firmware @ 0x%08lx\n\n",
	       match ? "digest matches fuse" : "MISMATCH (measured-boot mode, booting anyway)",
	       (unsigned long)MAIN_RAM_BASE);

	flush_cpu_icache();
	((void (*)(void))MAIN_RAM_BASE)();
	return 0;
}
