/*
 * "Mutable" firmware: lives in flash, can be updated, and therefore must not be
 * trusted until the boot ROM has measured it. Here it pokes at the RoT to show
 * what is (and is not) reachable once the ROM has locked it.
 */
#include <stdint.h>
#include <stdio.h>

#include <generated/csr.h>
#include <generated/mem.h>
#include <libbase/uart.h>

static void dump(const char *label, unsigned long addr)
{
	printf("%s", label);
	for (int i = 0; i < 8; i++)
		printf("%08lx", csr_read_simple(addr + 4 * i));
	printf("\n");
}

int main(void)
{
	uart_init();
	printf("[fw] hello from the official firmware\n");
	printf("[fw] RoT locked = %lu\n", rot_locked_read());

	/* Attack 1: read the secrets the ROM used. */
	dump("[fw] fuse digest read   : ", CSR_ROT_FUSE_DIGEST_ADDR);

	/* Attack 2: unlock, then forge the measurement with a value of our choosing. */
	rot_lock_write(0);
	for (int i = 0; i < 8; i++)
		csr_write_simple(0xdeadbeef, CSR_ROT_MEAS_STAGE_ADDR + 4 * i);
	rot_lock_write(1);
	sim_trace_enable_write(0);	/* end of the --trace waveform */
	printf("[fw] RoT locked = %lu after trying to clear it\n", rot_locked_read());

	/* What a remote verifier would receive as evidence (in real life: signed by a device key). */
	dump("[fw] attested measurement: ", CSR_ROT_MEASUREMENT_ADDR);

	sim_finish_finish_write(1);
	return 0;
}
