/*
 * DICE boot ROM: the first instructions the CPU executes after reset.
 * It is baked into the chip (read-only), so it is trusted by construction.
 *
 *   0. straps   : report the boot-mode and debug straps; with the UART-boot strap, load the firmware
 *                 from the host instead of from flash
 *   1. measure  : SHA-256 the firmware partition, wherever it came from
 *   2. read+lock: copy the UDS out of the fuses, then lock the RoT so nothing later can read them
 *   3. DeviceID : derive the chip's identity key from the UDS (same key every boot)
 *   4. CDI      : mix the UDS with the measurement (different firmware -> different CDI)
 *   5. Alias    : derive the firmware's key from the CDI
 *   6. certify  : sign "Alias key + measurement" with the DeviceID key
 *   7. hand off : leave the Alias key and certificate in RAM, wipe every secret, jump to firmware
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <generated/csr.h>
#include <generated/mem.h>
#include <libbase/uart.h>
#include <system.h>

#include "handoff.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

void sha256(const uint8_t *msg, size_t len, uint32_t h[8]);

#define STRAP_DEBUG         (1 << 0)
#define STRAP_UART_BOOT     (1 << 1)
#define FUSE_DEBUG_DISABLE  (1 << 0)

static void print_hex(const char *label, const uint8_t *p, int n)
{
	printf("%s", label);
	for (int i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static void words_to_bytes(const uint32_t *w, uint8_t *b, int nwords)
{
	for (int i = 0; i < 4 * nwords; i++)
		b[i] = w[i / 4] >> (24 - 8 * (i % 4));
}

static char getc_polled(void)
{
	char c;

	while (uart_rxempty_read());
	c = uart_rxtx_read();
	uart_ev_pending_write(UART_EV_RX);
	return c;
}

/* Recovery boot: ask the host for the firmware, one line of hex at a time, until it sends an empty line.
 * The ROM checks nothing here. The measurement in step 1 covers whatever arrives. */
static void load_from_uart(void)
{
	uint8_t *p = (uint8_t *)MAIN_RAM_BASE, *end = p + FW_PARTITION_SIZE;
	int n, v;
	char c;

	do {
		printf("LOAD\n");
		for (n = 0; (c = getc_polled()) != '\n'; n++) {
			v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
			if (v < 0 || p >= end)
				continue;  /* never write past the partition */
			if (n % 2)
				*p++ |= v;
			else
				*p = v << 4;
		}
	} while (n);
	printf("[rom] loaded %ld bytes of firmware from the UART\n", (long)(p - (uint8_t *)MAIN_RAM_BASE));
}

int main(void)
{
	struct dice_handoff *h = (struct dice_handoff *)HANDOFF_ADDR;
	uint32_t words[8];
	uint8_t uds[32], cdi[64], seed[32], device_priv[64], tbs[64];
	uint32_t straps, fuses, any = 0;

	uart_init();
	printf("\n[rom] reset vector reached, DICE boot ROM running\n");

	/* 0. Straps and fuses, as the RoT latched them at reset. */
	straps = rot_straps_read();
	fuses = rot_fuses_read();
	printf("[rom] straps: debug=%d uart-boot=%d, fuse DEBUG_DISABLE=%d -> JTAG debug access %s\n",
	       !!(straps & STRAP_DEBUG), !!(straps & STRAP_UART_BOOT), !!(fuses & FUSE_DEBUG_DISABLE),
	       rot_debug_read() ? "ENABLED" : "locked");
	if (straps & STRAP_UART_BOOT)
		load_from_uart();

	/* 1. Measure the firmware. */
	sha256((const uint8_t *)MAIN_RAM_BASE, FW_PARTITION_SIZE, words);
	words_to_bytes(words, h->cert.measurement, 8);
	print_hex("[rom] firmware measurement : ", h->cert.measurement, 32);

	/* 2. Copy the UDS out of the fuses, then lock: from here on the fuses read as zero. */
	for (int i = 0; i < 8; i++)
		words[i] = csr_read_simple(CSR_ROT_UDS_ADDR + 4 * i);
	words_to_bytes(words, uds, 8);
	rot_lock_write(1);
	printf("[rom] UDS copied, RoT locked\n");
	for (int i = 0; i < 8; i++)
		any |= words[i];
	if (!any)
		printf("[rom] the UDS read as zeros: the hardware hides it while debug is enabled\n");

	/* 3. DeviceID key: depends only on the UDS, so it is the same every boot. */
	crypto_sha512_hkdf(seed, 32, uds, 32, NULL, 0, (const uint8_t *)"DeviceID", 8);
	crypto_ed25519_key_pair(device_priv, h->device_id_pub, seed);
	print_hex("[rom] DeviceID public key  : ", h->device_id_pub, 32);

	/* 4. CDI: depends on the UDS and on the measurement. */
	crypto_sha512_hmac(cdi, uds, 32, h->cert.measurement, 32);

	/* 5. Alias key: derived from the CDI, so it changes whenever the firmware changes. */
	crypto_sha512_hkdf(seed, 32, cdi, 64, NULL, 0, (const uint8_t *)"Alias", 5);
	crypto_ed25519_key_pair(h->alias_priv, h->cert.alias_pub, seed);
	print_hex("[rom] Alias public key     : ", h->cert.alias_pub, 32);

	/* 6. Certify: "this Alias key belongs to firmware with this measurement", signed by DeviceID. */
	for (int i = 0; i < 32; i++) {
		tbs[i] = h->cert.alias_pub[i];
		tbs[32 + i] = h->cert.measurement[i];
	}
	crypto_ed25519_sign(h->cert.signature, device_priv, tbs, sizeof tbs);
	h->magic = HANDOFF_MAGIC;
	printf("[rom] Alias certificate signed with the DeviceID key\n");

	/* 7. Wipe every secret the firmware must never see, then hand off. */
	crypto_wipe(uds, sizeof uds);
	crypto_wipe(cdi, sizeof cdi);
	crypto_wipe(seed, sizeof seed);
	crypto_wipe(device_priv, sizeof device_priv);
	printf("[rom] UDS, CDI and DeviceID private key wiped, jumping to firmware @ 0x%08lx\n\n",
	       (unsigned long)MAIN_RAM_BASE);

	flush_cpu_icache();
	((void (*)(void))MAIN_RAM_BASE)();
	return 0;
}
