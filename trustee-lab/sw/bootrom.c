/*
 * DICE boot ROM: the first instructions the CPU executes after reset.
 * It is baked into the chip (read-only), so it is trusted by construction.
 *
 *   1. measure  : SHA-256 the firmware partition
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

int main(void)
{
	struct dice_handoff *h = (struct dice_handoff *)HANDOFF_ADDR;
	uint32_t words[8];
	uint8_t uds[32], cdi[64], seed[32], device_priv[64], tbs[64];

	uart_init();
	printf("\n[rom] reset vector reached, DICE boot ROM running\n");

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
