/*
 * Firmware: proves to a remote verifier what it is, and receives a secret only if the verifier
 * approves. It shares the UART with its log; the host relays protocol lines to the verifier:
 *
 *   firmware -> verifier   HELLO
 *   verifier -> firmware   NONCE <32 bytes>
 *   firmware -> verifier   EVIDENCE <DeviceID pub> <Alias certificate> <report> <report signature>
 *   verifier -> firmware   SECRET <verifier X25519 pub> <wrapped secret>   or   DENIED <reason>
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <libbase/uart.h>

#include "handoff.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static void put_hex(const uint8_t *p, int n)
{
	printf(" ");
	for (int i = 0; i < n; i++)
		printf("%02x", p[i]);
}

/* Read one line from the UART, polling (interrupts are off). */
static void get_line(char *buf, int size)
{
	int n = 0;
	char c;

	for (;;) {
		while (uart_rxempty_read());
		c = uart_rxtx_read();
		uart_ev_pending_write(UART_EV_RX);
		if (c == '\n')
			break;
		if (n < size - 1)
			buf[n++] = c;
	}
	buf[n] = 0;
}

/* Parse n bytes of hex starting at s. Returns the position after them, or NULL. */
static const char *parse_hex(const char *s, uint8_t *out, int n)
{
	for (int i = 0; i < 2 * n; i++) {
		char c = *s++;
		int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
		if (v < 0)
			return NULL;
		out[i / 2] = (i % 2) ? (out[i / 2] | v) : (v << 4);
	}
	return s;
}

static void stop(void)
{
	sim_finish_finish_write(1);
	for (;;);
}

int main(void)
{
	struct dice_handoff *h = (struct dice_handoff *)HANDOFF_ADDR;
	uint8_t report[64], report_sig[64], wrap_priv[32], verifier_pub[32], shared[32], pad[64], secret[33];
	const char *s;
	char line[256];

	uart_init();
	printf("[fw] hello from the official firmware\n");
	if (h->magic != HANDOFF_MAGIC) {
		printf("[fw] no DICE handoff from the ROM\n");
		stop();
	}
	printf("[fw] the ROM left me an Alias key and its certificate\n");

	/* 1. Say hello, get a fresh nonce: it proves the evidence is not a recording of an older boot. */
	printf("HELLO\n");
	get_line(line, sizeof line);
	if (strncmp(line, "NONCE ", 6) || !parse_hex(line + 6, report, 32)) {
		printf("[fw] bad request: %s\n", line);
		stop();
	}

	/* 2. A key pair for receiving the secret. This SoC has no RNG, so derive it from the Alias key and
	 *    the nonce (a real TEE uses its hardware RNG). Its public half goes into the report. */
	crypto_sha512_hkdf(wrap_priv, 32, h->alias_priv, 32, report, 32, (const uint8_t *)"KeyRelease", 10);
	crypto_x25519_public_key(report + 32, wrap_priv);

	/* 3. Report = nonce || key-release public key, signed with the Alias key. */
	crypto_ed25519_sign(report_sig, h->alias_priv, report, sizeof report);
	printf("EVIDENCE");
	put_hex(h->device_id_pub, 32);
	put_hex((const uint8_t *)&h->cert, sizeof h->cert);
	put_hex(report, sizeof report);
	put_hex(report_sig, sizeof report_sig);
	printf("\n");

	/* 4. Unwrap the secret: X25519 shared key, hashed, XORed with the wrapped bytes. */
	get_line(line, sizeof line);
	if (!strncmp(line, "SECRET ", 7) && (s = parse_hex(line + 7, verifier_pub, 32)) &&
	    *s == ' ' && parse_hex(s + 1, secret, 32)) {
		crypto_x25519(shared, wrap_priv, verifier_pub);
		crypto_sha512(pad, shared, sizeof shared);
		for (int i = 0; i < 32; i++)
			secret[i] ^= pad[i];
		secret[32] = 0;
		printf("[fw] unwrapped the secret: \"%s\"\n", (char *)secret);
	} else {
		printf("[fw] verifier said: %s\n", line);
	}

	crypto_wipe(wrap_priv, sizeof wrap_priv);
	crypto_wipe(shared, sizeof shared);
	crypto_wipe(secret, sizeof secret);
	stop();
	return 0;
}
