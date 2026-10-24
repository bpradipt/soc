/*
 * Firmware: attests to a Trustee KBS and receives a secret only if Trustee approves.
 * The host runs the HTTP side of the KBS protocol and relays lines over the UART:
 *
 *   firmware -> host   HELLO                     ready to attest
 *   host -> firmware   NONCE <nonce from the KBS challenge>
 *   firmware -> host   TEEPUBKEY <x> <y>         P-256 public key, base64url
 *   firmware -> host   EVIDENCE <json>           the litexdice evidence
 *   host -> firmware   JWE <protected> <encrypted_key> <iv> <ciphertext> <tag>
 *                      or DENIED <reason>
 *
 * The host sees every line but can't use them: the evidence binds the nonce and this
 * firmware's TEE key, and only this firmware holds the private half of that key.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <libbase/uart.h>

#include "handoff.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "bearssl.h"

static const char hexdigits[] = "0123456789abcdef";
static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void stop(void)
{
	sim_finish_finish_write(1);
	for (;;);
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

static void to_hex(char *out, const uint8_t *p, int n)
{
	for (int i = 0; i < n; i++) {
		out[2 * i] = hexdigits[p[i] >> 4];
		out[2 * i + 1] = hexdigits[p[i] & 15];
	}
	out[2 * n] = 0;
}

/* base64url without padding, as JOSE uses it. */
static void b64url_encode(char *out, const uint8_t *p, int n)
{
	uint32_t acc = 0;
	int bits = 0;

	for (int i = 0; i < n; i++) {
		acc = (acc << 8) | p[i];
		for (bits += 8; bits >= 6; bits -= 6)
			*out++ = b64url[(acc >> (bits - 6)) & 63];
	}
	if (bits)
		*out++ = b64url[(acc << (6 - bits)) & 63];
	*out = 0;
}

/* Decode base64url (no padding) from s up to the first space or NUL. Returns the length, or -1. */
static int b64url_decode(uint8_t *out, int size, const char *s)
{
	uint32_t acc = 0;
	int bits = 0, n = 0;

	for (; *s && *s != ' '; s++) {
		const char *pos = strchr(b64url, *s);
		if (!pos)
			return -1;
		acc = (acc << 6) | (uint32_t)(pos - b64url);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (n == size)
				return -1;
			out[n++] = acc >> bits;
		}
	}
	return n;
}

/* LiteX's small libc has no snprintf or strstr: two helpers instead. */
static char *append(char *dst, const char *src)
{
	while (*src)
		*dst++ = *src++;
	*dst = 0;
	return dst;
}

static const char *find(const char *haystack, const char *needle)
{
	for (size_t n = strlen(needle); *haystack; haystack++)
		if (!strncmp(haystack, needle, n))
			return haystack;
	return NULL;
}

/* Next space-separated field of a line. */
static const char *next_field(const char *s)
{
	s = strchr(s, ' ');
	return s ? s + 1 : NULL;
}

/* Find "<key>":"<value>" in a small JSON object and decode the base64url value. */
static int json_b64url(uint8_t *out, int size, const char *json, const char *key)
{
	char pattern[16], *p;
	const char *v;
	char buf[64];
	int n = 0;

	p = append(pattern, "\"");
	p = append(p, key);
	append(p, "\":\"");
	v = find(json, pattern);
	if (!v)
		return -1;
	for (v += strlen(pattern); *v && *v != '"' && n < (int)sizeof buf - 1; v++)
		buf[n++] = *v;
	buf[n] = 0;
	return b64url_decode(out, size, buf);
}

/* RFC 3394 AES key unwrap: 40 bytes of wrapped key -> 32-byte content key. Returns 0 if intact. */
static int aes_key_unwrap(uint8_t cek[32], const uint8_t kek[32], const uint8_t wrapped[40])
{
	br_aes_ct_cbcdec_keys aes;
	uint8_t a[8], r[4][8], block[16], zero_iv[16];

	br_aes_ct_cbcdec_init(&aes, kek, 32);
	memcpy(a, wrapped, 8);
	memcpy(r, wrapped + 8, 32);
	for (int j = 5; j >= 0; j--) {
		for (int i = 4; i >= 1; i--) {
			uint32_t t = 4 * j + i;
			memcpy(block, a, 8);
			block[7] ^= t;
			block[6] ^= t >> 8;
			memcpy(block + 8, r[i - 1], 8);
			memset(zero_iv, 0, sizeof zero_iv);
			br_aes_ct_cbcdec_run(&aes, zero_iv, block, 16);  /* one block with a zero IV = AES decrypt */
			memcpy(a, block, 8);
			memcpy(r[i - 1], block + 8, 8);
		}
	}
	memcpy(cek, r, 32);
	for (int i = 0; i < 8; i++)
		if (a[i] != 0xA6)
			return -1;
	return 0;
}

int main(void)
{
	struct dice_handoff *h = (struct dice_handoff *)HANDOFF_ADDR;
	const br_ec_impl *ec = &br_ec_p256_m31;
	static char line[1024], json[512], hex[160], x64[48], y64[48];
	uint8_t tee_priv[32], tee_pub[65], report_data[48], sig[64];
	uint8_t point[65], z[32], kek[32], cek[32], wrapped[40], iv[12], tag[16], secret[65];
	br_sha384_context sha384;
	br_sha256_context sha256;
	br_aes_ct_ctr_keys ctr;
	br_gcm_context gcm;
	const char *protected, *f;
	char *nonce;
	int n;

	uart_init();
	printf("[fw] hello from the official firmware\n");
	if (h->magic != HANDOFF_MAGIC) {
		printf("[fw] no DICE handoff from the ROM\n");
		stop();
	}

	/* 1. Ask for an attestation, then wait for the KBS nonce. */
	printf("HELLO\n");
	get_line(line, sizeof line);
	if (strncmp(line, "NONCE ", 6)) {
		printf("[fw] bad request: %s\n", line);
		stop();
	}
	nonce = line + 6;

	/* 2. A P-256 key for receiving the secret. This SoC has no RNG, so derive it from the Alias key
	 *    and the nonce (a real TEE uses its hardware RNG). */
	crypto_sha512_hkdf(tee_priv, 32, h->alias_priv, 32, (const uint8_t *)nonce, strlen(nonce),
			   (const uint8_t *)"KBS TEE key", 11);
	ec->mulgen(tee_pub, tee_priv, sizeof tee_priv, BR_EC_secp256r1);
	b64url_encode(x64, tee_pub + 1, 32);
	b64url_encode(y64, tee_pub + 33, 32);
	printf("TEEPUBKEY %s %s\n", x64, y64);

	/* 3. REPORT_DATA = SHA-384 of the canonical JSON (RFC 8785: sorted keys, no spaces) of the runtime
	 *    data KBS checks for primary evidence: additional evidence (none here), nonce and TEE key. */
	{
		char *p = append(json, "{\"additional-evidence\":\"\",\"nonce\":\"");
		p = append(p, nonce);
		p = append(p, "\",\"tee-pubkey\":{\"alg\":\"ECDH-ES+A256KW\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
		p = append(p, x64);
		p = append(p, "\",\"y\":\"");
		p = append(p, y64);
		append(p, "\"}}");
	}
	br_sha384_init(&sha384);
	br_sha384_update(&sha384, json, strlen(json));
	br_sha384_out(&sha384, report_data);
	crypto_ed25519_sign(sig, h->alias_priv, report_data, sizeof report_data);

	/* 4. Evidence: the ROM's certificate chain plus the signed REPORT_DATA. */
	printf("EVIDENCE {");
	to_hex(hex, (const uint8_t *)&h->cert, sizeof h->cert);
	printf("\"alias_cert\":\"%s\",", hex);
	to_hex(hex, h->device_id_pub, 32);
	printf("\"device_id\":\"%s\",", hex);
	to_hex(hex, report_data, sizeof report_data);
	printf("\"report_data\":\"%s\",", hex);
	to_hex(hex, sig, sizeof sig);
	printf("\"signature\":\"%s\"}\n", hex);

	/* 5. The answer: a JWE (ECDH-ES+A256KW, A256GCM) encrypted to our TEE key, or a refusal. */
	get_line(line, sizeof line);
	if (strncmp(line, "JWE ", 4)) {
		printf("[fw] KBS said: %s\n", line);
		stop();
	}
	protected = line + 4;
	if (b64url_decode((uint8_t *)json, sizeof json - 1, protected) < 0) {
		printf("[fw] bad JWE header\n");
		stop();
	}
	json[sizeof json - 1] = 0;
	point[0] = 4;
	if (json_b64url(point + 1, 32, json, "x") != 32 || json_b64url(point + 33, 32, json, "y") != 32) {
		printf("[fw] JWE header has no P-256 epk\n");
		stop();
	}

	/*    ECDH with the KBS's ephemeral key, then Concat KDF (RFC 7518 4.6) -> key-wrapping key. */
	if (!ec->mul(point, sizeof point, tee_priv, sizeof tee_priv, BR_EC_secp256r1)) {
		printf("[fw] bad epk point\n");
		stop();
	}
	memcpy(z, point + 1, 32);
	br_sha256_init(&sha256);
	br_sha256_update(&sha256, "\x00\x00\x00\x01", 4);
	br_sha256_update(&sha256, z, 32);
	br_sha256_update(&sha256, "\x00\x00\x00\x0e" "ECDH-ES+A256KW", 18);
	br_sha256_update(&sha256, "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\x01\x00", 12);
	br_sha256_out(&sha256, kek);

	/*    Unwrap the content key, then AES-256-GCM with the protected header as AAD. */
	f = next_field(protected);
	if (!f || b64url_decode(wrapped, sizeof wrapped, f) != 40 || aes_key_unwrap(cek, kek, wrapped)) {
		printf("[fw] key unwrap failed\n");
		stop();
	}
	f = next_field(f);
	if (!f || b64url_decode(iv, sizeof iv, f) != 12) {
		printf("[fw] bad IV\n");
		stop();
	}
	f = next_field(f);
	n = f ? b64url_decode(secret, sizeof secret - 1, f) : -1;
	f = f ? next_field(f) : NULL;
	if (n < 0 || !f || b64url_decode(tag, sizeof tag, f) != 16) {
		printf("[fw] bad ciphertext or tag\n");
		stop();
	}
	br_aes_ct_ctr_init(&ctr, cek, sizeof cek);
	br_gcm_init(&gcm, &ctr.vtable, br_ghash_ctmul32);
	br_gcm_reset(&gcm, iv, sizeof iv);
	br_gcm_aad_inject(&gcm, protected, strchr(protected, ' ') - protected);
	br_gcm_flip(&gcm);
	br_gcm_run(&gcm, 0, secret, n);
	if (!br_gcm_check_tag(&gcm, tag)) {
		printf("[fw] GCM tag mismatch: the secret was not encrypted to this firmware\n");
		stop();
	}
	secret[n] = 0;
	printf("[fw] decrypted the secret from Trustee: \"%s\"\n", (char *)secret);

	crypto_wipe(tee_priv, sizeof tee_priv);
	crypto_wipe(cek, sizeof cek);
	crypto_wipe(secret, sizeof secret);
	stop();
	return 0;
}
