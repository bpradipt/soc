/*
 * Firmware: the whole KBS client runs here. It opens a TLS session to Trustee through the host,
 * checks that the server holds the KBS key pinned in this firmware, then runs the KBS protocol
 * (auth, attest, resource) and decrypts the secret.
 *
 * The host is a byte pipe. It carries TCP bytes as hex lines and can't read or change them:
 *
 *   firmware -> host   TCP OPEN                   connect me to Trustee
 *   host -> firmware   TCP OPENED <32 bytes hex>  connected; extra randomness for TLS
 *   firmware -> host   TCP <hex>                  bytes to send to the server
 *   firmware -> host   TCP MORE                   ready for the next chunk from the server
 *   host -> firmware   TCP <hex>                  up to 256 bytes from the server
 *   host -> firmware   TCP CLOSED                 the server closed the connection
 *   firmware -> host   TCP CLOSE                  done
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <generated/csr.h>
#include <libbase/uart.h>

#include "handoff.h"
#include "kbs_pinned_key.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "bearssl.h"

static const char hexdigits[] = "0123456789abcdef";
static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void stop(void)
{
	printf("TCP CLOSE\n");
	sim_finish_finish_write(1);
	for (;;);
}

/* ---- Small helpers (LiteX's libc has no snprintf, strstr, atoi or memcmp) ---------------------- */

int memcmp(const void *a, const void *b, size_t n)   /* BearSSL needs it */
{
	const unsigned char *x = a, *y = b;

	for (; n; n--, x++, y++)
		if (*x != *y)
			return *x - *y;
	return 0;
}

static int parse_uint(const char *s)
{
	int v = 0;

	while (*s == ' ')
		s++;
	while (*s >= '0' && *s <= '9')
		v = 10 * v + *s++ - '0';
	return v;
}

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

static char *append(char *dst, const char *src)
{
	while (*src)
		*dst++ = *src++;
	*dst = 0;
	return dst;
}

static char *append_uint(char *dst, unsigned v)
{
	char tmp[12];
	int n = 0;

	do
		tmp[n++] = '0' + v % 10;
	while (v /= 10);
	while (n)
		*dst++ = tmp[--n];
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

static const char *find_nocase(const char *haystack, const char *needle)
{
	for (size_t n = strlen(needle); *haystack; haystack++) {
		size_t i = 0;
		while (i < n && (haystack[i] | 0x20) == (needle[i] | 0x20))
			i++;
		if (i == n)
			return haystack;
	}
	return NULL;
}

static int hex_nibble(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static char *append_hex(char *dst, const uint8_t *p, int n)
{
	for (int i = 0; i < n; i++) {
		*dst++ = hexdigits[p[i] >> 4];
		*dst++ = hexdigits[p[i] & 15];
	}
	*dst = 0;
	return dst;
}

static char *append_b64url(char *dst, const uint8_t *p, int n)
{
	uint32_t acc = 0;
	int bits = 0;

	for (int i = 0; i < n; i++) {
		acc = (acc << 8) | p[i];
		for (bits += 8; bits >= 6; bits -= 6)
			*dst++ = b64url[(acc >> (bits - 6)) & 63];
	}
	if (bits)
		*dst++ = b64url[(acc << (6 - bits)) & 63];
	*dst = 0;
	return dst;
}

/* Decode base64url (no padding) until the first character outside the alphabet. Returns the length. */
static int b64url_decode(uint8_t *out, int size, const char *s)
{
	uint32_t acc = 0;
	int bits = 0, n = 0;
	const char *pos;

	for (; *s && (pos = strchr(b64url, *s)); s++) {
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

/* Copy the string value of "<key>":"..." from compact JSON. Returns the length, or -1. */
static int json_str(char *out, int size, const char *json, const char *key)
{
	char pattern[32], *p;
	const char *v;
	int n = 0;

	p = append(pattern, "\"");
	p = append(p, key);
	append(p, "\":\"");
	v = find(json, pattern);
	if (!v)
		return -1;
	for (v += strlen(pattern); *v && *v != '"'; v++) {
		if (n == size - 1)
			return -1;
		out[n++] = *v;
	}
	out[n] = 0;
	return n;
}

/* ---- The TCP pipe through the host, and TLS on top of it --------------------------------------- */

static char line[1200];

static int pipe_read(void *ctx, unsigned char *buf, size_t len)
{
	static uint8_t pending[512];
	static int have, used;
	(void)ctx;

	while (used == have) {
		printf("TCP MORE\n");                      /* the UART bridge buffers only 2 KiB: ask */
		get_line(line, sizeof line);
		if (!strcmp(line, "TCP CLOSED") || strncmp(line, "TCP ", 4))
			return -1;
		have = used = 0;
		for (const char *h = line + 4; h[0] && h[1] && have < (int)sizeof pending; h += 2)
			pending[have++] = (hex_nibble(h[0]) << 4) | hex_nibble(h[1]);
	}
	if (len > (size_t)(have - used))
		len = have - used;
	memcpy(buf, pending + used, len);
	used += len;
	return len;
}

static int pipe_write(void *ctx, const unsigned char *buf, size_t len)
{
	char *p;
	(void)ctx;

	if (len > 256)
		len = 256;
	p = append(line, "TCP ");
	append_hex(p, buf, len);
	printf("%s\n", line);
	return len;
}

static br_ssl_client_context tls;
static br_x509_knownkey_context pinned;
static unsigned char tls_buf[BR_SSL_BUFSIZE_BIDI];
static br_sslio_context io;

static void tls_open(const uint8_t *seed)
{
	static const uint16_t suites[] = { BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
	static const br_ec_public_key kbs_key = {
		BR_EC_secp256r1, (unsigned char *)KBS_PINNED_KEY, sizeof KBS_PINNED_KEY
	};

	/* TLS 1.2, one cipher suite, and only the algorithms that suite needs. */
	br_ssl_client_zero(&tls);
	br_ssl_engine_set_versions(&tls.eng, BR_TLS12, BR_TLS12);
	br_ssl_engine_set_suites(&tls.eng, suites, 1);
	br_ssl_engine_set_hash(&tls.eng, br_sha256_ID, &br_sha256_vtable);
	br_ssl_engine_set_prf_sha256(&tls.eng, &br_tls12_sha256_prf);
	br_ssl_engine_set_ec(&tls.eng, &br_ec_p256_m31);
	br_ssl_engine_set_ecdsa(&tls.eng, &br_ecdsa_i31_vrfy_asn1);
	br_ssl_engine_set_aes_ctr(&tls.eng, &br_aes_ct_ctr_vtable);
	br_ssl_engine_set_ghash(&tls.eng, &br_ghash_ctmul32);
	br_ssl_engine_set_gcm(&tls.eng, &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);

	/* The server must prove it holds the private half of the pinned key: it signs the handshake with it. */
	br_x509_knownkey_init_ec(&pinned, &kbs_key, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN);
	br_ssl_engine_set_x509(&tls.eng, &pinned.vtable);

	br_ssl_engine_set_buffer(&tls.eng, tls_buf, sizeof tls_buf, 1);
	br_ssl_engine_inject_entropy(&tls.eng, seed, 32);
	br_ssl_client_reset(&tls, "kbs", 0);
	br_sslio_init(&io, &tls.eng, pipe_read, NULL, pipe_write, NULL);
}

static void tls_fail(void)
{
	int err = br_ssl_engine_last_error(&tls.eng);

	printf("[fw] TLS failed, BearSSL error %d", err);
	if (err == BR_ERR_BAD_SIGNATURE)
		printf(": the server's handshake signature doesn't match the pinned Trustee key");
	printf("\n");
	stop();
}

/* ---- HTTP/1.1 over the TLS session --------------------------------------------------------------- */

static char cookie[96];
static char response[8192];

/* Send one request; return the response body (in `response`) and set *status. */
static const char *http(const char *method, const char *path, const char *body, int *status)
{
	char head[512], *p;
	const char *v, *end = NULL;
	int n = 0, length = 0;

	p = append(head, method);
	p = append(p, " ");
	p = append(p, path);
	p = append(p, " HTTP/1.1\r\nHost: kbs\r\nContent-Type: application/json\r\nContent-Length: ");
	p = append_uint(p, body ? strlen(body) : 0);
	if (cookie[0]) {
		p = append(p, "\r\nCookie: ");
		p = append(p, cookie);
	}
	append(p, "\r\n\r\n");
	if (br_sslio_write_all(&io, head, strlen(head)) || (body && br_sslio_write_all(&io, body, strlen(body))) ||
	    br_sslio_flush(&io))
		tls_fail();

	/* Read the headers, then exactly Content-Length bytes of body. */
	while (!end || n - (end + 4 - response) < length) {
		int r = br_sslio_read(&io, response + n, sizeof response - 1 - n);
		if (r <= 0)
			tls_fail();
		n += r;
		response[n] = 0;
		if (!end && (end = find(response, "\r\n\r\n"))) {
			v = find_nocase(response, "\r\ncontent-length:");
			length = v ? parse_uint(v + 17) : 0;
			if ((v = find(response, "kbs-session-id="))) {
				int i = 0;
				while (v[i] && v[i] != ';' && v[i] != '\r' && i < (int)sizeof cookie - 1)
					cookie[i] = v[i], i++;
				cookie[i] = 0;
			}
		}
	}
	*status = parse_uint(response + 9);  /* "HTTP/1.1 200 OK" */
	return end + 4;
}

/* ---- JWE decryption: ECDH-ES+A256KW with P-256, A256GCM (RFC 7518) ------------------------------- */

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

/* Decrypt the JWE in `jwe` (flattened JSON) to `out`. Returns the plaintext length, or -1. */
static int jwe_decrypt(uint8_t *out, int size, const char *jwe, const uint8_t tee_priv[32])
{
	static char protected[512], field[256], header[400];
	uint8_t point[65], kek[32], cek[32], wrapped[40], iv[12], tag[16];
	br_sha256_context sha;
	br_aes_ct_ctr_keys ctr;
	br_gcm_context gcm;
	int n;

	if (json_str(protected, sizeof protected, jwe, "protected") < 0 ||
	    (n = b64url_decode((uint8_t *)header, sizeof header - 1, protected)) < 0)
		return -1;
	header[n] = 0;
	point[0] = 4;
	if (json_str(field, sizeof field, header, "x") < 0 || b64url_decode(point + 1, 32, field) != 32 ||
	    json_str(field, sizeof field, header, "y") < 0 || b64url_decode(point + 33, 32, field) != 32 ||
	    !br_ec_p256_m31.mul(point, sizeof point, tee_priv, 32, BR_EC_secp256r1))
		return -1;

	/* Concat KDF over the ECDH shared secret -> key-wrapping key. */
	br_sha256_init(&sha);
	br_sha256_update(&sha, "\x00\x00\x00\x01", 4);
	br_sha256_update(&sha, point + 1, 32);
	br_sha256_update(&sha, "\x00\x00\x00\x0e" "ECDH-ES+A256KW", 18);
	br_sha256_update(&sha, "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\x01\x00", 12);
	br_sha256_out(&sha, kek);

	if (json_str(field, sizeof field, jwe, "encrypted_key") < 0 || b64url_decode(wrapped, 40, field) != 40 ||
	    aes_key_unwrap(cek, kek, wrapped) || json_str(field, sizeof field, jwe, "iv") < 0 ||
	    b64url_decode(iv, 12, field) != 12 || json_str(field, sizeof field, jwe, "tag") < 0 ||
	    b64url_decode(tag, 16, field) != 16 || json_str(field, sizeof field, jwe, "ciphertext") < 0 ||
	    (n = b64url_decode(out, size, field)) < 0)
		return -1;

	br_aes_ct_ctr_init(&ctr, cek, sizeof cek);
	br_gcm_init(&gcm, &ctr.vtable, br_ghash_ctmul32);
	br_gcm_reset(&gcm, iv, sizeof iv);
	br_gcm_aad_inject(&gcm, protected, strlen(protected));
	br_gcm_flip(&gcm);
	br_gcm_run(&gcm, 0, out, n);
	crypto_wipe(cek, sizeof cek);
	return br_gcm_check_tag(&gcm, tag) ? n : -1;
}

/* ---- The KBS client ------------------------------------------------------------------------------ */

int main(void)
{
	struct dice_handoff *h = (struct dice_handoff *)HANDOFF_ADDR;
	static char body[1024], nonce[96], token[3072], claims[2048], status_str[32];
	uint8_t host_random[32], seed[32], tee_priv[32], tee_pub[65], report_data[48], sig[64], secret[65];
	char x64[48], y64[48], *p;
	const char *resp;
	br_sha384_context sha384;
	int status, n;

	uart_init();
	printf("[fw] hello from the official firmware\n");
	if (h->magic != HANDOFF_MAGIC) {
		printf("[fw] no DICE handoff from the ROM\n");
		stop();
	}

	/* 1. Connect to Trustee through the host. This SoC has no RNG, so TLS randomness comes from the
	 *    secret Alias key mixed with bytes from the host (a real TEE uses its hardware RNG). */
	printf("TCP OPEN\n");
	get_line(line, sizeof line);
	if (strncmp(line, "TCP OPENED ", 11)) {
		printf("[fw] the host didn't connect us: %s\n", line);
		stop();
	}
	for (int i = 0; i < 32; i++)
		host_random[i] = (hex_nibble(line[11 + 2 * i]) << 4) | hex_nibble(line[12 + 2 * i]);
	crypto_sha512_hkdf(seed, 32, h->alias_priv, 32, host_random, 32, (const uint8_t *)"TLS randomness", 14);
	tls_open(seed);
	crypto_wipe(seed, sizeof seed);

	/* 2. Request -> Challenge. The TLS handshake runs here, on the first write. */
	resp = http("POST", "/kbs/v0/auth", "{\"version\":\"0.4.0\",\"tee\":\"litexdice\",\"extra-params\":{}}",
		    &status);
	if (status != 200 || json_str(nonce, sizeof nonce, resp, "nonce") < 0) {
		printf("[fw] KBS auth failed: HTTP %d\n", status);
		stop();
	}
	printf("[fw] TLS session with the pinned Trustee key; KBS nonce %.16s...\n", nonce);

	/* 3. TEE key and REPORT_DATA, as in the trustee-lab firmware. */
	crypto_sha512_hkdf(tee_priv, 32, h->alias_priv, 32, (const uint8_t *)nonce, strlen(nonce),
			   (const uint8_t *)"KBS TEE key", 11);
	br_ec_p256_m31.mulgen(tee_pub, tee_priv, sizeof tee_priv, BR_EC_secp256r1);
	append_b64url(x64, tee_pub + 1, 32);
	append_b64url(y64, tee_pub + 33, 32);
	p = append(body, "{\"additional-evidence\":\"\",\"nonce\":\"");
	p = append(p, nonce);
	p = append(p, "\",\"tee-pubkey\":{\"alg\":\"ECDH-ES+A256KW\",\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
	p = append(p, x64);
	p = append(p, "\",\"y\":\"");
	p = append(p, y64);
	append(p, "\"}}");
	br_sha384_init(&sha384);
	br_sha384_update(&sha384, body, strlen(body));
	br_sha384_out(&sha384, report_data);
	crypto_ed25519_sign(sig, h->alias_priv, report_data, sizeof report_data);

	/* 4. Attestation -> token. */
	p = append(body, "{\"runtime-data\":{\"nonce\":\"");
	p = append(p, nonce);
	p = append(p, "\",\"tee-pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ECDH-ES+A256KW\",\"x\":\"");
	p = append(p, x64);
	p = append(p, "\",\"y\":\"");
	p = append(p, y64);
	p = append(p, "\"}},\"tee-evidence\":{\"primary_evidence\":{\"alias_cert\":\"");
	p = append_hex(p, (const uint8_t *)&h->cert, sizeof h->cert);
	p = append(p, "\",\"device_id\":\"");
	p = append_hex(p, h->device_id_pub, 32);
	p = append(p, "\",\"report_data\":\"");
	p = append_hex(p, report_data, sizeof report_data);
	p = append(p, "\",\"signature\":\"");
	p = append_hex(p, sig, sizeof sig);
	append(p, "\"},\"additional_evidence\":\"\"}}");
	resp = http("POST", "/kbs/v0/attest", body, &status);
	if (status != 200 || json_str(token, sizeof token, resp, "token") < 0) {
		printf("[fw] Trustee rejected the evidence: HTTP %d\n", status);
		stop();
	}
	/*    The token is a JWT: header.payload.signature. Show the appraisal from the payload. */
	n = b64url_decode((uint8_t *)claims, sizeof claims - 1, strchr(token, '.') + 1);
	claims[n < 0 ? 0 : n] = 0;
	json_str(status_str, sizeof status_str, claims, "ear.status");
	printf("[fw] Trustee accepted the evidence, appraisal: %s\n", status_str);

	/* 5. Response: the secret this firmware asked for, as a JWE to its TEE key. */
	resp = http("GET", "/kbs/v0/resource/default/key/tenant-42", NULL, &status);
	if (status != 200) {
		printf("[fw] Trustee refused the secret: HTTP %d\n", status);
		stop();
	}
	n = jwe_decrypt(secret, sizeof secret - 1, resp, tee_priv);
	if (n < 0) {
		printf("[fw] couldn't decrypt the JWE\n");
		stop();
	}
	secret[n] = 0;
	printf("[fw] decrypted the secret from Trustee: \"%s\"\n", (char *)secret);

	br_sslio_close(&io);
	crypto_wipe(tee_priv, sizeof tee_priv);
	crypto_wipe(secret, sizeof secret);
	stop();
	return 0;
}
