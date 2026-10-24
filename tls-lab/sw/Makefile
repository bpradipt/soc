BUILD_DIR?=../build

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

.DEFAULT_GOAL := all

# Monocypher 4.0.2 (BSD-2 or CC0, vendored in monocypher/): Ed25519, HKDF, HMAC for DICE.
# BearSSL 0.6 (MIT, downloaded and hash-checked): TLS 1.2 client, P-256, SHA-384, AES-GCM.
BEARSSL     = bearssl-0.6
BEARSSL_SHA = 6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14
BEARSSL_SRC = ec/ec_p256_m31.c codec/ccopy.c codec/dec32be.c codec/enc32be.c codec/dec32le.c \
              codec/enc32le.c codec/dec64be.c codec/enc64be.c hash/sha2big.c hash/sha2small.c \
              hash/ghash_ctmul32.c symcipher/aes_ct.c symcipher/aes_ct_enc.c symcipher/aes_ct_dec.c \
              symcipher/aes_ct_ctr.c symcipher/aes_ct_cbcdec.c aead/gcm.c \
              ssl/ssl_engine.c ssl/ssl_client.c ssl/ssl_hs_client.c ssl/ssl_io.c ssl/ssl_rec_gcm.c \
              ssl/prf.c ssl/prf_sha256.c x509/x509_knownkey.c ec/ecdsa_i31_vrfy_asn1.c \
              ec/ecdsa_i31_vrfy_raw.c ec/ecdsa_atr.c ec/ecdsa_i31_bits.c rand/hmac_drbg.c mac/hmac.c \
              hash/multihash.c rand/sysrng.c ec/ec_secp256r1.c ec/ec_secp384r1.c ec/ec_secp521r1.c \
              int/i31_decode.c int/i31_decmod.c int/i31_encode.c int/i31_fmont.c int/i31_iszero.c \
              int/i31_modpow.c int/i31_montmul.c int/i31_ninv31.c int/i31_rshift.c int/i31_sub.c \
              int/i31_bitlen.c int/i31_tmont.c int/i31_muladd.c int/i31_add.c int/i32_div32.c

# Reuse LiteX's own CPU startup code (crt0) and linker scripts:
#  - the BIOS one places code in ROM and data/stack in on-chip SRAM  -> boot ROM
#  - the demo one places everything in main RAM                      -> firmware
VPATH = $(CPU_DIRECTORY):monocypher:$(BEARSSL)/src
CFLAGS += -I. -Imonocypher -I$(BEARSSL)/inc -I$(BEARSSL)/src \
          -DBR_USE_URANDOM=0 -DBR_USE_GETENTROPY=0 -DBR_RDRAND=0 -DBR_USE_UNIX_TIME=0  # no OS, no RNG
CRYPTO = monocypher.o monocypher-ed25519.o
TLS    = $(notdir $(BEARSSL_SRC:.c=.o))

$(BEARSSL)/inc/bearssl.h:
	curl -sSLo $(BEARSSL).tar.gz https://bearssl.org/$(BEARSSL).tar.gz
	echo "$(BEARSSL_SHA)  $(BEARSSL).tar.gz" | sha256sum -c -
	tar -xzf $(BEARSSL).tar.gz && rm $(BEARSSL).tar.gz

$(TLS) firmware.o: $(BEARSSL)/inc/bearssl.h
vpath %.c $(addprefix $(BEARSSL)/src/,$(sort $(dir $(BEARSSL_SRC))))

LINK = $(CC) $(LDFLAGS) -N -o $@ $^ \
	$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
	-Wl,--start-group $(LIBS:lib%=-l%) -Wl,--end-group -Wl,--gc-sections

all: bootrom.bin firmware.bin

bootrom.elf: crt0.o bootrom.o sha256.o $(CRYPTO)
	$(LINK) -T $(BIOS_DIRECTORY)/linker.ld

firmware.elf: crt0.o firmware.o $(CRYPTO) $(TLS)
	$(LINK) -T $(SOC_DIRECTORY)/software/demo/linker.ld

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) *.o *.d *.elf *.bin
	$(RM) -r $(BEARSSL)

.PHONY: all clean
