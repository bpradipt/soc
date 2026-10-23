BUILD_DIR?=../build

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

# Reuse LiteX's own CPU startup code (crt0) and linker scripts:
#  - the BIOS one places code in ROM and data/stack in on-chip SRAM  -> boot ROM
#  - the demo one places everything in main RAM                      -> firmware
VPATH = $(CPU_DIRECTORY):monocypher
CFLAGS += -I. -Imonocypher
CRYPTO = monocypher.o monocypher-ed25519.o  # Monocypher 4.0.2, BSD-2 or CC0 (monocypher/LICENCE.md)

LINK = $(CC) $(LDFLAGS) -N -o $@ $^ \
	$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
	-Wl,--start-group $(LIBS:lib%=-l%) -Wl,--end-group -Wl,--gc-sections

all: bootrom.bin firmware.bin

bootrom.elf: crt0.o bootrom.o sha256.o $(CRYPTO)
	$(LINK) -T $(BIOS_DIRECTORY)/linker.ld

firmware.elf: crt0.o firmware.o $(CRYPTO)
	$(LINK) -T $(SOC_DIRECTORY)/software/demo/linker.ld

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) *.o *.d *.elf *.bin

.PHONY: all clean
