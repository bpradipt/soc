/* What the DICE boot ROM leaves in RAM for the firmware. Never the UDS, never the DeviceID private key. */
#ifndef HANDOFF_H
#define HANDOFF_H

#include <stdint.h>
#include <generated/mem.h>

#define FW_PARTITION_SIZE 0x10000                   /* the ROM measures this much firmware */
#define HANDOFF_ADDR      (MAIN_RAM_BASE + 0x1F000) /* above the firmware partition */
#define HANDOFF_MAGIC     0x45434944                /* "DICE" */

/* Alias certificate: the ROM's statement "this Alias key belongs to firmware with this measurement",
 * signed with the chip's DeviceID key. */
struct alias_cert {
	uint8_t alias_pub[32];
	uint8_t measurement[32];   /* SHA-256 of the firmware partition */
	uint8_t signature[64];     /* Ed25519 by DeviceID over alias_pub || measurement */
};

struct dice_handoff {
	uint32_t magic;
	uint8_t  device_id_pub[32];  /* the chip's long-term identity */
	uint8_t  alias_priv[64];     /* the firmware's own signing key (Monocypher format) */
	struct alias_cert cert;
};

#endif
