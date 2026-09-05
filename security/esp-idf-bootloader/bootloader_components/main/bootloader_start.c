/* SPDX-License-Identifier: MIT */

#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include "bootloader_common.h"
#include "bootloader_flash_priv.h"
#include "bootloader_init.h"
#include "bootloader_sha.h"
#include "bootloader_utility.h"
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_secure_boot.h"
#include "rom/secure_boot.h"
#include "sdkconfig.h"

#if !CONFIG_RISSOKEY_SIGNED_AB_BOOTLOADER
#error "custom bootloader main is only valid for the signed A/B profile"
#endif

#define ALIGN_UP(value, alignment) (((value) + ((alignment) - 1U)) & ~((alignment) - 1U))

_Static_assert(sizeof(CONFIG_RISSOKEY_UPDATE_KEY_DIGEST_HEX) == 65,
               "trusted update-key digest must contain exactly 64 hex characters");

static const char *TAG = "rissokey-ab";
static uint8_t trusted_key_digest[32] __attribute__((aligned(4)));

static bool parse_trusted_key_digest(void)
{
    const char *hex = CONFIG_RISSOKEY_UPDATE_KEY_DIGEST_HEX;
    for (size_t index = 0; index < sizeof(trusted_key_digest); ++index) {
        uint8_t value = 0;
        for (unsigned nibble = 0; nibble < 2; ++nibble) {
            char character = hex[index * 2U + nibble];
            uint8_t digit;
            if (character >= '0' && character <= '9') {
                digit = (uint8_t)(character - '0');
            } else if (character >= 'a' && character <= 'f') {
                digit = (uint8_t)(character - 'a' + 10);
            } else {
                return false;
            }
            value = (uint8_t)((value << 4U) | digit);
        }
        trusted_key_digest[index] = value;
    }
    return hex[64] == '\0';
}

static bool verify_signed_partition(const esp_partition_pos_t *partition)
{
    if (partition->offset == 0 || partition->size == 0) {
        return false;
    }

    esp_image_metadata_t metadata = {0};
    if (esp_image_get_metadata(partition, &metadata) != ESP_OK) {
        ESP_LOGE(TAG, "invalid image metadata at 0x%" PRIx32, partition->offset);
        return false;
    }

    uint32_t padded_length = ALIGN_UP(metadata.image_len, FLASH_SECTOR_SIZE);
    if (padded_length > partition->size - FLASH_SECTOR_SIZE) {
        ESP_LOGE(TAG, "signature sector does not fit partition at 0x%" PRIx32,
                 partition->offset);
        return false;
    }

    uint8_t image_digest[32] = {0};
    uint8_t verified_digest[32] = {0};
    if (bootloader_sha256_flash_contents(partition->offset, padded_length, image_digest) != ESP_OK) {
        ESP_LOGE(TAG, "image digest failed at 0x%" PRIx32, partition->offset);
        return false;
    }

    const ets_secure_boot_signature_t *signature = bootloader_mmap(
        partition->offset + padded_length, sizeof(ets_secure_boot_signature_t));
    if (signature == NULL) {
        ESP_LOGE(TAG, "signature map failed at 0x%" PRIx32, partition->offset);
        return false;
    }

    const ets_secure_boot_sig_block_t *block = &signature->block[0];
    bool format_valid = block->magic_byte == ETS_SECURE_BOOT_V2_SIGNATURE_MAGIC
        && block->version == ESP_SECURE_BOOT_SCHEME
        && block->block_crc == esp_rom_crc32_le(
            0, (const uint8_t *)block, CRC_SIGN_BLOCK_LEN);

    uint8_t signature_key_digest[32] __attribute__((aligned(4))) = {0};
    if (format_valid) {
        bootloader_sha256_handle_t key_sha = bootloader_sha256_start();
        bootloader_sha256_data(key_sha, &block->key, sizeof(block->key));
        bootloader_sha256_finish(key_sha, signature_key_digest);
    }
    bool trusted_key = format_valid
        && memcmp(signature_key_digest, trusted_key_digest,
                  sizeof(trusted_key_digest)) == 0;
    bool signature_valid = trusted_key
        && ets_rsa_pss_verify(&block->key, block->signature,
                              image_digest, verified_digest);
    bootloader_munmap(signature);

    bool verified = signature_valid
        && memcmp(image_digest, verified_digest, sizeof(image_digest)) == 0;
    if (!verified) {
        ESP_LOGE(TAG, "signature verification failed at 0x%" PRIx32
                 " (format=%d, trusted_key=%d, rsa=%d, digest_match=%d)",
                 partition->offset, format_valid, trusted_key, signature_valid,
                 memcmp(image_digest, verified_digest, sizeof(image_digest)) == 0);
        esp_rom_delay_us(5000000);
    } else {
        ESP_LOGI(TAG, "trusted signature verified at 0x%" PRIx32, partition->offset);
    }
    return verified;
}

static void reject_unsigned_partitions(bootloader_state_t *state)
{
    for (uint32_t index = 0; index < state->app_count; ++index) {
        if (state->ota[index].size != 0 && !verify_signed_partition(&state->ota[index])) {
            state->ota[index].size = 0;
        }
    }
    if (state->factory.size != 0 && !verify_signed_partition(&state->factory)) {
        state->factory.size = 0;
    }
    if (state->test.size != 0 && !verify_signed_partition(&state->test)) {
        state->test.size = 0;
    }
}

void __attribute__((noreturn)) call_start_cpu0(void)
{
    if (bootloader_init() != ESP_OK) {
        bootloader_reset();
    }
    /* bootloader_init() clears BSS on ESP32-S2, including trusted_key_digest. */
    if (!parse_trusted_key_digest()) {
        ESP_LOGE(TAG, "trusted update-key digest is malformed");
        bootloader_reset();
    }

    bootloader_state_t state = {0};
    if (!bootloader_utility_load_partition_table(&state)) {
        ESP_LOGE(TAG, "partition table validation failed");
        bootloader_reset();
    }
    int boot_index = bootloader_utility_get_selected_boot_partition(&state);
    if (boot_index == INVALID_INDEX) {
        bootloader_reset();
    }

    reject_unsigned_partitions(&state);
    bootloader_utility_load_boot_image(&state, boot_index);
}
