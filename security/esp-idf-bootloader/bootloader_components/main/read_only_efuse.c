/* SPDX-License-Identifier: MIT */

#include <stdbool.h>
#include <stdint.h>

#include "esp_efuse.h"
#include "esp_err.h"
#include "sdkconfig.h"

#if CONFIG_RISSOKEY_EFUSE_READ_ONLY

#if !CONFIG_IDF_TARGET_ESP32S2 || !CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
#error "read-only eFuse enforcement requires ESP32-S2 anti-rollback checks"
#endif

#if CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD != 16
#error "the ESP32-S2 hardware version floor must use all 16 eFuse bits"
#endif

/*
 * ESP-IDF calls this when it selects an already VALID image and when it
 * initializes empty OTA metadata. Neither event authorizes a counter advance.
 * Returning an error for a requested change does not bypass the separate
 * version checks in bootloader_utility.c. The pinned IDF ignores this return
 * value during selection; the builder verifies that the real writer is absent.
 */
esp_err_t __wrap_esp_efuse_update_secure_version(uint32_t secure_version)
{
    if (secure_version == esp_efuse_read_secure_version()) {
        return ESP_OK;
    }
    return ESP_ERR_NOT_SUPPORTED;
}

/*
 * All ESP32-S2 eFuse field writes in the pinned IDF converge on this backend.
 * Block security initialization as well as counter writes. A fresh device
 * must be provisioned separately; this bootloader cannot provision it.
 */
esp_err_t __wrap_esp_efuse_utility_burn_chip_opt(
    bool ignore_coding_errors, bool verify_written_data)
{
    (void)ignore_coding_errors;
    (void)verify_written_data;
    return ESP_ERR_NOT_SUPPORTED;
}

#endif
