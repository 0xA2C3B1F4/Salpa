idf_component_register(
    SRCS "bootloader_start.c" "read_only_efuse.c"
    REQUIRES bootloader bootloader_support spi_flash efuse
)

if(CONFIG_RISSOKEY_EFUSE_READ_ONLY)
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=esp_efuse_update_secure_version"
        "-Wl,--wrap=esp_efuse_utility_burn_chip_opt"
        "-Wl,--undefined=__wrap_esp_efuse_update_secure_version"
        "-Wl,--undefined=__wrap_esp_efuse_utility_burn_chip_opt"
    )
endif()

idf_build_get_property(scripts BOOTLOADER_LINKER_SCRIPT)
target_linker_script(${COMPONENT_LIB} INTERFACE "${scripts}")
