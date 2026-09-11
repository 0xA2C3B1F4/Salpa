cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{SALPA_SIGNED_AB_BOOTLOADER} AND DEFINED ENV{RISSO_KEY_SIGNED_AB_BOOTLOADER}
   AND NOT "$ENV{SALPA_SIGNED_AB_BOOTLOADER}" STREQUAL "$ENV{RISSO_KEY_SIGNED_AB_BOOTLOADER}")
    message(FATAL_ERROR "conflicting environment variables: SALPA_SIGNED_AB_BOOTLOADER and RISSO_KEY_SIGNED_AB_BOOTLOADER")
endif()
if(DEFINED ENV{SALPA_SIGNED_AB_BOOTLOADER})
    set(salpa_signed_ab_bootloader "$ENV{SALPA_SIGNED_AB_BOOTLOADER}")
else()
    set(salpa_signed_ab_bootloader "$ENV{RISSO_KEY_SIGNED_AB_BOOTLOADER}")
endif()
if(NOT "${salpa_signed_ab_bootloader}" STREQUAL "1")
    set(BOOTLOADER_IGNORE_EXTRA_COMPONENT "main")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(salpa_bootloader_builds)
