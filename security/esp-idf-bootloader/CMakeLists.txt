cmake_minimum_required(VERSION 3.16)

if(NOT "$ENV{RISSO_KEY_SIGNED_AB_BOOTLOADER}" STREQUAL "1")
    set(BOOTLOADER_IGNORE_EXTRA_COMPONENT "main")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(rissokey_bootloader_builds)
