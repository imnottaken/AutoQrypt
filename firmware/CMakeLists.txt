cmake_minimum_required(VERSION 3.16)

# Firmware release built into this image: 1 = factory, 2 = feature update, 3 = fault-injected
# (crashes before confirming itself, to demonstrate bootloader rollback).
#   idf.py -B build_v2 -DAPP_FW_VERSION=2 build
if(NOT DEFINED APP_FW_VERSION)
    set(APP_FW_VERSION 1)
endif()
set(PROJECT_VER "v${APP_FW_VERSION}.0.0")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(autoqrypt-ecu-surrogate)
