#
# Test Certificate Parser library
#
# Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# use the SDK
find_package("os-sdk" REQUIRED)
os_sdk_set_defaults()
os_sdk_setup(CONFIG_FILE "config.h" CONFIG_PROJECT "system_config")


#-------------------------------------------------------------------------------
project(test_certparser C)

DeclareCAmkESComponent(
    test_OS_CertParser
    SOURCES
        components/Tests/src/test_OS_CertParser_Cert.c
        components/Tests/src/test_OS_CertParser_Chain.c
        components/Tests/src/test_OS_CertParser.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        lib_macros
        os_cert
)

EntropySource_DeclareCAmkESComponent(
    EntropySource
)

os_sdk_create_CAmkES_system("main.camkes")
