#
# Test Certificate Parser lib
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config.h)

os_use_libs(
    OS_LIBS
    OS_CERT
    OS_CRYPTO
)

#-------------------------------------------------------------------------------
project(test_cert_lib C)

DeclareCAmkESComponent(
    test_CertParser
    SOURCES
        components/Tests/src/test_CertParser_Cert.c
        components/Tests/src/test_CertParser_Chain.c
        components/Tests/src/test_CertParser.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        os_libs
        os_cert
        os_crypto
)


GenerateCAmkESRootServer()
GenerateSimulateScript()
