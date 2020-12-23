#
# Test Certificate Parser library
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config.h)


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

DeclareAndCreateCamkESSystem(main.camkes)
GenerateSimulateScript()
