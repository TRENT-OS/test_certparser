cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_CERT
    SEOS_CRYPTO
)

project(test_cert_lib C)

DeclareCAmkESComponent(test_CertParser
    SOURCES
        components/Tests/src/test_CertParser.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        seos_cert
        seos_crypto
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()