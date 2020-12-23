#include "OS_CertParser.h"

#include "lib_macros/Test.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// Test Functions --------------------------------------------------------------

void
test_OS_CertParserCert_init_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    // Cert in PEM encoding
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    // Cert in DER encoding
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_DER,
                                        serverCertDER, sizeof(serverCertDER)));
    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    TEST_FINISH();
}

void
test_OS_CertParserCert_init_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserCert_init(NULL, hParser,
                                            OS_CertParserCert_Encoding_PEM,
                                            serverCert, sizeof(serverCert)));

    // Empty parser
    TEST_INVAL_PARAM(OS_CertParserCert_init(&hCert, NULL,
                                            OS_CertParserCert_Encoding_PEM,
                                            serverCert, sizeof(serverCert)));

    // Wrong encoding
    TEST_INVAL_PARAM(OS_CertParserCert_init(&hCert, hParser,
                                            OS_CertParserCert_Encoding_NONE,
                                            serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserCert_init(&hCert, hParser,
                                            OS_CertParserCert_Encoding_PEM,
                                            NULL, sizeof(serverCert)));

    // Zero length
    TEST_INVAL_PARAM(OS_CertParserCert_init(&hCert, hParser,
                                            OS_CertParserCert_Encoding_PEM,
                                            serverCert, 0));

    // Unsupported hash algorithm
    TEST_NOT_SUPP(OS_CertParserCert_init(&hCert, hParser,
                                         OS_CertParserCert_Encoding_PEM,
                                         serverCertSha1, sizeof(serverCertSha1)));

    // Unsupported algorithm for cert signature
    TEST_NOT_SUPP(OS_CertParserCert_init(&hCert, hParser,
                                         OS_CertParserCert_Encoding_PEM,
                                         serverCertEcc, sizeof(serverCertEcc)));

    TEST_FINISH();
}

void
test_OS_CertParserCert_free_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    TEST_FINISH();
}

void
test_OS_CertParserCert_free_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserCert_free(NULL));

    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    TEST_FINISH();
}

void
test_OS_CertParserCert_getAttrib_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;
    OS_CertParserCert_Attrib_t attrib;

    TEST_START();

    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));

    // Get PUBLICKEY
    TEST_SUCCESS(OS_CertParserCert_getAttrib(hCert,
                                             OS_CertParserCert_AttribType_PUBLICKEY, &attrib));
    TEST_TRUE(OS_CertParserCert_AttribType_PUBLICKEY == attrib.type);

    // Get SUBJECT
    TEST_SUCCESS(OS_CertParserCert_getAttrib(hCert,
                                             OS_CertParserCert_AttribType_SUBJECT, &attrib));
    TEST_TRUE(OS_CertParserCert_AttribType_SUBJECT == attrib.type);

    // Get ISSUER
    TEST_SUCCESS(OS_CertParserCert_getAttrib(hCert,
                                             OS_CertParserCert_AttribType_ISSUER, &attrib));
    TEST_TRUE(OS_CertParserCert_AttribType_ISSUER == attrib.type);

    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    TEST_FINISH();
}

void
test_OS_CertParserCert_getAttrib_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserCert_Handle_t hCert;
    OS_CertParserCert_Attrib_t attrib;

    TEST_START();

    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserCert_getAttrib(NULL,
                                                 OS_CertParserCert_AttribType_PUBLICKEY, &attrib));

    // Invalid attrib type
    TEST_INVAL_PARAM(OS_CertParserCert_getAttrib(hCert,
                                                 OS_CertParserCert_AttribType_NONE, &attrib));

    // Empty result buffer
    TEST_INVAL_PARAM(OS_CertParserCert_getAttrib(hCert,
                                                 OS_CertParserCert_AttribType_PUBLICKEY, NULL));

    TEST_SUCCESS(OS_CertParserCert_free(hCert));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

void
test_OS_CertParserCert(
    OS_CertParser_Handle_t hParser)
{
    test_OS_CertParserCert_init_pos(hParser);
    test_OS_CertParserCert_init_neg(hParser);

    test_OS_CertParserCert_free_pos(hParser);
    test_OS_CertParserCert_free_neg(hParser);

    test_OS_CertParserCert_getAttrib_pos(hParser);
    test_OS_CertParserCert_getAttrib_neg(hParser);
}