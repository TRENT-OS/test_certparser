#include "OS_CertParser.h"

#include "lib_macros/Test.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// Test Functions --------------------------------------------------------------

void
test_OS_CertParserChain_init_pos(
    OS_CertParser_Handle_t parser)
{
    OS_CertParserChain_Handle_t hChain;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, parser));
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void
test_OS_CertParserChain_init_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;

    TEST_START();

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParserChain_init(NULL, hParser));

    // Empty parser
    TEST_INVAL_PARAM(OS_CertParserChain_init(&hChain, NULL));

    TEST_FINISH();
}

void
test_OS_CertParserChain_free_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;

    TEST_START();

    // Free chain and free all certs
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    // Free chain and don't free all certs
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserChain_free(hChain, false));

    TEST_FINISH();
}

void
test_OS_CertParserChain_free_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParserChain_free(NULL, true));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, false));

    TEST_FINISH();
}

void
test_OS_CertParserChain_addCert_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));

    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void
test_OS_CertParserChain_addCert_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParserChain_addCert(NULL, hCert));

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserChain_addCert(hChain, NULL));

    // Add a second cert which does not have the first cert as issuer
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        rootCert, sizeof(rootCert)));
    TEST_ABORTED(OS_CertParserChain_addCert(hChain, hCert));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void
test_OS_CertParserChain_getCert_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Attrib_t aCert, aTmp;
    OS_CertParserCert_Handle_t hCert;
    OS_CertParserCert_Handle_t tmp;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    // Read cert back and make sure it is the same public key as the
    // cert we have added above
    TEST_SUCCESS(OS_CertParserChain_getCert(hChain, 0, &tmp));
    TEST_SUCCESS(OS_CertParserCert_getAttrib(hCert,
                                             OS_CertParserCert_AttribType_PUBLICKEY, &aCert));
    TEST_SUCCESS(OS_CertParserCert_getAttrib(tmp,
                                             OS_CertParserCert_AttribType_PUBLICKEY, &aTmp));
    TEST_TRUE(!memcmp(&aCert, &aTmp, sizeof(OS_CertParserCert_Attrib_t)));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void
test_OS_CertParserChain_getCert_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;
    OS_CertParserCert_Handle_t tmp;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParserChain_getCert(NULL, 0, &tmp));

    // Invalid index
    TEST_NOT_FOUND(OS_CertParserChain_getCert(hChain, -1, &tmp));

    // Empty cert
    TEST_INVAL_PARAM(OS_CertParserChain_getCert(hChain, 0, NULL));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void
test_OS_CertParserChain_getLength_pos(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;
    size_t len;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));

    // Check empty chain len
    TEST_SUCCESS(OS_CertParserChain_getLength(hChain, &len));
    TEST_TRUE(0 == len);

    // Add one cert and check again
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserChain_getLength(hChain, &len));
    TEST_TRUE(1 == len);

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

void test_OS_CertParserChain_getLength_neg(
    OS_CertParser_Handle_t hParser)
{
    OS_CertParserChain_Handle_t hChain;
    size_t len;

    TEST_START();

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParserChain_getLength(NULL, &len));

    // Empty len
    TEST_INVAL_PARAM(OS_CertParserChain_getLength(hChain, NULL));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

void
test_OS_CertParserChain(
    OS_CertParser_Handle_t hParser)
{
    test_OS_CertParserChain_init_pos(hParser);
    test_OS_CertParserChain_init_neg(hParser);

    test_OS_CertParserChain_free_pos(hParser);
    test_OS_CertParserChain_free_neg(hParser);

    test_OS_CertParserChain_addCert_pos(hParser);
    test_OS_CertParserChain_addCert_neg(hParser);

    test_OS_CertParserChain_getCert_pos(hParser);
    test_OS_CertParserChain_getCert_neg(hParser);

    test_OS_CertParserChain_getLength_pos(hParser);
    test_OS_CertParserChain_getLength_neg(hParser);
}