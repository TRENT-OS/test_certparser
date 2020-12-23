#include "OS_CertParser.h"

#include "lib_macros/Test.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <camkes.h>

// These are defined in the sub-tests
void
test_OS_CertParserCert(
    OS_CertParser_Handle_t hParser);
void
test_OS_CertParserChain(
    OS_CertParser_Handle_t hParser);

static OS_CertParser_Config_t parserCfg;
static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),
};

// Test Functions --------------------------------------------------------------

void
test_OS_CertParser_init_pos(
    void)
{
    OS_CertParser_Handle_t hParser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    TEST_SUCCESS(OS_CertParser_free(hParser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_init_neg(
    void)
{
    OS_CertParser_Handle_t hParser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));

    // Empty parser context
    TEST_INVAL_PARAM(OS_CertParser_init(NULL, &parserCfg));

    // Empty config
    TEST_INVAL_PARAM(OS_CertParser_init(&hParser, NULL));

    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    // Config with crypto not set
    parserCfg.hCrypto = NULL;
    TEST_INVAL_PARAM(OS_CertParser_init(&hParser, &parserCfg));

    TEST_FINISH();
}

void
test_OS_CertParser_free_pos(
    void)
{
    OS_CertParser_Handle_t hParser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    TEST_SUCCESS(OS_CertParser_free(hParser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_free_neg(
    void)
{
    OS_CertParser_Handle_t hParser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    // Empty context
    TEST_INVAL_PARAM(OS_CertParser_free(NULL, false));

    TEST_SUCCESS(OS_CertParser_free(hParser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_addTrustedChain_pos(
    void)
{
    OS_CertParser_Handle_t hParser;
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    // Construct chain of root and intermediate cert
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        rootCert, sizeof(rootCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        imedCert, sizeof(imedCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    // Add chain to parser
    TEST_SUCCESS(OS_CertParser_addTrustedChain(hParser, hChain));

    TEST_SUCCESS(OS_CertParser_free(hParser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_addTrustedChain_neg(
    void)
{
    OS_CertParser_Handle_t hParser;
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));

    // Try adding zero-length chain
    TEST_INVAL_PARAM(OS_CertParser_addTrustedChain(hParser, hChain));

    // Construct chain of root and intermediate cert
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        rootCert, sizeof(rootCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        imedCert, sizeof(imedCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    // Empty parser
    TEST_INVAL_PARAM(OS_CertParser_addTrustedChain(NULL, hChain));

    // Empty chain
    TEST_INVAL_PARAM(OS_CertParser_addTrustedChain(hParser, NULL));

    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_verifyChain_pos(
    void)
{
    OS_CertParser_Handle_t hParser;
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;
    OS_CertParser_VerifyFlags_t flags;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    // Construct chain of root and intermediate cert and add to parser
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        rootCert, sizeof(rootCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        imedCert, sizeof(imedCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParser_addTrustedChain(hParser, hChain));

    // Verify a cert that has been signed by the INTERMEDIATE
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParser_verifyChain(hParser, 0, hChain, &flags));
    TEST_TRUE(OS_CertParser_VerifyFlags_NONE == flags);
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    // Verify a cert that has been signed by the ROOT
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCertRoot, sizeof(serverCertRoot)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParser_verifyChain(hParser, 0, hChain, &flags));
    TEST_TRUE(OS_CertParser_VerifyFlags_NONE == flags);
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_SUCCESS(OS_CertParser_free(hParser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_OS_CertParser_verifyChain_neg(
    void)
{
    OS_CertParser_Handle_t hParser;
    OS_CertParserChain_Handle_t hChain;
    OS_CertParserCert_Handle_t hCert;
    OS_CertParser_VerifyFlags_t flags;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    // Construct chain of root and intermediate cert and add to parser
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        rootCert, sizeof(rootCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        imedCert, sizeof(imedCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_SUCCESS(OS_CertParser_addTrustedChain(hParser, hChain));

    // Create a working chain for cert-to-be-verified
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCert, sizeof(serverCert)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));

    // Empty parser
    TEST_INVAL_PARAM(OS_CertParser_verifyChain(NULL, 0, hChain, &flags));

    // Invalid trusted chain index
    TEST_NOT_FOUND(OS_CertParser_verifyChain(hParser, -1, hChain, &flags));

    // Empty input chain
    TEST_INVAL_PARAM(OS_CertParser_verifyChain(hParser, 0, NULL, &flags));

    // Empty flags
    TEST_INVAL_PARAM(OS_CertParser_verifyChain(hParser, 0, hChain, NULL));

    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    // Certificate has too small key (768 bits)
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCertSmall, sizeof(serverCertSmall)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_GENERIC(OS_CertParser_verifyChain(hParser, 0, hChain, &flags));
    TEST_TRUE(OS_CertParser_VerifyFlags_INVALID_KEY == flags);
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    // Certificate is not signed by trusted chain (it is self signed)
    TEST_SUCCESS(OS_CertParserChain_init(&hChain, hParser));
    TEST_SUCCESS(OS_CertParserCert_init(&hCert, hParser,
                                        OS_CertParserCert_Encoding_PEM,
                                        serverCertSelf, sizeof(serverCertSelf)));
    TEST_SUCCESS(OS_CertParserChain_addCert(hChain, hCert));
    TEST_GENERIC(OS_CertParser_verifyChain(hParser, 0, hChain, &flags));
    TEST_TRUE(OS_CertParser_VerifyFlags_INVALID_SIG == flags);
    TEST_SUCCESS(OS_CertParserChain_free(hChain, true));

    TEST_SUCCESS(OS_CertParser_free(hParser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

int run()
{
    OS_CertParser_Handle_t hParser;

    /*
     * The sequence of tests is arranged with ascening complexity:
     * 1. Do all tests that do not require parser initialization to work
     * 2. Do all tests of the _Cert and _Chain sub-module, which require a
     *    working parser initialization/free
     * 3. Do all parser tests that require working _Chain and _Cert sub-modules
     */

    test_OS_CertParser_init_pos();
    test_OS_CertParser_init_neg();

    test_OS_CertParser_free_pos();
    test_OS_CertParser_free_neg();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(OS_CertParser_init(&hParser, &parserCfg));

    test_OS_CertParserCert(hParser);
    test_OS_CertParserChain(hParser);

    TEST_SUCCESS(OS_CertParser_free(hParser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    test_OS_CertParser_addTrustedChain_pos();
    test_OS_CertParser_addTrustedChain_neg();

    test_OS_CertParser_verifyChain_pos();
    test_OS_CertParser_verifyChain_neg();

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}