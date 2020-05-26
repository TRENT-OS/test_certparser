#include "CertParser.h"

#include "TestMacros.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// These are defined in the sub-tests
void
test_CertParser_Cert(
    CertParser_t* parser);
void
test_CertParser_Chain(
    CertParser_t* parser);

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

static CertParser_Config_t parserCfg;
static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.rng.entropy = entropy,
};

// Test Functions --------------------------------------------------------------

void
test_CertParser_init_pos(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_init_neg(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_free_pos(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_free_neg(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_addTrustedChain_pos(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_addTrustedChain_neg(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_verifyChain_pos(
    void)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_verifyChain_neg(
    void)
{
    TEST_START();
    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

int run()
{
    CertParser_t* parser;

    test_CertParser_init_pos();
    test_CertParser_init_neg();

    test_CertParser_free_pos();
    test_CertParser_free_neg();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    test_CertParser_Cert(parser);
    test_CertParser_Chain(parser);

    TEST_SUCCESS(CertParser_free(parser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    test_CertParser_addTrustedChain_pos();
    test_CertParser_addTrustedChain_neg();

    test_CertParser_verifyChain_pos();
    test_CertParser_verifyChain_neg();

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}