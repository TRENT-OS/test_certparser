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
    CertParser_t* parser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    TEST_SUCCESS(CertParser_free(parser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_init_neg(
    void)
{
    CertParser_t* parser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));

    // Empty parser context
    TEST_INVAL_PARAM(CertParser_init(NULL, &parserCfg));

    // Empty config
    TEST_INVAL_PARAM(CertParser_init(&parser, NULL));

    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    // Config with crypto not set
    parserCfg.hCrypto = NULL;
    TEST_INVAL_PARAM(CertParser_init(&parser, &parserCfg));

    TEST_FINISH();
}

void
test_CertParser_free_pos(
    void)
{
    CertParser_t* parser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    TEST_SUCCESS(CertParser_free(parser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_free_neg(
    void)
{
    CertParser_t* parser;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    // Empty context
    TEST_INVAL_PARAM(CertParser_free(NULL, false));

    TEST_SUCCESS(CertParser_free(parser, false));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_addTrustedChain_pos(
    void)
{
    CertParser_t* parser;
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    // Construct chain of root and intermediate cert
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      rootCert, sizeof(rootCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      imedCert, sizeof(imedCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    // Add chain to parser
    TEST_SUCCESS(CertParser_addTrustedChain(parser, chain));

    TEST_SUCCESS(CertParser_free(parser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_addTrustedChain_neg(
    void)
{
    CertParser_t* parser;
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));

    // Try adding zero-length chain
    TEST_INVAL_PARAM(CertParser_addTrustedChain(parser, chain));

    // Construct chain of root and intermediate cert
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      rootCert, sizeof(rootCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      imedCert, sizeof(imedCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    // Empty parser
    TEST_INVAL_PARAM(CertParser_addTrustedChain(NULL, chain));

    // Empty chain
    TEST_INVAL_PARAM(CertParser_addTrustedChain(parser, NULL));

    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_verifyChain_pos(
    void)
{
    CertParser_t* parser;
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;
    CertParser_VerifyFlags_t flags;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    // Construct chain of root and intermediate cert and add to parser
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      rootCert, sizeof(rootCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      imedCert, sizeof(imedCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_addTrustedChain(parser, chain));

    // Verify a cert that has been signed by the INTERMEDIATE
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_verifyChain(parser, 0, chain, &flags));
    TEST_TRUE(CertParser_VerifyFlags_NONE == flags);
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    // Verify a cert that has been signed by the ROOT
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCertRoot, sizeof(serverCertRoot)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_verifyChain(parser, 0, chain, &flags));
    TEST_TRUE(CertParser_VerifyFlags_NONE == flags);
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_SUCCESS(CertParser_free(parser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

void
test_CertParser_verifyChain_neg(
    void)
{
    CertParser_t* parser;
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;
    CertParser_VerifyFlags_t flags;

    TEST_START();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    // Construct chain of root and intermediate cert and add to parser
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      rootCert, sizeof(rootCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      imedCert, sizeof(imedCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_addTrustedChain(parser, chain));

    // Create a working chain for cert-to-be-verified
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    // Empty parser
    TEST_INVAL_PARAM(CertParser_verifyChain(NULL, 0, chain, &flags));

    // Invalid trusted chain index
    TEST_NOT_FOUND(CertParser_verifyChain(parser, -1, chain, &flags));

    // Empty input chain
    TEST_INVAL_PARAM(CertParser_verifyChain(parser, 0, NULL, &flags));

    // Empty flags
    TEST_INVAL_PARAM(CertParser_verifyChain(parser, 0, chain, NULL));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    // Certificate has too small key (768 bits)
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCertSmall, sizeof(serverCertSmall)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_GENERIC(CertParser_verifyChain(parser, 0, chain, &flags));
    TEST_TRUE(CertParser_VerifyFlags_INVALID_KEY == flags);
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    // Certificate is not signed by trusted chain (it is self signed)
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCertSelf, sizeof(serverCertSelf)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_GENERIC(CertParser_verifyChain(parser, 0, chain, &flags));
    TEST_TRUE(CertParser_VerifyFlags_INVALID_SIG == flags);
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_SUCCESS(CertParser_free(parser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

int run()
{
    CertParser_t* parser;

    /*
     * The sequence of tests is arranged with ascening complexity:
     * 1. Do all tests that do not require parser initialization to work
     * 2. Do all tests of the _Cert and _Chain sub-module, which require a
     *    working parser initialization/free
     * 3. Do all parser tests that require working _Chain and _Cert sub-modules
     */

    test_CertParser_init_pos();
    test_CertParser_init_neg();

    test_CertParser_free_pos();
    test_CertParser_free_neg();

    TEST_SUCCESS(OS_Crypto_init(&parserCfg.hCrypto, &cfgCrypto));
    TEST_SUCCESS(CertParser_init(&parser, &parserCfg));

    test_CertParser_Cert(parser);
    test_CertParser_Chain(parser);

    TEST_SUCCESS(CertParser_free(parser, true));
    TEST_SUCCESS(OS_Crypto_free(parserCfg.hCrypto));

    test_CertParser_addTrustedChain_pos();
    test_CertParser_addTrustedChain_neg();

    test_CertParser_verifyChain_pos();
    test_CertParser_verifyChain_neg();

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}