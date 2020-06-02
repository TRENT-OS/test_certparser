#include "CertParser.h"

#include "TestMacros.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// Test Functions --------------------------------------------------------------

void
test_CertParser_Chain_init_pos(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void
test_CertParser_Chain_init_neg(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;

    TEST_START();

    // Empty chain
    TEST_INVAL_PARAM(CertParser_Chain_init(NULL, parser));

    // Empty parser
    TEST_INVAL_PARAM(CertParser_Chain_init(&chain, NULL));

    TEST_FINISH();
}

void
test_CertParser_Chain_free_pos(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;

    TEST_START();

    // Free chain and free all certs
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    // Free chain and don't free all certs
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Chain_free(chain, false));

    TEST_FINISH();
}

void
test_CertParser_Chain_free_neg(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));

    // Empty chain
    TEST_INVAL_PARAM(CertParser_Chain_free(NULL, true));

    TEST_SUCCESS(CertParser_Chain_free(chain, false));

    TEST_FINISH();
}

void
test_CertParser_Chain_addCert_pos(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));

    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void
test_CertParser_Chain_addCert_neg(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));

    // Empty chain
    TEST_INVAL_PARAM(CertParser_Chain_addCert(NULL, cert));

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Chain_addCert(chain, NULL));

    // Add a second cert which does not have the first cert as issuer
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      rootCert, sizeof(rootCert)));
    TEST_ABORTED(CertParser_Chain_addCert(chain, cert));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void
test_CertParser_Chain_getCert_pos(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    CertParser_Cert_Attrib_t aCert, aTmp;
    CertParser_Cert_t* cert;
    const CertParser_Cert_t* tmp;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    // Read cert back and make sure it is the same public key as the
    // cert we have added above
    TEST_SUCCESS(CertParser_Chain_getCert(chain, 0, &tmp));
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_PUBLICKEY, &aCert));
    TEST_SUCCESS(CertParser_Cert_getAttrib(tmp,
                                           CertParser_Cert_Attrib_Type_PUBLICKEY, &aTmp));
    TEST_TRUE(!memcmp(&aCert, &aTmp, sizeof(CertParser_Cert_Attrib_t)));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void
test_CertParser_Chain_getCert_neg(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;
    const CertParser_Cert_t* tmp;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));

    // Empty chain
    TEST_INVAL_PARAM(CertParser_Chain_getCert(NULL, 0, &tmp));

    // Invalid index
    TEST_NOT_FOUND(CertParser_Chain_getCert(chain, -1, &tmp));

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Chain_getCert(chain, 0, NULL));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void
test_CertParser_Chain_getLength_pos(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    CertParser_Cert_t* cert;
    size_t len;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));

    // Check empty chain len
    TEST_SUCCESS(CertParser_Chain_getLength(chain, &len));
    TEST_TRUE(0 == len);

    // Add one cert and check again
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, cert));
    TEST_SUCCESS(CertParser_Chain_getLength(chain, &len));
    TEST_TRUE(1 == len);

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

void test_CertParser_Chain_getLength_neg(
    CertParser_t* parser)
{
    CertParser_Chain_t* chain;
    size_t len;

    TEST_START();

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));

    // Empty chain
    TEST_INVAL_PARAM(CertParser_Chain_getLength(NULL, &len));

    // Empty len
    TEST_INVAL_PARAM(CertParser_Chain_getLength(chain, NULL));

    TEST_SUCCESS(CertParser_Chain_free(chain, true));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

void
test_CertParser_Chain(
    CertParser_t* parser)
{
    test_CertParser_Chain_init_pos(parser);
    test_CertParser_Chain_init_neg(parser);

    test_CertParser_Chain_free_pos(parser);
    test_CertParser_Chain_free_neg(parser);

    test_CertParser_Chain_addCert_pos(parser);
    test_CertParser_Chain_addCert_neg(parser);

    test_CertParser_Chain_getCert_pos(parser);
    test_CertParser_Chain_getCert_neg(parser);

    test_CertParser_Chain_getLength_pos(parser);
    test_CertParser_Chain_getLength_neg(parser);
}