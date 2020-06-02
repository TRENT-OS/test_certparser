#include "CertParser.h"

#include "TestMacros.h"
#include "SharedCerts.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// Test Functions --------------------------------------------------------------

void
test_CertParser_Cert_init_pos(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;

    TEST_START();

    // Cert in PEM encoding
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Cert_free(cert));

    // Cert in DER encoding
    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_DER,
                                      serverCertDER, sizeof(serverCertDER)));
    TEST_SUCCESS(CertParser_Cert_free(cert));

    TEST_FINISH();
}

void
test_CertParser_Cert_init_neg(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;

    TEST_START();

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Cert_init(NULL, parser,
                                          CertParser_Cert_Encoding_PEM,
                                          serverCert, sizeof(serverCert)));

    // Empty parser
    TEST_INVAL_PARAM(CertParser_Cert_init(&cert, NULL, CertParser_Cert_Encoding_PEM,
                                          serverCert, sizeof(serverCert)));

    // Wrong encoding
    TEST_INVAL_PARAM(CertParser_Cert_init(&cert, parser,
                                          CertParser_Cert_Encoding_NONE,
                                          serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Cert_init(&cert, parser,
                                          CertParser_Cert_Encoding_PEM,
                                          NULL, sizeof(serverCert)));

    // Zero length
    TEST_INVAL_PARAM(CertParser_Cert_init(&cert, parser,
                                          CertParser_Cert_Encoding_PEM,
                                          serverCert, 0));

    // Unsupported hash algorithm
    TEST_NOT_SUPP(CertParser_Cert_init(&cert, parser,
                                       CertParser_Cert_Encoding_PEM,
                                       serverCertSha1, sizeof(serverCertSha1)));

    // Unsupported algorithm for cert signature
    TEST_NOT_SUPP(CertParser_Cert_init(&cert, parser,
                                       CertParser_Cert_Encoding_PEM,
                                       serverCertEcc, sizeof(serverCertEcc)));

    TEST_FINISH();
}

void
test_CertParser_Cert_free_pos(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Cert_free(cert));

    TEST_FINISH();
}

void
test_CertParser_Cert_free_neg(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;

    TEST_START();

    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Cert_free(NULL));

    TEST_SUCCESS(CertParser_Cert_free(cert));

    TEST_FINISH();
}

void
test_CertParser_Cert_getAttrib_pos(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;
    CertParser_Cert_Attrib_t attrib;

    TEST_START();

    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));

    // Get PUBLICKEY
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_PUBLICKEY, &attrib));
    TEST_TRUE(CertParser_Cert_Attrib_Type_PUBLICKEY == attrib.type);

    // Get SUBJECT
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_SUBJECT, &attrib));
    TEST_TRUE(CertParser_Cert_Attrib_Type_SUBJECT == attrib.type);

    // Get ISSUER
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_ISSUER, &attrib));
    TEST_TRUE(CertParser_Cert_Attrib_Type_ISSUER == attrib.type);

    TEST_SUCCESS(CertParser_Cert_free(cert));

    TEST_FINISH();
}

void
test_CertParser_Cert_getAttrib_neg(
    CertParser_t* parser)
{
    CertParser_Cert_t* cert;
    CertParser_Cert_Attrib_t attrib;

    TEST_START();

    TEST_SUCCESS(CertParser_Cert_init(&cert, parser, CertParser_Cert_Encoding_PEM,
                                      serverCert, sizeof(serverCert)));

    // Empty cert
    TEST_INVAL_PARAM(CertParser_Cert_getAttrib(NULL,
                                               CertParser_Cert_Attrib_Type_PUBLICKEY, &attrib));

    // Invalid attrib type
    TEST_INVAL_PARAM(CertParser_Cert_getAttrib(cert,
                                               CertParser_Cert_Attrib_Type_NONE, &attrib));

    // Empty result buffer
    TEST_INVAL_PARAM(CertParser_Cert_getAttrib(cert,
                                               CertParser_Cert_Attrib_Type_PUBLICKEY, NULL));

    TEST_SUCCESS(CertParser_Cert_free(cert));

    TEST_FINISH();
}

// Public Functions ------------------------------------------------------------

void
test_CertParser_Cert(
    CertParser_t* parser)
{
    test_CertParser_Cert_init_pos(parser);
    test_CertParser_Cert_init_neg(parser);

    test_CertParser_Cert_free_pos(parser);
    test_CertParser_Cert_free_neg(parser);

    test_CertParser_Cert_getAttrib_pos(parser);
    test_CertParser_Cert_getAttrib_neg(parser);
}