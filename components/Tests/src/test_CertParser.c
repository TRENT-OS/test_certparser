#include "CertParser.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "TestMacros.h"
#include "TestCerts.h"

typedef struct
{
    const uint8_t* cert;
    size_t len;
} certData_t;

static const uint8_t rootCert[]   = TEST_ROOT_CA_CERT;
static const uint8_t imedCert[]   = TEST_IMED_CA_CERT;
static const uint8_t serverCert[] = TEST_SERVER_CERT;

static const certData_t caChain[] =
{
    { rootCert, sizeof(rootCert) },
    { imedCert, sizeof(imedCert) },
};

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

static OS_Crypto_Config_t cfgCrypto =
{
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.rng.entropy = entropy,
};

// Public Functions -----------------------------------------------------------

int run()
{
    size_t len = sizeof(caChain) / sizeof(certData_t);
    CertParser_t* parser;
    CertParser_Cert_t* certs[len];
    CertParser_Cert_Attrib_t attr;
    CertParser_Cert_t* server;
    CertParser_Chain_t* chain;
    CertParser_Config_t cfgCert;
    CertParser_VerifyFlags_t flags;
    const CertParser_Cert_t* cert;

    TEST_SUCCESS(OS_Crypto_init(&cfgCert.hCrypto, &cfgCrypto));

    TEST_SUCCESS(CertParser_init(&parser, &cfgCert));
    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));

    for (size_t i = 0; i < len; i++)
    {
        TEST_SUCCESS(CertParser_Cert_init(&certs[i],
                                          parser,
                                          CertParser_Cert_Encoding_PEM,
                                          caChain[i].cert,
                                          caChain[i].len));
        TEST_SUCCESS(CertParser_Chain_addCert(chain, certs[i]));
    }

    TEST_SUCCESS(CertParser_Chain_getCert(chain, 0, &cert));
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_SUBJECT,
                                           &attr));
    Debug_LOG_DEBUG("SUBJECT: %s\n", attr.data.subject);
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_ISSUER,
                                           &attr));
    Debug_LOG_DEBUG("ISSUER: %s\n", attr.data.issuer);

    TEST_SUCCESS(CertParser_Chain_getCert(chain, 1, &cert));
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_SUBJECT,
                                           &attr));
    Debug_LOG_DEBUG("SUBJECT: %s\n", attr.data.subject);
    TEST_SUCCESS(CertParser_Cert_getAttrib(cert,
                                           CertParser_Cert_Attrib_Type_ISSUER,
                                           &attr));
    Debug_LOG_DEBUG("ISSUER: %s\n", attr.data.issuer);

    TEST_SUCCESS(CertParser_addTrustedChain(parser, chain));

    TEST_SUCCESS(CertParser_Chain_init(&chain, parser));
    TEST_SUCCESS(CertParser_Cert_init(&server,
                                      parser,
                                      CertParser_Cert_Encoding_PEM,
                                      serverCert,
                                      sizeof(serverCert)));
    TEST_SUCCESS(CertParser_Chain_addCert(chain, server));

    TEST_SUCCESS(CertParser_Cert_getAttrib(server,
                                           CertParser_Cert_Attrib_Type_SUBJECT,
                                           &attr));
    Debug_LOG_DEBUG("SUBJECT: %s\n", attr.data.subject);
    TEST_SUCCESS(CertParser_Cert_getAttrib(server,
                                           CertParser_Cert_Attrib_Type_ISSUER,
                                           &attr));
    Debug_LOG_DEBUG("ISSUER: %s\n", attr.data.issuer);

    TEST_SUCCESS(CertParser_verifyChain(parser, 0, chain, &flags));

    // Free context, chain and all certs
    TEST_SUCCESS(CertParser_Chain_free(chain, true));
    TEST_SUCCESS(CertParser_free(parser, true));

    return 0;
}