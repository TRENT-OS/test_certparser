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
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Cert_init_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Cert_free_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Cert_free_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Cert_getAttrib_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Cert_getAttrib_neg(
    CertParser_t* parser)
{
    TEST_START();
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