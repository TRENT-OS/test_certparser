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
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_init_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_free_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_free_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_addCert_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_addCert_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_getCert_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_getCert_neg(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void
test_CertParser_Chain_getLength_pos(
    CertParser_t* parser)
{
    TEST_START();
    TEST_FINISH();
}

void test_CertParser_Chain_getLength_neg(
    CertParser_t* parser)
{
    TEST_START();
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