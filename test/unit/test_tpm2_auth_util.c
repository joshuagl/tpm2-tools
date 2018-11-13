//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <tss2/tss2_sys.h>

#include "tpm2_util.h"
#include "tpm2_auth_util.h"

#include "esys_stubs.h"
#include "test_session_common.h"

TSS2_RC __wrap_Esys_TR_SetAuth(ESYS_CONTEXT *esysContext, ESYS_TR handle,
			TPM2B_AUTH const *authValue) {
	UNUSED(esysContext);
	UNUSED(handle);
	UNUSED(authValue);

	return TPM2_RC_SUCCESS;
}

static void test_tpm2_password_util_from_optarg_raw_noprefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;
    bool res = tpm2_auth_util_from_optarg(NULL, "abcd", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 4);
    assert_memory_equal(dest.hmac.buffer, "abcd", 4);
}

static void test_tpm2_password_util_from_optarg_str_prefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;
    bool res = tpm2_auth_util_from_optarg(NULL, "str:abcd", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 4);
    assert_memory_equal(dest.hmac.buffer, "abcd", 4);
}

static void test_tpm2_password_util_from_optarg_hex_prefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;
    BYTE expected[] = {
            0x12, 0x34, 0xab, 0xcd
    };

    bool res = tpm2_auth_util_from_optarg(NULL, "hex:1234abcd", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, sizeof(expected));
    assert_memory_equal(dest.hmac.buffer, expected, sizeof(expected));
}

static void test_tpm2_password_util_from_optarg_str_escaped_hex_prefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;

    bool res = tpm2_auth_util_from_optarg(NULL, "str:hex:1234abcd", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 12);
    assert_memory_equal(dest.hmac.buffer, "hex:1234abcd", 12);
}

static void test_tpm2_password_util_from_optarg_raw_overlength(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;
    char *overlength = "this_password_is_over_64_characters_in_length_and_should_fail_XXX";
    bool res = tpm2_auth_util_from_optarg(NULL, overlength, &dest, NULL);
    assert_false(res);
}

static void test_tpm2_password_util_from_optarg_hex_overlength(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest;
    /* 65 hex chars generated via: echo \"`xxd -p -c256 -l65 /dev/urandom`\"\; */
    char *overlength =
        "ae6f6fa01589aa7b227bb6a34c7a8e0c273adbcf14195ce12391a5cc12a5c271f62088"
        "dbfcf1914fdf120da183ec3ad6cc78a2ffd91db40a560169961e3a6d26bf";
    bool res = tpm2_auth_util_from_optarg(NULL, overlength, &dest, NULL);
    assert_false(res);
}

static void test_tpm2_password_util_from_optarg_empty_str(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest = {
        .hmac = { .size = 42 }
    };

    bool res = tpm2_auth_util_from_optarg(NULL, "", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 0);
}

static void test_tpm2_password_util_from_optarg_empty_str_str_prefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest = {
        .hmac = { .size = 42 }
    };

    bool res = tpm2_auth_util_from_optarg(NULL, "str:", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 0);
}


static void test_tpm2_password_util_from_optarg_empty_str_hex_prefix(void **state) {
    (void)state;

    TPMS_AUTH_COMMAND dest = {
        .hmac = { .size = 42 }
    };

    bool res = tpm2_auth_util_from_optarg(NULL, "hex:", &dest, NULL);
    assert_true(res);
    assert_int_equal(dest.hmac.size, 0);
}

static int setup(void **state) {
    TSS2_RC rc;
    ESYS_CONTEXT *ectx;
    size_t size = sizeof(TSS2_TCTI_CONTEXT_FAKE);
    TSS2_TCTI_CONTEXT *tcti = malloc(size);

    rc = tcti_fake_initialize(tcti, &size);
    if (rc) {
      return (int)rc;
    }
    rc = Esys_Initialize(&ectx, tcti, NULL);
    *state = (void *)ectx;
    return (int)rc;
}

static int teardown(void **state) {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    Esys_GetTcti(ectx, &tcti);
    Esys_Finalize(&ectx);
    free(tcti);
    return 0;
}

static void test_tpm2_auth_util_get_shandle(void **state) {

    ESYS_CONTEXT *ectx = (ESYS_CONTEXT *)*state;
    ESYS_TR auth_handle;
    ESYS_TR shandle;
    TPMS_AUTH_COMMAND auth = TPMS_AUTH_COMMAND_EMPTY_INIT;

    bool res = tpm2_auth_util_get_shandle(ectx, auth_handle, &auth, NULL,
                    &shandle);
    assert_true(res);
    assert_true(shandle == ESYS_TR_PASSWORD);

    set_expected_defaults(TPM2_SE_POLICY, SESSION_HANDLE, TPM2_RC_SUCCESS);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    assert_non_null(d);

    tpm2_session *s = tpm2_session_new(ectx, d);
    assert_non_null(s);

    res = tpm2_auth_util_get_shandle(ectx, auth_handle, &auth, s, &shandle);
    assert_true(res);

    assert_int_equal(SESSION_HANDLE, shandle);
}

/* link required symbol, but tpm2_tool.c declares it AND main, which
 * we have a main below for cmocka tests.
 */
bool output_enabled = true;

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_tpm2_password_util_from_optarg_raw_noprefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_str_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_hex_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_str_escaped_hex_prefix),

            cmocka_unit_test_setup_teardown(test_tpm2_auth_util_get_shandle,
                                            setup, teardown),

            /* negative testing */
            cmocka_unit_test(test_tpm2_password_util_from_optarg_raw_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_hex_overlength),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_str_prefix),
            cmocka_unit_test(test_tpm2_password_util_from_optarg_empty_str_hex_prefix)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
