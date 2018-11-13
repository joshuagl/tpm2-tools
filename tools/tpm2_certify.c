//**********************************************************************;
// Copyright (c) 2015-2018, Intel Corporation
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
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
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

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_convert.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_certify_ctx tpm_certify_ctx;
struct tpm_certify_ctx {
    TPMS_AUTH_COMMAND cmd_auth[2];
    tpm2_session *session[2];
    TPMI_ALG_HASH  halg;
    struct {
        char *attest;
        char *sig;
    } file_path;
    struct {
        UINT16 P : 1;
        UINT16 p : 1;
        UINT16 g : 1;
        UINT16 a : 1;
        UINT16 s : 1;
        UINT16 f : 1;
        UINT16 unused : 6;
    } flags;
    char *object_auth_str;
    char *key_auth_str;
    const char *key_context_arg;
    tpm2_loaded_object key_context_object;
    const char *context_arg;
    tpm2_loaded_object context_object;
    tpm2_convert_sig_fmt sig_fmt;
};

static tpm_certify_ctx ctx = {
    .cmd_auth = {
        TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
    },
    .sig_fmt = signature_format_tss,
};

static bool get_key_type(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT object_handle, TPMI_ALG_PUBLIC *type) {
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;

    TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TPM2B_NAME qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ReadPublic(sapi_context, object_handle, 0,
            &out_public, &name, &qualified_name, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ReadPublic, rval);
        *type = TPM2_ALG_ERROR;
        return false;
    }

    *type = out_public.publicArea.type;

    return true;
}

static bool set_scheme(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT key_handle,
        TPMI_ALG_HASH halg, TPMT_SIG_SCHEME *scheme) {

    TPM2_ALG_ID type;
    bool result = get_key_type(sapi_context, key_handle, &type);
    if (!result) {
        return false;
    }

    switch (type) {
    case TPM2_ALG_RSA :
        scheme->scheme = TPM2_ALG_RSASSA;
        scheme->details.rsassa.hashAlg = halg;
        break;
    case TPM2_ALG_KEYEDHASH :
        scheme->scheme = TPM2_ALG_HMAC;
        scheme->details.hmac.hashAlg = halg;
        break;
    case TPM2_ALG_ECC :
        scheme->scheme = TPM2_ALG_ECDSA;
        scheme->details.ecdsa.hashAlg = halg;
        break;
    case TPM2_ALG_SYMCIPHER :
    default:
        LOG_ERR("Unknown key type, got: 0x%x", type);
        return false;
    }

    return true;
}

static bool certify_and_save_data(TSS2_SYS_CONTEXT *sapi_context) {

    TSS2L_SYS_AUTH_COMMAND cmd_auth_array = {
        .count = ARRAY_LEN(ctx.cmd_auth),
        .auths = { ctx.cmd_auth[0], ctx.cmd_auth[1]}
    };

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    TPM2B_DATA qualifying_data = {
        .size = 4,
        .buffer = { 0x00, 0xff, 0x55,0xaa }
    };

    TPMT_SIG_SCHEME scheme;
    bool result = set_scheme(sapi_context, ctx.key_context_object.handle, ctx.halg, &scheme);
    if (!result) {
        LOG_ERR("No suitable signing scheme!");
        return false;
    }

    TPM2B_ATTEST certify_info = {
        .size = sizeof(certify_info)-2
    };

    TPMT_SIGNATURE signature;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Certify(sapi_context, ctx.context_object.handle,
            ctx.key_context_object.handle, &cmd_auth_array, &qualifying_data, &scheme,
            &certify_info, &signature, &sessions_data_out));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_Certify, rval);
        return false;
    }

    /* serialization is safe here, since it's just a byte array */
    result = files_save_bytes_to_file(ctx.file_path.attest,
            certify_info.attestationData, certify_info.size);
    if (!result) {
        return false;
    }

    return tpm2_convert_sig_save(&signature, ctx.sig_fmt, ctx.file_path.sig);
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'C':
        ctx.context_arg = value;
        break;
    case 'c':
        ctx.key_context_arg = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.object_auth_str = value;
        break;
    case 'p':
        ctx.flags.p = 1;
        ctx.key_auth_str = value;
        break;
    case 'g':
        ctx.halg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.halg == TPM2_ALG_ERROR) {
            LOG_ERR("Could not format algorithm to number, got: \"%s\"", value);
            return false;
        }
        ctx.flags.g = 1;
        break;
    case 'a':
        ctx.file_path.attest = value;
        ctx.flags.a = 1;
        break;
    case 's':
        ctx.file_path.sig = value;
        ctx.flags.s = 1;
        break;
    case 'f':
        ctx.flags.f = 1;
        ctx.sig_fmt = tpm2_convert_sig_fmt_from_optarg(value);

        if (ctx.sig_fmt == signature_format_err) {
            return false;
        }
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "auth-object",   required_argument, NULL, 'P' },
      { "auth-key",      required_argument, NULL, 'p' },
      { "halg",          required_argument, NULL, 'g' },
      { "attest-file",   required_argument, NULL, 'a' },
      { "sig-file",      required_argument, NULL, 's' },
      { "obj-context",   required_argument, NULL, 'C' },
      { "key-context",   required_argument, NULL, 'c' },
      { "format",        required_argument, NULL, 'f' },
    };

    *opts = tpm2_options_new("P:p:g:a:s:c:C:f:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    size_t i;
    int rc = 1;
    bool result;

    UNUSED(flags);

    if ((!ctx.context_arg)
        && (!ctx.key_context_arg)
        && (ctx.flags.g) && (ctx.flags.a)
        && (ctx.flags.s)) {
        return -1;
    }

    /* Load input files */
    result = tpm2_util_object_load_sapi(sapi_context, ctx.context_arg,
            &ctx.context_object);
    if (!result) {
        tpm2_tool_output("Failed to load context object (handle: 0x%x, path: %s).\n",
                ctx.context_object.handle, ctx.context_object.path);
        goto out;
    }

    result = tpm2_util_object_load_sapi(sapi_context, ctx.key_context_arg,
            &ctx.key_context_object);
    if (!result) {
        tpm2_tool_output("Failed to load context object for key (handle: 0x%x, path: %s).\n",
                ctx.key_context_object.handle, ctx.key_context_object.path);
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.object_auth_str,
                &ctx.cmd_auth[0], &ctx.session[0]);
        if (!result) {
            LOG_ERR("Invalid object key authorization, got\"%s\"", ctx.object_auth_str);
            goto out;
        }
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(sapi_context, ctx.key_auth_str,
                &ctx.cmd_auth[1], &ctx.session[1]);
        if (!result) {
            LOG_ERR("Invalid key handle authorization, got\"%s\"", ctx.key_auth_str);
            goto out;
        }
    }

    result = certify_and_save_data(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    for (i=0; i < ARRAY_LEN(ctx.session); i++) {
        result = tpm2_session_save(sapi_context, ctx.session[i], NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_onexit(void) {

    size_t i;
    for (i=0; i < ARRAY_LEN(ctx.session); i++) {
        tpm2_session_free(&ctx.session[i]);
    }
}
