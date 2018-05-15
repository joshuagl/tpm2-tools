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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>
#include <ctype.h>

#include <tss2/tss2_sys.h>

#include "files.h"
#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_error.h"
#include "tpm2_options.h"
#include "tpm2_util.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"

typedef struct tpm_activatecred_ctx tpm_activatecred_ctx;
struct tpm_activatecred_ctx {

    struct {
        UINT8 f : 1;
        UINT8 o : 1;
    } flags;

    struct {
        tpm2_auth endorse;
        tpm2_auth key;
    } auths;

    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    const char *output_file;
    const char *ctx_arg;
    const char *key_ctx_arg;
    tpm2_loaded_object ctx_obj;
    tpm2_loaded_object key_ctx_obj;
};

static tpm_activatecred_ctx ctx = {
        .auths = {
            .endorse = TPM2_AUTH_INIT(1, tpm2_auth_all),
            .key = TPM2_AUTH_INIT(1, tpm2_auth_password)
        },
};

static bool read_cert_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    uint32_t version;
    result = files_read_header(fp, &version);
    if (!result) {
        LOG_ERR("Could not read version header");
        goto out;
    }

    if (version != 1) {
        LOG_ERR("Unknown credential format, got %"PRIu32" expected 1",
                version);
        goto out;
    }

    result = files_read_16(fp, &cred->size);
    if (!result) {
        LOG_ERR("Could not read credential size");
        goto out;
    }

    result = files_read_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not read credential data");
        goto out;
    }

    result = files_read_16(fp, &secret->size);
    if (!result) {
        LOG_ERR("Could not read secret size");
        goto out;
    }

    result = files_read_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}

static bool output_and_save(TPM2B_DIGEST *digest, const char *path) {

    tpm2_tool_output("certinfodata:");

    unsigned k;
    for (k = 0; k < digest->size; k++) {
        tpm2_tool_output("%.2x", digest->buffer[k]);
    }
    tpm2_tool_output("\n");

    return files_save_bytes_to_file(path, digest->buffer, digest->size);
}

static bool activate_credential_and_output(TSS2_SYS_CONTEXT *sapi_context) {

    bool res = false;
    TPM2B_DIGEST certInfoData = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

    tpm2_session_data *d = tpm2_session_data_new(TPM2_SE_POLICY);
    if (!d) {
        LOG_ERR("oom");
        return false;
    }

    tpm2_session *session = tpm2_session_new(sapi_context, d);
    if (!session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    TPMI_SH_AUTH_SESSION handle = tpm2_session_get_handle(session);


    TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
            handle, &ctx.auths.endorse.auth_list, 0, 0, 0, 0, 0, 0, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_PolicySecret, rval);
        return false;
    }

    ctx.auths.key.auth_list.count = 2;
    ctx.auths.key.auth_list.auths[1].sessionHandle = handle;
    ctx.auths.key.auth_list.auths[1].sessionAttributes |=
            TPMA_SESSION_CONTINUESESSION;
    ctx.auths.key.auth_list.auths[1].hmac.size = 0;

    rval = TSS2_RETRY_EXP(Tss2_Sys_ActivateCredential(sapi_context, ctx.ctx_obj.handle,
            ctx.key_ctx_obj.handle, &ctx.auths.key.auth_list, &ctx.credentialBlob, &ctx.secret,
            &certInfoData, 0));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ActivateCredential, rval);
        goto out;
    }

    // Need to flush the session here.
    rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_FlushContext, rval);
        goto out;
    }

    res = output_and_save(&certInfoData, ctx.output_file);

out:
    tpm2_session_free(&session);
    ctx.auths.key.auth_list.count = 1;
    return res;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.ctx_arg = value;
        break;
    case 'C':
        ctx.key_ctx_arg = value;
        break;
    case 'P':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.key);
        if (!result) {
            return false;
        }
        break;
    case 'E':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.endorse);
        if (!result) {
            return false;
        }
        break;
    case 'f':
        /* logs errors */
        result = read_cert_secret(value, &ctx.credentialBlob,
                &ctx.secret);
        if (!result) {
            return false;
        }
        ctx.flags.f = 1;
        break;
    case 'o':
        ctx.output_file = value;
        ctx.flags.o = 1;
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
         {"context",        required_argument, NULL, 'c'},
         {"key-context",    required_argument, NULL, 'C'},
         {"auth-key",       required_argument, NULL, 'P'},
         {"endorse-passwd", required_argument, NULL, 'E'},
         {"in-file",        required_argument, NULL, 'f'},
         {"out-file",       required_argument, NULL, 'o'},
    };

    *opts = tpm2_options_new("c:C:P:E:f:o:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    int rc = 1;

    /* opts is unused, avoid compiler warning */
    UNUSED(flags);

    if ((!ctx.ctx_arg)
            && (!ctx.key_ctx_arg)
            && !ctx.flags.f && !ctx.flags.o) {
        LOG_ERR("Expected options c and C and f and o.");
        return -1;
    }

    bool res = tpm2_util_object_load(sapi_context, ctx.ctx_arg, &ctx.ctx_obj);
    if (!res) {
        tpm2_tool_output(
                "Failed to load context object (handle: 0x%x, path: %s).\n",
                ctx.ctx_obj.handle, ctx.ctx_obj.path);
        return 1;
    }

    res = tpm2_util_object_load(sapi_context, ctx.key_ctx_arg, &ctx.key_ctx_obj);
    if (!res) {
        tpm2_tool_output("Failed to load context object for key (handle: 0x%x, path: %s).\n",
                ctx.key_ctx_obj.handle, ctx.key_ctx_obj.path);
        return 1;
    }

    bool result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.key, NULL);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for key");
        goto out;
    }

    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.endorse, NULL);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for endorsement hierarchy");
        goto out;
    }

    res = activate_credential_and_output(sapi_context);
    if (!res) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_auth_util_free(sapi_context, &ctx.auths.key);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
        rc = 1;
    }

    result = tpm2_auth_util_free(sapi_context, &ctx.auths.endorse);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
        rc = 1;
    }

    return rc;
}
