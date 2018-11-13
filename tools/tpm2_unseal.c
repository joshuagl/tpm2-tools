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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hash.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm_unseal_ctx tpm_unseal_ctx;
struct tpm_unseal_ctx {
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    char *outFilePath;
    char *raw_pcrs_file;
    char *session_file;
    char *parent_auth_str;
    TPML_PCR_SELECTION pcr_selection;
    const char *context_arg;
    tpm2_loaded_object context_object;
    struct {
        UINT8 p : 1;
        UINT8 L : 1;
    } flags;
};

static tpm_unseal_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
};

bool unseal_and_save(ESYS_CONTEXT *ectx) {

    bool ret = false;
    TPM2B_SENSITIVE_DATA *outData;

    TSS2_RC rval;

    ESYS_TR shandle1;
    bool ok = tpm2_auth_util_get_shandle(ectx, ctx.context_object.tr_handle,
                &ctx.auth.session_data, ctx.auth.session, &shandle1);
    if (!ok) {
        return false;
    }

    rval = Esys_Unseal(ectx, ctx.context_object.tr_handle,
                shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                &outData);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Unseal, rval);
        return false;
    }

    if (ctx.outFilePath) {
        ret = files_save_bytes_to_file(ctx.outFilePath, (UINT8 *)
                                        outData->buffer, outData->size);
    } else {
        ret = files_write_bytes(stdout, (UINT8 *) outData->buffer,
                                 outData->size);
    }

    free(outData);

    return ret;
}

static bool start_auth_session(ESYS_CONTEXT *ectx) {

    tpm2_session_data *session_data =
            tpm2_session_data_new(TPM2_SE_POLICY);
    if (!session_data) {
        LOG_ERR("oom");
        return false;
    }

    ctx.auth.session = tpm2_session_new(ectx,
            session_data);
    if (!ctx.auth.session) {
        LOG_ERR("Could not start tpm session");
        return false;
    }

    bool result = tpm2_policy_build_pcr(ectx, ctx.auth.session,
                    ctx.raw_pcrs_file, &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        return false;
    }

    return true;
}

static bool init(ESYS_CONTEXT *ectx) {

    if (!ctx.context_arg) {
        LOG_ERR("Expected option c");
        return false;
    }

    bool retval = tpm2_util_object_load(ectx, ctx.context_arg,
                    &ctx.context_object);
    if (!retval) {
        return false;
    } else if (!ctx.context_object.tr_handle) {
        retval = tpm2_util_sys_handle_to_esys_handle(ectx,
                    ctx.context_object.handle,
                    &ctx.context_object.tr_handle);
        if (!retval) {
            return false;
        }
    }

    if (ctx.flags.L) {
        bool result = start_auth_session(ectx);
        if (!result) {
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'p': {
        ctx.flags.p = 1;
        ctx.parent_auth_str = value;
    }
        break;
    case 'o':
        ctx.outFilePath = value;
        break;
    case 'L':
        if (!pcr_parse_selections(value, &ctx.pcr_selection)) {
            return false;
        }
        ctx.flags.L = 1;
        break;
    case 'F':
        ctx.raw_pcrs_file = value;
        break;
        /* no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      { "auth-key",             required_argument, NULL, 'p' },
      { "out-file",             required_argument, NULL, 'o' },
      { "item-context",         required_argument, NULL, 'c' },
      { "set-list",             required_argument, NULL, 'L' },
      { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("p:o:c:L:F:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result = init(ectx);
    if (!result) {
        goto out;
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.parent_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid item handle authorization, got\"%s\"", ctx.parent_auth_str);
            goto out;
        }
    }

    result = unseal_and_save(ectx);
    if (!result) {
        LOG_ERR("Unseal failed!");
        goto out;
    }

    rc = 0;
out:

    if (ctx.flags.L) {
        /*
         * Only flush sessions started internally by the tool.
         */
        ESYS_TR handle = tpm2_session_get_handle(ctx.auth.session);
        TSS2_RC rval = Esys_FlushContext(ectx, handle);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_FlushContext, rval);
            rc = 1;
        }
    } else {
        result = tpm2_session_save(ectx, ctx.auth.session, NULL);
        if (!result) {
            rc = 1;
        }
    }

    return rc;
}

void tpm2_tool_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
