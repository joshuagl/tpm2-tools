//**********************************************************************;
// Copyright (c) 2016, Intel Corporation
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

#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <tss2/tss2_esys.h>


#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_capability.h"
#include "tpm2_options.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_listpersistent_context tpm_listpersistent_context;
struct tpm_listpersistent_context {
    TPMI_ALG_HASH nameAlg;
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
};

static tpm_listpersistent_context ctx = {
    .nameAlg = TPM2_ALG_NULL,
    .type = TPM2_ALG_NULL,
};

static bool on_option(char key, char *value) {

    switch (key) {
    case 'g':
        ctx.nameAlg = tpm2_alg_util_from_optarg(value, tpm2_alg_util_flags_hash);
        if (ctx.nameAlg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid hash algorithm, got \"%s\"", value);
            return false;
        }
        break;
    case 'G':
        ctx.type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_symmetric
                |tpm2_alg_util_flags_asymmetric
                |tpm2_alg_util_flags_keyedhash);
        if (ctx.type == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid key algorithm, got \"%s\"", value);
            return false;
        }

        tpm2_alg_util_flags flags = tpm2_alg_util_algtoflags(ctx.type);
        if (flags & tpm2_alg_util_flags_keyedhash) {
            ctx.scheme = ctx.type;
            ctx.type = TPM2_ALG_KEYEDHASH;
        }

        if (flags & tpm2_alg_util_flags_symmetric) {
            ctx.scheme = ctx.type;
            ctx.type = TPM2_ALG_SYMCIPHER;
        }
    }

    return true;
}

static int read_public(ESYS_CONTEXT *ectx,
        TPM2_HANDLE objectHandle, TPM2B_PUBLIC **outPublic) {

    TSS2_RC rval;
    ESYS_TR objHandle = ESYS_TR_NONE;

    rval = Esys_TR_FromTPMPublic(ectx, objectHandle,
                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                    &objHandle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return -1;
    }

    rval = Esys_ReadPublic(ectx, objHandle,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        outPublic, NULL, NULL);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_ReadPublic, rval);
        return -1;
    }

    return 0;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
        {"halg", required_argument, NULL, 'g'},
        {"kalg", required_argument, NULL, 'G'},
    };

    *opts = tpm2_options_new("g:G:", ARRAY_LEN(topts), topts, on_option, NULL,
                             0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    TPMS_CAPABILITY_DATA *capabilityData;
    bool ret = tpm2_capability_get(ectx, TPM2_CAP_HANDLES,
                                TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES,
                                &capabilityData);
    if (!ret) {
        LOG_ERR("Failed to read TPM capabilities.");
        return 1;
    }

    UINT32 i;
    for (i = 0; i < capabilityData->data.handles.count; i++) {
        TPM2B_PUBLIC *outPublic = NULL;
        TPM2_HANDLE objectHandle = capabilityData->data.handles.handle[i];
        if (read_public(ectx, objectHandle, &outPublic)) {
            return 2;
        }

        TPMI_ALG_KEYEDHASH_SCHEME kh_scheme = outPublic->publicArea.parameters.keyedHashDetail.scheme.scheme;
        TPMI_ALG_KEYEDHASH_SCHEME sym_scheme = outPublic->publicArea.parameters.symDetail.sym.algorithm;
        TPMI_ALG_PUBLIC type = outPublic->publicArea.type;
        TPMI_ALG_HASH nameAlg = outPublic->publicArea.nameAlg;
        if ((ctx.type != TPM2_ALG_NULL && ctx.type != type)
                || (ctx.nameAlg != TPM2_ALG_NULL && ctx.nameAlg != nameAlg)
                || (ctx.type == TPM2_ALG_KEYEDHASH && kh_scheme != ctx.scheme)
                || (ctx.type == TPM2_ALG_SYMCIPHER && sym_scheme != ctx.scheme)) {
            /* Skip, filter me out */
            continue;
        }

        tpm2_tool_output("- handle: 0x%x\n", objectHandle);
        tpm2_util_public_to_yaml(outPublic, "  ");
        tpm2_tool_output("\n");
        free(outPublic);
    }

    return 0;
}
