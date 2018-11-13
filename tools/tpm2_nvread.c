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
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_nv_util.h"
#include "tpm2_options.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvread_ctx tpm_nvread_ctx;
struct tpm_nvread_ctx {
    TPM2_HANDLE nv_index;
    UINT32 size_to_read;
    UINT32 offset;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
        TPMI_RH_PROVISION hierarchy;
    } auth;
    char *output_file;
    char *raw_pcrs_file;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 L : 1;
        UINT8 P : 1;
        UINT8 a : 1;
    } flags;
    char *hierarchy_auth_str;
};

static tpm_nvread_ctx ctx = {
    .auth = {
        .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
        .hierarchy = TPM2_RH_OWNER
    }
};

static bool nv_read(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    TPM2B_NV_PUBLIC *nv_public;
    bool res = tpm2_util_nv_read_public(ectx, ctx.nv_index, &nv_public);
    if (!res) {
        LOG_ERR("Failed to read NVRAM public area at index 0x%X",
                ctx.nv_index);
        return false;
    }

    UINT16 data_size = nv_public->nvPublic.dataSize;

    /* if no size was specified, assume the whole object */
    if (ctx.size_to_read == 0) {
        ctx.size_to_read = data_size;
    }

    if (ctx.offset > data_size) {
        LOG_ERR(
            "Requested offset to read from is greater than size. offset=%u"
            ", size=%u", ctx.offset, data_size);
        return false;
    }

    if (ctx.offset + ctx.size_to_read > data_size) {
        LOG_WARN(
            "Requested to read more bytes than available from offset,"
            " truncating read! offset=%u, request-read-size=%u"
            " actual-data-size=%u", ctx.offset, ctx.size_to_read, data_size);
        ctx.size_to_read = data_size - ctx.offset;
        return false;
    }

    UINT32 max_data_size;
    res = tpm2_util_nv_max_buffer_size(ectx, &max_data_size);
    if (!res) {
        return false;
    }

    if (max_data_size > TPM2_MAX_NV_BUFFER_SIZE) {
        max_data_size = TPM2_MAX_NV_BUFFER_SIZE;
    }
    else if (max_data_size == 0) {
        max_data_size = NV_DEFAULT_BUFFER_SIZE;
    }

    UINT8 *data_buffer = malloc(data_size);
    if (!data_buffer) {
        LOG_ERR("oom");
        return false;
    }

    bool result = false;
    UINT16 data_offset = 0;
    ESYS_TR nv_handle;

    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, ctx.nv_index,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nv_handle);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        goto out;
    }


    // Convert TPMI_RH_PROVISION in ctx.auth.hierarchy to an ESYS_TR
    ESYS_TR hierarchy;
    if (ctx.auth.hierarchy == ctx.nv_index) {
        hierarchy = nv_handle;
    } else {
        hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(ctx.auth.hierarchy);
    }

    ESYS_TR shandle1;
    bool ok = tpm2_auth_util_get_shandle(ectx, hierarchy,
                &ctx.auth.session_data,
                ctx.auth.session, &shandle1);
    if (!ok) {
        LOG_ERR("Couldn't get session handle");
        return false;
    }

    while (ctx.size_to_read) {

        UINT16 bytes_to_read = ctx.size_to_read > max_data_size ?
                max_data_size : ctx.size_to_read;

        TPM2B_MAX_NV_BUFFER *nv_data;

        rval = Esys_NV_Read(ectx, hierarchy, nv_handle,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                    bytes_to_read, ctx.offset, &nv_data);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to read NVRAM area at index 0x%X", ctx.nv_index);
            LOG_PERR(Esys_NV_Read, rval);
            goto out;
        }

        ctx.size_to_read -= nv_data->size;
        ctx.offset += nv_data->size;

        memcpy(data_buffer + data_offset, nv_data->buffer, nv_data->size);
        data_offset += nv_data->size;
    }

    /* dump data_buffer to output file, if specified */
    if (ctx.output_file) {
        if (!files_save_bytes_to_file(ctx.output_file, data_buffer, data_offset)) {
            goto out;
        }
    /* else use stdout if quiet is not specified */
    } else if (!flags.quiet) {
        if (!files_write_bytes(stdout, data_buffer, data_offset)) {
            goto out;
        }
    }

    result = true;

out:
    free(data_buffer);
    return result;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'x':
        result = tpm2_util_string_to_uint32(value, &ctx.nv_index);
        if (!result) {
            LOG_ERR("Could not convert NV index to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.nv_index == 0) {
            LOG_ERR("NV Index cannot be 0");
            return false;
        }
        break;
    case 'a':
        result = tpm2_hierarchy_from_optarg(value, &ctx.auth.hierarchy,
                TPM2_HIERARCHY_FLAGS_O|TPM2_HIERARCHY_FLAGS_P);
        if (!result) {
            return false;
        }
        ctx.flags.a = 1;
        break;
    case 'f':
        ctx.output_file = value;
        break;
    case 'P':
        ctx.flags.P = 1;
        ctx.hierarchy_auth_str = value;
        break;
    case 's':
        result = tpm2_util_string_to_uint32(value, &ctx.size_to_read);
        if (!result) {
            LOG_ERR("Could not convert size to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'o':
        result = tpm2_util_string_to_uint32(value, &ctx.offset);
        if (!result) {
            LOG_ERR("Could not convert offset to number, got: \"%s\"",
                    value);
            return false;
        }
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

    const struct option topts[] = {
        { "index",                required_argument, NULL, 'x' },
        { "hierarchy",       required_argument, NULL, 'a' },
        { "out-file",             required_argument, NULL, 'f' },
        { "size",                 required_argument, NULL, 's' },
        { "offset",               required_argument, NULL, 'o' },
        { "auth-hierarchy", required_argument, NULL, 'P' },
        { "set-list",             required_argument, NULL, 'L' },
        { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:f:s:o:P:L:F:", ARRAY_LEN(topts),
                             topts, on_option, NULL, 0);

    return *opts != NULL;
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
            ctx.raw_pcrs_file,
            &ctx.pcr_selection);
    if (!result) {
        LOG_ERR("Could not build a pcr policy");
        return false;
    }

    return true;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    if (ctx.flags.L && ctx.auth.session) {
        LOG_ERR("Can only use either existing session or a new session,"
                " not both!");
        goto out;
    }

    if (ctx.flags.L) {
        result = start_auth_session(ectx);
        if (!result) {
            goto out;
        }
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.hierarchy_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid handle authorization, got \"%s\"",
                ctx.hierarchy_auth_str);
            return false;
        }
    }

    /* If the users doesn't specify an authorisation hierarchy use the index
     * passed to -x/--index for the authorisation index.
     */
    if (!ctx.flags.a) {
        ctx.auth.hierarchy = ctx.nv_index;
    }

    result = nv_read(ectx, flags);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    if (ctx.flags.L) {
        ESYS_TR sess = tpm2_session_get_handle(ctx.auth.session);
        TSS2_RC rval = Esys_FlushContext(ectx, sess);
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

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
