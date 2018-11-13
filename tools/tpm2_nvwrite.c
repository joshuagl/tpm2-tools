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
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <limits.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "pcr.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"
#include "tpm2_nv_util.h"
#include "tpm2_policy.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct tpm_nvwrite_ctx tpm_nvwrite_ctx;
struct tpm_nvwrite_ctx {
    TPM2_HANDLE nv_index;
    UINT16 data_size;
    UINT8 nv_buffer[TPM2_MAX_NV_BUFFER_SIZE];
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
        TPMI_RH_PROVISION hierarchy;
    } auth;
    FILE *input_file;
    UINT16 offset;
    char *raw_pcrs_file;
    tpm2_session *policy_session;
    TPML_PCR_SELECTION pcr_selection;
    struct {
        UINT8 L : 1;
        UINT8 P : 1;
        UINT8 a : 1;
    } flags;
    char *hierarchy_auth_str;
};

static tpm_nvwrite_ctx ctx = {
    .auth = {
            .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
            .hierarchy = TPM2_RH_OWNER
    }
};

static bool nv_write(ESYS_CONTEXT *ectx) {

    TPM2B_MAX_NV_BUFFER nv_write_data;
    UINT16 data_offset = 0;

    if (!ctx.data_size) {
        LOG_WARN("Data to write is of size 0");
    }

    /*
     * Ensure that writes will fit before attempting write to prevent data
     * from being partially written to the index.
     */
    TPM2B_NV_PUBLIC *nv_public;
    bool res = tpm2_util_nv_read_public(ectx, ctx.nv_index, &nv_public);
    if (!res) {
        LOG_ERR("Failed to write NVRAM public area at index 0x%X",
                ctx.nv_index);
        free(nv_public);
        return false;
    }

    if (ctx.offset + ctx.data_size > nv_public->nvPublic.dataSize) {
        LOG_ERR("The starting offset (%u) and the size (%u) are larger than the"
                " defined space: %u.",
                ctx.offset, ctx.data_size, nv_public->nvPublic.dataSize);
        free(nv_public);
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

    // Convert TPM2_HANDLE ctx.nv_index to an ESYS_TR
    ESYS_TR nv_index;
    TSS2_RC rval = Esys_TR_FromTPMPublic(ectx, ctx.nv_index,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &nv_index);
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_TR_FromTPMPublic, rval);
        return false;
    }

    // Convert TPMI_RH_PROVISION ctx.auth.hierarchy to an ESYS_TR
    ESYS_TR hierarchy;
    if (ctx.auth.hierarchy == ctx.nv_index) {
        hierarchy = nv_index;
    } else {
        hierarchy = tpm2_tpmi_hierarchy_to_esys_tr(ctx.auth.hierarchy);
    }

    ESYS_TR shandle1;
    bool ret = tpm2_auth_util_get_shandle(ectx, hierarchy,
                    &ctx.auth.session_data, ctx.auth.session, &shandle1);
    if (!ret) {
        LOG_ERR("Failed to get shandle");
        return false;
    }

    while (ctx.data_size > 0) {

        nv_write_data.size =
                ctx.data_size > max_data_size ?
                        max_data_size : ctx.data_size;

        LOG_INFO("The data(size=%d) to be written:", nv_write_data.size);

        memcpy(nv_write_data.buffer, &ctx.nv_buffer[data_offset], nv_write_data.size);

        TSS2_RC rval = Esys_NV_Write(ectx, hierarchy, nv_index,
                        shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                        &nv_write_data, ctx.offset + data_offset);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_ERR("Failed to write NV area at index 0x%X", ctx.nv_index);
            LOG_PERR(Tss2_Sys_NV_Write, rval);
            return false;
        }

        LOG_INFO("Success to write NV area at index 0x%x (%d) offset 0x%x.",
                ctx.nv_index, ctx.nv_index, data_offset);

        ctx.data_size -= nv_write_data.size;
        data_offset += nv_write_data.size;
    }

    return true;
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
    case 'P':
        ctx.flags.P = 1;
        ctx.hierarchy_auth_str = value;
        break;
    case 'o':
        if (!tpm2_util_string_to_uint16(value, &ctx.offset)) {
            LOG_ERR("Could not convert starting offset, got: \"%s\"",
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
    }

    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one input file, got: %d", argc);
        return false;
    }

    ctx.input_file = fopen(argv[0], "rb");
    if (!ctx.input_file) {
        LOG_ERR("Could not open input file \"%s\", error: %s",
                argv[0], strerror(errno));
        return false;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "index",                required_argument, NULL, 'x' },
        { "hierarchy",            required_argument, NULL, 'a' },
        { "auth-hierarchy",       required_argument, NULL, 'P' },
        { "offset",               required_argument, NULL, 'o' },
        { "set-list",             required_argument, NULL, 'L' },
        { "pcr-input-file",       required_argument, NULL, 'F' },
    };

    *opts = tpm2_options_new("x:a:P:o:L:F:", ARRAY_LEN(topts), topts,
                             on_option, on_args, 0);

    ctx.input_file = stdin;

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

    /* If the users doesn't specify an authorisation hierarchy use the index
     * passed to -x/--index for the authorisation index.
     */
    if (!ctx.flags.a) {
        ctx.auth.hierarchy = ctx.nv_index;
    }

    /* Suppress error reporting with NULL path */
    unsigned long file_size;
    result = files_get_file_size(ctx.input_file, &file_size, NULL);

    if (result && file_size > TPM2_MAX_NV_BUFFER_SIZE) {
        LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE, got %lu expected %u", file_size,
                TPM2_MAX_NV_BUFFER_SIZE);
        goto out;
    }

    if (ctx.flags.P) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.hierarchy_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid handle authorization, got \"%s\"",
                ctx.hierarchy_auth_str);
            goto out;
        }
    }

    if (result) {
        /*
         * We know the size upfront, read it. Note that the size was already
         * bounded by TPM2_MAX_NV_BUFFER_SIZE
         */
        ctx.data_size = (UINT16) file_size;
        result = files_read_bytes(ctx.input_file, ctx.nv_buffer, ctx.data_size);
        if (!result)  {
            LOG_ERR("could not read input file");
            goto out;
        }
    } else {
        /* we don't know the file size, ie it's a stream, read till end */
        size_t bytes = fread(ctx.nv_buffer, 1, TPM2_MAX_NV_BUFFER_SIZE, ctx.input_file);
        if (bytes != TPM2_MAX_NV_BUFFER_SIZE) {
            if (ferror(ctx.input_file)) {
                LOG_ERR("reading from input file failed: %s", strerror(errno));
                goto out;
            }

            if (!feof(ctx.input_file)) {
                LOG_ERR("File larger than TPM2_MAX_NV_BUFFER_SIZE: %u",
                        TPM2_MAX_NV_BUFFER_SIZE);
                goto out;
            }
        }

        ctx.data_size = (UINT16)bytes;
    }

    result = nv_write(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:

    if (ctx.flags.L) {
        ESYS_TR sess_handle = tpm2_session_get_handle(ctx.auth.session);
        TSS2_RC rval = Esys_FlushContext(ectx, sess_handle);
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
