/*
 * Copyright (c) 2017, Emmanuel Deloget <logout@free.fr>
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct clearlock_ctx clearlock_ctx;
struct clearlock_ctx {
    TPMI_YES_NO disable;
    TPMI_RH_CLEAR rh;
    tpm2_auth auth;
};

static clearlock_ctx ctx = {
    .rh = TPM2_RH_LOCKOUT,
    .disable = 0,
    .auth = TPM2_AUTH_INIT(AUTH_MAX, tpm2_auth_all)
};

static bool clearlock(TSS2_SYS_CONTEXT *sapi_context) {

    LOG_INFO ("Sending TPM2_ClearControl(%s) command on %s",
            ctx.disable ? "SET" : "CLEAR",
            ctx.rh == TPM2_RH_PLATFORM ? "TPM2_RH_PLATFORM" : "TPM2_RH_LOCKOUT");

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

    bool result = tpm2_auth_update(sapi_context, &ctx.auth, NULL);
    if (!result) {
        LOG_ERR("Error updating authentications");
        return false;
    }

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ClearControl (sapi_context,
            ctx.rh, &ctx.auth.auth_list, ctx.disable, &sessionsDataOut));
    if (rval != TPM2_RC_SUCCESS && rval != TPM2_RC_INITIALIZE) {
        LOG_PERR(Tss2_Sys_ClearControl, rval);
        return false;
    }

    LOG_INFO ("Success. TSS2_RC: 0x%x", rval);
    return true;
}

static bool hmac_init_cb(tpm2_session_data *d) {

    TPM2_HANDLE handles[1] = {
        ctx.rh
    };

    tpm2_session_set_auth_handles(d, handles, ARRAY_LEN(handles));

    return true;
}

static bool hmac_update_cb(TSS2_SYS_CONTEXT *sapi_context, void *userdata) {

    UNUSED(userdata);

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ClearControl_Prepare(sapi_context, ctx.rh, ctx.disable));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_ClearControl_Prepare, rval);
        return false;
    }

    return true;
} 

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {
    case 'c':
        ctx.disable = 1;
        break;
    case 'p':
        ctx.rh = TPM2_RH_PLATFORM;
        break;
    case 'L':
        result = tpm2_auth_util_set_opt(value, &ctx.auth);
        if (!result) {
            LOG_ERR("Invalid authorization, got \"%s\"", value);
            return false;
        }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "clear",          no_argument,       NULL, 'c' },
        { "auth-lockout",   required_argument, NULL, 'L' },
        { "platform",       no_argument,       NULL, 'p' },
    };

    *opts = tpm2_options_new("cL:p", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    UNUSED(flags);
    int rc = 1;

    tpm2_auth_cb auth_cb = {
        .hmac = {
            .init = hmac_init_cb,
            .update = hmac_update_cb
        }
    };

    bool result = tpm2_auth_util_from_options(sapi_context,
        &ctx.auth, &auth_cb);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms");
        goto out;
    }

    result = clearlock(sapi_context);
    if (!result) {
        goto out;
    }
    rc = 0;

out:
    result = tpm2_auth_util_free(sapi_context, &ctx.auth);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
    }

    return result ? rc : 1;
}
