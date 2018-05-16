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
#include <string.h>

#include <tss2/tss2_sys.h>

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct hmac_update_cb_data hmac_update_cb_data;
struct hmac_update_cb_data {
    TPM2B_AUTH *new;
    TPMI_RH_HIERARCHY_AUTH handle;
};

typedef struct auth auth;
struct auth {
    struct {
        tpm2_auth auth;
    } old;
    struct {
        tpm2_auth auth;
    } new;
};

typedef struct changeauth_ctx changeauth_ctx;
struct changeauth_ctx {
    struct {
        auth owner;
        auth endorse;
        auth lockout;
    } auths;
    struct {
        UINT8 o : 1;
        UINT8 e : 1;
        UINT8 l : 1;
        UINT8 O : 1;
        UINT8 E : 1;
        UINT8 L : 1;
        UINT8 unused : 2;
    } flags;
};

static changeauth_ctx ctx = {
    .auths = {
        .owner = {
            .old = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_all) },
            .new = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_password) },
        },
        .endorse = {
                .old = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_all) },
                .new = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_password) },
        },
        .lockout = {
                .old = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_all) },
                .new = { .auth = TPM2_AUTH_INIT(1, tpm2_auth_password) },
        },
    },
    .flags = { 0 },
};

static bool change_auth(TSS2_SYS_CONTEXT *sapi_context,
        struct auth *pwd, const char *desc,
        TPMI_RH_HIERARCHY_AUTH auth_handle) {

    TPM2B_AUTH *new = &pwd->new.auth.auth_list.auths[0].hmac;
    TSS2L_SYS_AUTH_COMMAND *sdata = &pwd->old.auth.auth_list;

    hmac_update_cb_data udata = {
            .handle = auth_handle,
            .new = new
    };

    bool result = tpm2_auth_update(sapi_context, &pwd->old.auth, &udata);
    if (!result) {
        LOG_ERR("Error updating authentications");
        return false;
    }

    UINT32 rval = TSS2_RETRY_EXP(Tss2_Sys_HierarchyChangeAuth(sapi_context,
            auth_handle, sdata, new, NULL));
    if (rval != TPM2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_HierarchyChangeAuth, rval);
        return false;
    }

    LOG_INFO("Successfully changed hierarchy for %s", desc);

    return true;
}

static bool change_hierarchy_auth(TSS2_SYS_CONTEXT *sapi_context) {

    // change owner, endorsement and lockout auth.
    bool result = true;
    if (ctx.flags.o || ctx.flags.O) {
        result &= change_auth(sapi_context, &ctx.auths.owner,
                "Owner", TPM2_RH_OWNER);
    }

    if (ctx.flags.e || ctx.flags.E) {
        result &= change_auth(sapi_context, &ctx.auths.endorse,
                "Endorsement", TPM2_RH_ENDORSEMENT);
    }

    if (ctx.flags.l || ctx.flags.L) {
        result &= change_auth(sapi_context, &ctx.auths.lockout,
                "Lockout", TPM2_RH_LOCKOUT);
    }

    return result;
}

static bool on_option(char key, char *value) {

    bool result;
    switch (key) {

    case 'o':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.owner.new.auth);
        if (!result) {
            return false;
        }
        ctx.flags.o = 1;
        break;
    case 'e':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.endorse.new.auth);
        if (!result) {
            return false;
        }
        ctx.flags.e = 1;
        break;
    case 'l':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.lockout.new.auth);
        if (!result) {
            return false;
        }
        ctx.flags.l = 1;
        break;
    case 'O':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.owner.old.auth);
        if (!result) {
            return false;
        }
        ctx.flags.O = 1;
        break;
    case 'E':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.endorse.old.auth);
        if (!result) {
            return false;
        }
        ctx.flags.E = 1;
        break;
    case 'L':
        result = tpm2_auth_util_set_opt(value, &ctx.auths.lockout.old.auth);
        if (!result) {
            return false;
        }
        ctx.flags.L = 1;
        break;
        /*no default */
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    struct option topts[] = {
        { "owner-passwd",       required_argument, NULL, 'o' },
        { "endorse-passwd",     required_argument, NULL, 'e' },
        { "lockout-passwd",     required_argument, NULL, 'l' },
        { "old-auth-owner",     required_argument, NULL, 'O' },
        { "old-auth-endorse",   required_argument, NULL, 'E' },
        { "old-auth-lockout",   required_argument, NULL, 'L' },
    };

    *opts = tpm2_options_new("o:e:l:O:E:L:", ARRAY_LEN(topts), topts,
                             on_option, NULL, 0);

    return *opts != NULL;
}

static bool hmac_init_cb_owner(tpm2_session_data *d) {

    TPM2_HANDLE handles[1] = {
            TPM2_RH_OWNER,
    };

    tpm2_session_set_auth_handles(d, handles, ARRAY_LEN(handles));

    return true;
}

static bool hmac_init_cb_endorse(tpm2_session_data *d) {

    TPM2_HANDLE handles[1] = {
            TPM2_RH_ENDORSEMENT,
    };

    tpm2_session_set_auth_handles(d, handles, ARRAY_LEN(handles));

    return true;
}

static bool hmac_init_cb_lockout(tpm2_session_data *d) {

    TPM2_HANDLE handles[1] = {
            TPM2_RH_LOCKOUT,
    };

    tpm2_session_set_auth_handles(d, handles, ARRAY_LEN(handles));

    return true;
}

static bool hmac_update_cb(TSS2_SYS_CONTEXT *sapi_context, void *userdata) {

    hmac_update_cb_data *udata = (hmac_update_cb_data *)userdata;

    TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_HierarchyChangeAuth_Prepare(sapi_context,
                                udata->handle, udata->new));
    if (rval != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_Sys_NV_Write_Prepare, rval);
        return false;
    }

    return true;
}

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags) {

    int rc = 1;
    UNUSED(flags);
    bool result;

    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.owner.new.auth, NULL);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for owner");
        goto out;
    }

    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.endorse.new.auth, NULL);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for new endorse");
        goto out;
    }

    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.lockout.new.auth, NULL);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for new lockout");
        goto out;
    }

    tpm2_auth_cb auth_cb_owner = {
        .hmac = {
            .init = hmac_init_cb_owner,
            .update = hmac_update_cb
        }
    };

    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.owner.old.auth, &auth_cb_owner);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for old owner");
        goto out;
    }

    tpm2_auth_cb auth_cb_endorse = {
        .hmac = {
            .init = hmac_init_cb_endorse,
            .update = hmac_update_cb
        }
    };
    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.endorse.old.auth, &auth_cb_endorse);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for old endorse");
        goto out;
    }

    tpm2_auth_cb auth_cb_lockout = {
        .hmac = {
            .init = hmac_init_cb_lockout,
            .update = hmac_update_cb
        }
    };
    result = tpm2_auth_util_from_options(sapi_context,
            &ctx.auths.lockout.old.auth, &auth_cb_lockout);
    if (!result) {
        LOG_ERR("Error handling auth mechanisms for old lockout");
        goto out;
    }

    result = change_hierarchy_auth(sapi_context);
    if (!result) {
        goto out;
    }

    rc = 0;
out:

    result = tpm2_auth_util_free(sapi_context, &ctx.auths.endorse.old.auth);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
        rc = 1;
    }

    result = tpm2_auth_util_free(sapi_context, &ctx.auths.owner.old.auth);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
        rc = 1;
    }

    result = tpm2_auth_util_free(sapi_context, &ctx.auths.lockout.old.auth);
    if (!result) {
        LOG_ERR("Error finalizing auth data");
        rc = 1;
    }

    /* true is success, coerce to 0 for program success */
    return rc;
}
