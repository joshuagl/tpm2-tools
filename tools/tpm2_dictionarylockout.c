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

#include "log.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"
#include "tpm2_session.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

typedef struct dictionarylockout_ctx dictionarylockout_ctx;
struct dictionarylockout_ctx {
    UINT32 max_tries;
    UINT32 recovery_time;
    UINT32 lockout_recovery_time;
    bool clear_lockout;
    bool setup_parameters;
    struct {
        TPMS_AUTH_COMMAND session_data;
        tpm2_session *session;
    } auth;
    struct {
        UINT8 p : 1;
        UINT8 unused : 7;
    } flags;
    char *lockout_auth_str;
};

static dictionarylockout_ctx ctx = {
    .auth = { .session_data = TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW) },
    .flags = { 0 },
};

bool dictionary_lockout_reset_and_parameter_setup(ESYS_CONTEXT *ectx) {

    TPM2_RC rval;
    ESYS_TR shandle1;
    bool ok = tpm2_auth_util_get_shandle(ectx, ESYS_TR_RH_LOCKOUT,
                &ctx.auth.session_data, ctx.auth.session, &shandle1);
    if (!ok) {
        LOG_ERR("Couldn't get shandle for lockout hierarchy");
        return false;
    }

    /*
     * If setup params and clear lockout are both required, clear lockout should
     * precede parameters setup.
     */
    if (ctx.clear_lockout) {

        LOG_INFO("Resetting dictionary lockout state.");
        rval = Esys_DictionaryAttackLockReset(ectx, ESYS_TR_RH_LOCKOUT,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackLockReset, rval);
            return false;
        }
    }

    if (ctx.setup_parameters) {
        LOG_INFO("Setting up Dictionary Lockout parameters.");
        rval = Esys_DictionaryAttackParameters(ectx, ESYS_TR_RH_LOCKOUT,
                    shandle1, ESYS_TR_NONE, ESYS_TR_NONE,
                    ctx.max_tries, ctx.recovery_time,
                    ctx.lockout_recovery_time);
        if (rval != TPM2_RC_SUCCESS) {
            LOG_PERR(Esys_DictionaryAttackParameters, rval);
            return false;
        }
    }

    return true;
}

static bool on_option(char key, char *value) {

    bool result;

    switch (key) {
    case 'c':
        ctx.clear_lockout = true;
        break;
    case 's':
        ctx.setup_parameters = true;
        break;
    case 'p':
        ctx.flags.p = 1;
        ctx.lockout_auth_str = value;
        break;
    case 'n':
        result = tpm2_util_string_to_uint32(value, &ctx.max_tries);
        if (!result) {
            LOG_ERR("Could not convert max_tries to number, got: \"%s\"",
                    value);
            return false;
        }

        if (ctx.max_tries == 0) {
            return false;
        }
        break;
    case 't':
        result = tpm2_util_string_to_uint32(value, &ctx.recovery_time);
        if (!result) {
            LOG_ERR("Could not convert recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    case 'l':
        result = tpm2_util_string_to_uint32(value, &ctx.lockout_recovery_time);
        if (!result) {
            LOG_ERR("Could not convert lockout_recovery_time to number, got: \"%s\"",
                    value);
            return false;
        }
        break;
    }

    return true;
}

bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
        { "max-tries",             required_argument, NULL, 'n' },
        { "recovery-time",         required_argument, NULL, 't' },
        { "lockout-recovery-time", required_argument, NULL, 'l' },
        { "auth-lockout",          required_argument, NULL, 'p' },
        { "clear-lockout",         no_argument,       NULL, 'c' },
        { "setup-parameters",      no_argument,       NULL, 's' },
    };

    *opts = tpm2_options_new("n:t:l:p:cs", ARRAY_LEN(topts), topts, on_option,
                             NULL, 0);

    return *opts != NULL;
}

int tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    int rc = 1;
    bool result;

    if (!ctx.clear_lockout && !ctx.setup_parameters) {
        LOG_ERR( "Invalid operational input: Neither Setup nor Clear lockout requested.");
        return -1;
    }

    if (ctx.flags.p) {
        result = tpm2_auth_util_from_optarg(ectx, ctx.lockout_auth_str,
                &ctx.auth.session_data, &ctx.auth.session);
        if (!result) {
            LOG_ERR("Invalid lockout authorization, got\"%s\"",
                ctx.lockout_auth_str);
            return 1;
        }
    }

    result = dictionary_lockout_reset_and_parameter_setup(ectx);
    if (!result) {
        goto out;
    }

    rc = 0;

out:
    result = tpm2_session_save(ectx, ctx.auth.session, NULL);
    if (!result) {
        rc = 1;
    }

    return rc;
}

void tpm2_onexit(void) {

    tpm2_session_free(&ctx.auth.session);
}
