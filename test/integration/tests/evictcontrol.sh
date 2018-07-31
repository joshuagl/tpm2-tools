#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2016-2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

source helpers.sh

cleanup() {
  rm -f primary.ctx decrypt.ctx key.pub key.priv key.name decrypt.out \
        encrypt.out secret.dat key.dat evict.log

  if [ "$1" != "no-shut-down" ]; then
      shut_down
  fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_clear -Q

tpm2_createprimary -Q -a e -g sha256 -G rsa -o primary.ctx

tpm2_create -Q -g sha256 -G aes -u key.pub -r key.priv  -C primary.ctx

tpm2_load -Q -C primary.ctx  -u key.pub  -r key.priv -n key.name -o key.dat

# Load the context into a specific handle, delete it
tpm2_evictcontrol -Q -c key.dat -p 0x81010003

tpm2_evictcontrol -Q -c 0x81010003 -p 0x81010003

# Load the context into a specific handle, delete it without an explicit -p
tpm2_evictcontrol -Q -a o -c key.dat -p 0x81010003

tpm2_evictcontrol -Q -a o -c 0x81010003

# Load the context into an available handle, delete it
tpm2_evictcontrol -a o -c key.dat > evict.log
phandle=`grep "persistentHandle: " evict.log | awk '{print $2}'`
tpm2_evictcontrol -Q -a o -c $phandle

yaml_verify evict.log

# Load the context into a specific handle, delete it -- using auth
tpm2_changeauth -Q -o "foo"
tpm2_evictcontrol -Q -a o -c key.dat -p 0x81010003 -P "foo"
tpm2_evictcontrol -Q -a o -c 0x81010003 -p 0x81010003 -P "foo"

exit 0
