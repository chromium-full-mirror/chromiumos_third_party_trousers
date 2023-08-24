# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

JOB="tcsd-pre-start"

# Check the vboot nvram bit which indicates that the TPM was reset in the
# middle of a command within 30s of boot in the previous boot session,
# and report if bit is ON.
if crossystem "tpm_attack?1"; then
  crossystem "tpm_attack=0" || \
      logger -t "${JOB}" "crossystem: status $?"
fi

if [ -e /sys/class/misc/tpm0 ]; then
  TPMDIR=/sys/class/misc/tpm0/device
else
  TPMDIR=/sys/class/tpm/tpm0/device
fi
if [ -e "$TPMDIR/owned" ]; then
  owned=$(cat "$TPMDIR/owned" || echo "")
  if [ "$owned" -eq "0" ]; then
    # Clean up any existing tcsd state.
    rm -rf /var/lib/tpm/*
  elif [ "$owned" -eq "1" ]; then
    # Already owned.
    # Check if trousers' system.data is size zero.  If so, then the TPM has
    # been owned already and we need to copy over an empty system.data to be
    # able to use it in trousers.
    if [ ! -f /var/lib/tpm/system.data ] ||
       [ ! -s /var/lib/tpm/system.data ]; then
      if [ ! -e /var/lib/tpm ]; then
        mkdir -m 0700 -p /var/lib/tpm
      fi
      umask 0177
      cp --no-preserve=mode /etc/trousers/system.data.auth \
        /var/lib/tpm/system.data
    fi
  fi
fi
