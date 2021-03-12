// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tcs_da_reset.h"

#include <tss/tpm.h>

#include "libhwsec-foundation/tpm_error/handle_auth_failure.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"
#include "tcslog.h"

enum { MAX_HISTORY_SIZE = 32 };

static __thread struct TpmErrorData command_history_entries[MAX_HISTORY_SIZE] =
    {};

static __thread int command_history_size = 0;

void recordFailedCommandHistory(UINT32 ordinal, UINT32 response) {
	if (response == TPM_SUCCESS) {
		return;
	}
	if (command_history_size == MAX_HISTORY_SIZE) {
		LogWarn("History size limit reached; dropping (ordinal: %d, "
			"response: %d)",
			ordinal, response);
		return;
	}
	command_history_entries[command_history_size].command = ordinal;
	command_history_entries[command_history_size].response = response;
	++command_history_size;
}

void handleAuthFailures() {
	int i;
	for (i = 0; i < command_history_size; ++i) {
		HandleAuthFailure(&command_history_entries[i]);
	}
}

void clearCommandHistory() { command_history_size = 0; }
