// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _TCS_DA_RESET_H_
#define _TCS_DA_RESET_H_

#include "tss/tss_typedef.h"

void recordFailedCommandHistory(UINT32 ordinal, UINT32 result);

void handleAuthFailures();

void clearCommandHistory();

#endif /*_TCS_DA_RESET_H_ */
