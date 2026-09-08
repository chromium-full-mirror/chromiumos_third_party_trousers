
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2006
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcsps.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcslog.h"
#include "req_mgr.h"
#include "tcsd_wrap.h"
#include "tcsd.h"

TSS_RESULT
UnloadBlob_MIGRATIONKEYAUTH_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_MIGRATIONKEYAUTH *mkAuth)
{
	TSS_RESULT result;

	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if (!mkAuth) {
		if ((result = UnloadBlob_PUBKEY_s(offset, blob, capacity, NULL)))
			return result;

		if ((result = UnloadBlob_UINT16_s(offset, NULL, blob, capacity)))
			return result;
		return UnloadBlob_s(offset, 20, blob, capacity, NULL);
	}

	if ((result = UnloadBlob_PUBKEY_s(offset, blob, capacity, &mkAuth->migrationKey)))
		return result;

	if ((result = UnloadBlob_UINT16_s(offset, &mkAuth->migrationScheme, blob, capacity)))
		goto err;
	if ((result = UnloadBlob_s(offset, 20, blob, capacity, mkAuth->digest.digest)))
		goto err;

	return TSS_SUCCESS;

err:
	free(mkAuth->migrationKey.algorithmParms.parms);
	mkAuth->migrationKey.algorithmParms.parms = NULL;
	mkAuth->migrationKey.algorithmParms.parmSize = 0;
	free(mkAuth->migrationKey.pubKey.key);
	mkAuth->migrationKey.pubKey.key = NULL;
	mkAuth->migrationKey.pubKey.keyLength = 0;
	return result;
}

TSS_RESULT
UnloadBlob_MIGRATIONKEYAUTH(UINT64 *offset, BYTE *blob, TCPA_MIGRATIONKEYAUTH *mkAuth)
{
	return UnloadBlob_MIGRATIONKEYAUTH_s(offset, blob, UINT64_MAX, mkAuth);
}
