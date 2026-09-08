
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "trousers/tss.h"
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcslog.h"


TSS_RESULT
UnloadBlob_STORED_DATA_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_STORED_DATA *data)
{
	TSS_RESULT rc;

	if (!data) {
		UINT32 size;

		if ((rc = UnloadBlob_VERSION_s(offset, blob, capacity, NULL)))
			return rc;

		if ((rc = UnloadBlob_UINT32_s(offset, &size, blob, capacity)))
			return rc;
		if (size > 4096)
			return TCSERR(TSS_E_BAD_PARAMETER);
		if (size > 0) {
			if ((rc = UnloadBlob_s(offset, size, blob, capacity, NULL)))
				return rc;
		}

		if ((rc = UnloadBlob_UINT32_s(offset, &size, blob, capacity)))
			return rc;
		if (size > 4096)
			return TCSERR(TSS_E_BAD_PARAMETER);
		if (size > 0) {
			if ((rc = UnloadBlob_s(offset, size, blob, capacity, NULL)))
				return rc;
		}

		return TSS_SUCCESS;
	}

	data->sealInfo = NULL;
	data->sealInfoSize = 0;
	data->encData = NULL;
	data->encDataSize = 0;

	if ((rc = UnloadBlob_VERSION_s(offset, blob, capacity, (TPM_VERSION *)&data->ver)))
		return rc;

	if ((rc = UnloadBlob_UINT32_s(offset, &data->sealInfoSize, blob, capacity)))
		return rc;

	if (data->sealInfoSize > 4096) {
		data->sealInfoSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}
	if (*offset > capacity || (UINT64)data->sealInfoSize > capacity - *offset) {
		data->sealInfoSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}

	if (data->sealInfoSize > 0) {
		data->sealInfo = (BYTE *)calloc(1, data->sealInfoSize);
		if (data->sealInfo == NULL) {
			LogError("malloc of %u bytes failed.", data->sealInfoSize);
			data->sealInfoSize = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if ((rc = UnloadBlob_s(offset, data->sealInfoSize, blob, capacity, data->sealInfo))) {
			free(data->sealInfo);
			data->sealInfo = NULL;
			data->sealInfoSize = 0;
			return rc;
		}
	} else {
		data->sealInfo = NULL;
	}

	if ((rc = UnloadBlob_UINT32_s(offset, &data->encDataSize, blob, capacity))) {
		free(data->sealInfo);
		data->sealInfo = NULL;
		data->sealInfoSize = 0;
		return rc;
	}

	if (data->encDataSize > 4096) {
		free(data->sealInfo);
		data->sealInfo = NULL;
		data->sealInfoSize = 0;
		data->encDataSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}
	if (*offset > capacity || (UINT64)data->encDataSize > capacity - *offset) {
		free(data->sealInfo);
		data->sealInfo = NULL;
		data->sealInfoSize = 0;
		data->encDataSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}

	if (data->encDataSize > 0) {
		data->encData = (BYTE *)calloc(1, data->encDataSize);
		if (data->encData == NULL) {
			LogError("malloc of %u bytes failed.", data->encDataSize);
			data->encDataSize = 0;
			free(data->sealInfo);
			data->sealInfo = NULL;
			data->sealInfoSize = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}
		if ((rc = UnloadBlob_s(offset, data->encDataSize, blob, capacity, data->encData))) {
			free(data->encData);
			data->encData = NULL;
			data->encDataSize = 0;
			free(data->sealInfo);
			data->sealInfo = NULL;
			data->sealInfoSize = 0;
			return rc;
		}
	} else {
		data->encData = NULL;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_STORED_DATA(UINT64 *offset, BYTE *blob, TCPA_STORED_DATA *data)
{
	return UnloadBlob_STORED_DATA_s(offset, blob, UINT64_MAX, data);
}
