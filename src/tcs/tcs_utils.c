/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2007
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
#include "trousers_types.h"
#include "tcs_tsp.h"
#include "tcs_utils.h"
#include "tcs_int_literals.h"
#include "capabilities.h"
#include "tcsps.h"
#include "tcslog.h"


TCS_CONTEXT_HANDLE InternalContext = 0x30000000;
TSS_UUID SRK_UUID = TSS_UUID_SRK;


void
LogData(char *string, UINT32 data)
{
#if 0
	/* commenting out temporarily, logs getting too chatty */
	LogDebug("%s %08x", string, data);
#endif
}

void
LogResult(char *string, TCPA_RESULT result)
{
#if 0
	/* commenting out temporarily, logs getting too chatty */
	LogDebug("Leaving %s with result 0x%08x", string, result);
#endif
}

UINT16
Decode_UINT16(BYTE * in)
{
	UINT16 temp = 0;
	temp = (in[1] & 0xFF);
	temp |= (in[0] << 8);
	return temp;
}

void
UINT64ToArray(UINT64 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 56) & 0xFF);
	out[1] = (BYTE) ((i >> 48) & 0xFF);
	out[2] = (BYTE) ((i >> 40) & 0xFF);
	out[3] = (BYTE) ((i >> 32) & 0xFF);
	out[4] = (BYTE) ((i >> 24) & 0xFF);
	out[5] = (BYTE) ((i >> 16) & 0xFF);
	out[6] = (BYTE) ((i >> 8) & 0xFF);
	out[7] = (BYTE) (i & 0xFF);
}

void
UINT32ToArray(UINT32 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 24) & 0xFF);
	out[1] = (BYTE) ((i >> 16) & 0xFF);
	out[2] = (BYTE) ((i >> 8) & 0xFF);
	out[3] = (BYTE) (i & 0xFF);
}

void
UINT16ToArray(UINT16 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 8) & 0xFF);
	out[1] = (BYTE) (i & 0xFF);
}

UINT32
Decode_UINT32(BYTE * y)
{
	UINT32 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));

	return x;
}

UINT64
Decode_UINT64(BYTE *y)
{
	UINT64 x = 0;

	x = y[0];
	x = ((x << 8) | (y[1] & 0xFF));
	x = ((x << 8) | (y[2] & 0xFF));
	x = ((x << 8) | (y[3] & 0xFF));
	x = ((x << 8) | (y[4] & 0xFF));
	x = ((x << 8) | (y[5] & 0xFF));
	x = ((x << 8) | (y[6] & 0xFF));
	x = ((x << 8) | (y[7] & 0xFF));

	return x;
}

void
LoadBlob_UINT64(UINT64 *offset, UINT64 in, BYTE * blob)
{
	if (blob)
		UINT64ToArray(in, &blob[*offset]);
	*offset += sizeof(UINT64);
}

void
LoadBlob_UINT32(UINT64 *offset, UINT32 in, BYTE * blob)
{
	if (blob)
		UINT32ToArray(in, &blob[*offset]);
	*offset += sizeof(UINT32);
}

void
LoadBlob_UINT16(UINT64 *offset, UINT16 in, BYTE * blob)
{
	if (blob)
		UINT16ToArray(in, &blob[*offset]);
	*offset += sizeof(UINT16);
}

void
UnloadBlob_UINT64(UINT64 *offset, UINT64 * out, BYTE * blob)
{
	if (out)
		*out = Decode_UINT64(&blob[*offset]);
	*offset += sizeof(UINT64);
}

TSS_RESULT
UnloadBlob_UINT64_s(UINT64 *offset, UINT64 * out, BYTE * blob, UINT64 capacity)
{
	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (*offset > capacity || sizeof(UINT64) > capacity - *offset)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (out)
		*out = Decode_UINT64(&blob[*offset]);
	*offset += sizeof(UINT64);
	return TSS_SUCCESS;
}

void
UnloadBlob_UINT32(UINT64 *offset, UINT32 * out, BYTE * blob)
{
	if (out)
		*out = Decode_UINT32(&blob[*offset]);
	*offset += sizeof(UINT32);
}

TSS_RESULT
UnloadBlob_UINT32_s(UINT64 *offset, UINT32 * out, BYTE * blob, UINT64 capacity)
{
	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (*offset > capacity || sizeof(UINT32) > capacity - *offset)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (out)
		*out = Decode_UINT32(&blob[*offset]);
	*offset += sizeof(UINT32);
	return TSS_SUCCESS;
}

void
UnloadBlob_UINT16(UINT64 *offset, UINT16 * out, BYTE * blob)
{
	if (out)
		*out = Decode_UINT16(&blob[*offset]);
	*offset += sizeof(UINT16);
}

TSS_RESULT
UnloadBlob_UINT16_s(UINT64 *offset, UINT16 * out, BYTE * blob, UINT64 capacity)
{
	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (*offset > capacity || sizeof(UINT16) > capacity - *offset)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (out)
		*out = Decode_UINT16(&blob[*offset]);
	*offset += sizeof(UINT16);
	return TSS_SUCCESS;
}

void
LoadBlob_BYTE(UINT64 *offset, BYTE data, BYTE * blob)
{
	if (blob)
		blob[*offset] = data;
	(*offset)++;
}

void
UnloadBlob_BYTE(UINT64 *offset, BYTE * dataOut, BYTE * blob)
{
	if (dataOut)
		*dataOut = blob[*offset];
	(*offset)++;
}

TSS_RESULT
UnloadBlob_BYTE_s(UINT64 *offset, BYTE * dataOut, BYTE * blob, UINT64 capacity)
{
	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (*offset >= capacity)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (dataOut)
		*dataOut = blob[*offset];
	(*offset)++;
	return TSS_SUCCESS;
}

void
LoadBlob_BOOL(UINT64 *offset, TSS_BOOL data, BYTE * blob)
{
	if (blob)
		blob[*offset] = data;
	(*offset)++;
}

void
UnloadBlob_BOOL(UINT64 *offset, TSS_BOOL *dataOut, BYTE * blob)
{
	if (dataOut)
		*dataOut = blob[*offset];
	(*offset)++;
}

TSS_RESULT
UnloadBlob_BOOL_s(UINT64 *offset, TSS_BOOL *dataOut, BYTE * blob, UINT64 capacity)
{
	return UnloadBlob_BYTE_s(offset, (BYTE *)dataOut, blob, capacity);
}

void
LoadBlob(UINT64 *offset, UINT32 size, BYTE *container, BYTE *object)
{
	if (container)
		memcpy(&container[*offset], object, size);
	(*offset) += (UINT64) size;
}

void
UnloadBlob(UINT64 *offset, UINT32 size, BYTE *container, BYTE *object)
{
	if (object)
		memcpy(object, &container[*offset], size);
	(*offset) += (UINT64) size;
}

TSS_RESULT
UnloadBlob_s(UINT64 *offset, UINT32 size, BYTE *container, UINT64 capacity, BYTE *object)
{
	if (!offset || !container)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (size == 0)
		return TSS_SUCCESS;
	if (*offset > capacity || (UINT64)size > capacity - *offset)
		return TCSERR(TSS_E_BAD_PARAMETER);
	if (object)
		memcpy(object, &container[*offset], size);
	(*offset) += (UINT64)size;
	return TSS_SUCCESS;
}

void
LoadBlob_Header(UINT16 tag, UINT32 paramSize, UINT32 ordinal, BYTE * blob)
{
	if (blob) {
		UINT16ToArray(tag, &blob[0]);
		LogData("Header Tag:", tag);
		UINT32ToArray(paramSize, &blob[2]);
		LogData("Header ParamSize:", paramSize);
		UINT32ToArray(ordinal, &blob[6]);
		LogData("Header Ordinal:", ordinal);
	}
#if 0
	LogInfo("Blob's TPM Ordinal: 0x%x", ordinal);
#endif
}

#ifdef TSS_DEBUG
TSS_RESULT
LogUnloadBlob_Header(BYTE * blob, UINT32 * size, char *file, int line)
{
	TSS_RESULT result;

	UINT16 temp = Decode_UINT16(blob);
	LogData("UnloadBlob_Tag:", (temp));
	*size = Decode_UINT32(&blob[2]);
	LogData("UnloadBlob_Header, size:", *size);
	LogData("UnloadBlob_Header, returnCode:", Decode_UINT32(&blob[6]));

	if ((result = Decode_UINT32(&blob[6]))) {
		LogTPMERR(result, file, line);
	}

	return result;
}
#else
TSS_RESULT
UnloadBlob_Header(BYTE * blob, UINT32 * size)
{
	UINT16 temp = Decode_UINT16(blob);
	LogData("UnloadBlob_Tag:", (temp));
	*size = Decode_UINT32(&blob[2]);
	LogData("UnloadBlob_Header, size:", *size);
	LogData("UnloadBlob_Header, returnCode:", Decode_UINT32(&blob[6]));
	return Decode_UINT32(&blob[6]);
}
#endif

void
LoadBlob_Auth(UINT64 *offset, BYTE * blob, TPM_AUTH * auth)
{
	LoadBlob_UINT32(offset, auth->AuthHandle, blob);
	LoadBlob(offset, TCPA_NONCE_SIZE, blob, auth->NonceOdd.nonce);
	LoadBlob_BOOL(offset, auth->fContinueAuthSession, blob);
	LoadBlob(offset, TCPA_AUTHDATA_SIZE, blob, (BYTE *)&auth->HMAC);
}

void
UnloadBlob_Auth(UINT64 *offset, BYTE * blob, TPM_AUTH * auth)
{
	if (!auth) {
		UnloadBlob(offset, TCPA_NONCE_SIZE, blob, NULL);
		UnloadBlob_BOOL(offset, NULL, blob);
		UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, NULL);

		return;
	}

	UnloadBlob(offset, TCPA_NONCE_SIZE, blob, auth->NonceEven.nonce);
	UnloadBlob_BOOL(offset, &auth->fContinueAuthSession, blob);
	UnloadBlob(offset, TCPA_DIGEST_SIZE, blob, (BYTE *)&auth->HMAC);
}

void
UnloadBlob_VERSION(UINT64 *offset, BYTE *blob, TPM_VERSION *out)
{
	(void)UnloadBlob_VERSION_s(offset, blob, UINT64_MAX, out);
}

TSS_RESULT
UnloadBlob_VERSION_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TPM_VERSION *out)
{
	return UnloadBlob_TCPA_VERSION_s(offset, blob, capacity, (TCPA_VERSION *)out);
}

void
LoadBlob_VERSION(UINT64 *offset, BYTE *blob, TPM_VERSION *ver)
{
	LoadBlob_BYTE(offset, ver->major, blob);
	LoadBlob_BYTE(offset, ver->minor, blob);
	LoadBlob_BYTE(offset, ver->revMajor, blob);
	LoadBlob_BYTE(offset, ver->revMinor, blob);
}

void
UnloadBlob_TCPA_VERSION(UINT64 *offset, BYTE *blob, TCPA_VERSION *out)
{
	(void)UnloadBlob_TCPA_VERSION_s(offset, blob, UINT64_MAX, out);
}

TSS_RESULT
UnloadBlob_TCPA_VERSION_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_VERSION *out)
{
	TSS_RESULT rc;

	if (!offset || !blob)
		return TCSERR(TSS_E_BAD_PARAMETER);

	if (!out) {
		if (*offset > capacity || (sizeof(BYTE) * 4) > capacity - *offset)
			return TCSERR(TSS_E_BAD_PARAMETER);
		*offset += (sizeof(BYTE) * 4);
		return TSS_SUCCESS;
	}

	if ((rc = UnloadBlob_BYTE_s(offset, &out->major, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_BYTE_s(offset, &out->minor, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_BYTE_s(offset, &out->revMajor, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_BYTE_s(offset, &out->revMinor, blob, capacity)))
		return rc;

	return TSS_SUCCESS;
}

void
LoadBlob_TCPA_VERSION(UINT64 *offset, BYTE *blob, TCPA_VERSION *ver)
{
	LoadBlob_BYTE(offset, ver->major, blob);
	LoadBlob_BYTE(offset, ver->minor, blob);
	LoadBlob_BYTE(offset, ver->revMajor, blob);
	LoadBlob_BYTE(offset, ver->revMinor, blob);
}

TSS_RESULT
UnloadBlob_KEY_PARMS_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_KEY_PARMS *keyParms)
{
	TSS_RESULT rc;

	if (!keyParms) {
		UINT32 parmSize;

		if ((rc = UnloadBlob_UINT32_s(offset, NULL, blob, capacity)))
			return rc;
		if ((rc = UnloadBlob_UINT16_s(offset, NULL, blob, capacity)))
			return rc;
		if ((rc = UnloadBlob_UINT16_s(offset, NULL, blob, capacity)))
			return rc;
		if ((rc = UnloadBlob_UINT32_s(offset, &parmSize, blob, capacity)))
			return rc;

		if (parmSize > 4096)
			return TCSERR(TSS_E_BAD_PARAMETER);
		if (parmSize > 0) {
			if ((rc = UnloadBlob_s(offset, parmSize, blob, capacity, NULL)))
				return rc;
		}

		return TSS_SUCCESS;
	}

	keyParms->parms = NULL;
	keyParms->parmSize = 0;

	if ((rc = UnloadBlob_UINT32_s(offset, &keyParms->algorithmID, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_UINT16_s(offset, &keyParms->encScheme, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_UINT16_s(offset, &keyParms->sigScheme, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_UINT32_s(offset, &keyParms->parmSize, blob, capacity)))
		return rc;

	if (keyParms->parmSize > 4096) {
		LogError("KEY_PARMS.parmSize %u exceeds maximum allowed bound",
			 keyParms->parmSize);
		keyParms->parmSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}
	if (*offset > capacity || (UINT64)keyParms->parmSize > capacity - *offset) {
		keyParms->parmSize = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}

	if (keyParms->parmSize == 0)
		keyParms->parms = NULL;
	else {
		keyParms->parms = malloc(keyParms->parmSize);
		if (keyParms->parms == NULL) {
			LogError("malloc of %u bytes failed.", keyParms->parmSize);
			keyParms->parmSize = 0;
			return TCSERR(TSS_E_OUTOFMEMORY);
		}

		if ((rc = UnloadBlob_s(offset, keyParms->parmSize, blob, capacity, keyParms->parms))) {
			free(keyParms->parms);
			keyParms->parms = NULL;
			keyParms->parmSize = 0;
			return rc;
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_KEY_PARMS(UINT64 *offset, BYTE *blob, TCPA_KEY_PARMS *keyParms)
{
	return UnloadBlob_KEY_PARMS_s(offset, blob, UINT64_MAX, keyParms);
}

void
UnloadBlob_KEY_FLAGS(UINT64 *offset, BYTE *blob, TCPA_KEY_FLAGS *flags)
{
	(void)UnloadBlob_KEY_FLAGS_s(offset, blob, UINT64_MAX, flags);
}

TSS_RESULT
UnloadBlob_KEY_FLAGS_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_KEY_FLAGS *flags)
{
	return UnloadBlob_UINT32_s(offset, (UINT32 *)flags, blob, capacity);
}

TSS_RESULT
UnloadBlob_CERTIFY_INFO_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_CERTIFY_INFO *certify)
{
	TSS_RESULT rc;

	if (!certify) {
		TPM_VERSION version;
		UINT32 size;

		if ((rc = UnloadBlob_VERSION_s(offset, blob, capacity, &version)))
			return rc;
		if ((rc = UnloadBlob_UINT16_s(offset, NULL, blob, capacity)))
			return rc;
		if ((rc = UnloadBlob_KEY_FLAGS_s(offset, blob, capacity, NULL)))
			return rc;
		if ((rc = UnloadBlob_BOOL_s(offset, NULL, blob, capacity)))
			return rc;

		if ((rc = UnloadBlob_KEY_PARMS_s(offset, blob, capacity, NULL)))
			return rc;

		if ((rc = UnloadBlob_s(offset, TCPA_DIGEST_SIZE, blob, capacity, NULL)))
			return rc;
		if ((rc = UnloadBlob_s(offset, TCPA_NONCE_SIZE, blob, capacity, NULL)))
			return rc;
		if ((rc = UnloadBlob_BOOL_s(offset, NULL, blob, capacity)))
			return rc;
		if ((rc = UnloadBlob_UINT32_s(offset, &size, blob, capacity)))
			return rc;

		if (size > 4096)
			return TCSERR(TSS_E_BAD_PARAMETER);
		if (size > 0) {
			if ((rc = UnloadBlob_s(offset, size, blob, capacity, NULL)))
				return rc;
		}

		if (Decode_UINT16((BYTE *) &version) == TPM_TAG_CERTIFY_INFO2){
			/* This is a TPM_CERTIFY_INFO2 structure. */
			/* Read migrationAuthority. */
			if ((rc = UnloadBlob_UINT32_s(offset, &size, blob, capacity)))
				return rc;
			if (size > 4096)
				return TCSERR(TSS_E_BAD_PARAMETER);
			if (size > 0) {
				if ((rc = UnloadBlob_s(offset, size, blob, capacity, NULL)))
					return rc;
			}
		}

		return TSS_SUCCESS;
	}

	certify->algorithmParms.parms = NULL;
	certify->algorithmParms.parmSize = 0;
	certify->PCRInfo = NULL;
	certify->PCRInfoSize = 0;

	if ((rc = UnloadBlob_VERSION_s(offset, blob, capacity, (TPM_VERSION *)&certify->version)))
		return rc;
	if ((rc = UnloadBlob_UINT16_s(offset, &certify->keyUsage, blob, capacity)))
		return rc;
	if ((rc = UnloadBlob_KEY_FLAGS_s(offset, blob, capacity, &certify->keyFlags)))
		return rc;
	if ((rc = UnloadBlob_BOOL_s(offset, (TSS_BOOL *)&certify->authDataUsage, blob, capacity)))
		return rc;

	if ((rc = UnloadBlob_KEY_PARMS_s(offset, blob, capacity, &certify->algorithmParms)))
		return rc;

	if ((rc = UnloadBlob_s(offset, TCPA_DIGEST_SIZE, blob, capacity, certify->pubkeyDigest.digest)))
		goto err;
	if ((rc = UnloadBlob_s(offset, TCPA_NONCE_SIZE, blob, capacity, certify->data.nonce)))
		goto err;
	if ((rc = UnloadBlob_BOOL_s(offset, (TSS_BOOL *)&certify->parentPCRStatus, blob, capacity)))
		goto err;
	if ((rc = UnloadBlob_UINT32_s(offset, &certify->PCRInfoSize, blob, capacity)))
		goto err;

	if (certify->PCRInfoSize > 4096) {
		rc = TCSERR(TSS_E_BAD_PARAMETER);
		goto err;
	}
	if (*offset > capacity || (UINT64)certify->PCRInfoSize > capacity - *offset) {
		rc = TCSERR(TSS_E_BAD_PARAMETER);
		goto err;
	}

	if (certify->PCRInfoSize > 0) {
		certify->PCRInfo = (BYTE *)malloc(certify->PCRInfoSize);
		if (certify->PCRInfo == NULL) {
			LogError("malloc of %u bytes failed.", certify->PCRInfoSize);
			certify->PCRInfoSize = 0;
			rc = TCSERR(TSS_E_OUTOFMEMORY);
			goto err;
		}
		if ((rc = UnloadBlob_s(offset, certify->PCRInfoSize, blob, capacity, certify->PCRInfo)))
			goto err;
	} else {
		certify->PCRInfo = NULL;
	}

	if (Decode_UINT16((BYTE *) &certify->version) == TPM_TAG_CERTIFY_INFO2){
		/* This is a TPM_CERTIFY_INFO2 structure. */
		/* Read migrationAuthority. */
		UINT32 size;
		if ((rc = UnloadBlob_UINT32_s(offset, &size, blob, capacity)))
			goto err;
		if (size > 4096) {
			rc = TCSERR(TSS_E_BAD_PARAMETER);
			goto err;
		}
		if (size > 0) {
			if ((rc = UnloadBlob_s(offset, size, blob, capacity, NULL)))
				goto err;
		}
	}

	return TSS_SUCCESS;

err:
	free(certify->algorithmParms.parms);
	certify->algorithmParms.parms = NULL;
	certify->algorithmParms.parmSize = 0;
	free(certify->PCRInfo);
	certify->PCRInfo = NULL;
	certify->PCRInfoSize = 0;
	return rc;
}

TSS_RESULT
UnloadBlob_CERTIFY_INFO(UINT64 *offset, BYTE *blob, TCPA_CERTIFY_INFO *certify)
{
	return UnloadBlob_CERTIFY_INFO_s(offset, blob, UINT64_MAX, certify);
}

TSS_RESULT
UnloadBlob_KEY_HANDLE_LIST_s(UINT64 *offset, BYTE *blob, UINT64 capacity, TCPA_KEY_HANDLE_LIST *list)
{
	UINT16 i;
	TSS_RESULT rc;

	if (!list) {
		UINT16 size;

		if ((rc = UnloadBlob_UINT16_s(offset, &size, blob, capacity)))
			return rc;

		if (*offset > capacity || ((UINT64)size * sizeof(UINT32)) > capacity - *offset)
			return TCSERR(TSS_E_BAD_PARAMETER);

		*offset += ((UINT64)size * sizeof(UINT32));

		return TSS_SUCCESS;
	}

	list->handle = NULL;
	list->loaded = 0;

	if ((rc = UnloadBlob_UINT16_s(offset, &list->loaded, blob, capacity)))
		return rc;

	if (list->loaded == 0)
		return TSS_SUCCESS;

	if (*offset > capacity || ((UINT64)list->loaded * sizeof(UINT32)) > capacity - *offset) {
		list->loaded = 0;
		return TCSERR(TSS_E_BAD_PARAMETER);
	}

	list->handle = malloc(list->loaded * sizeof (UINT32));
	if (list->handle == NULL) {
		LogError("malloc of %zd bytes failed.", list->loaded * sizeof (UINT32));
		list->loaded = 0;
		return TCSERR(TSS_E_OUTOFMEMORY);
	}

	for (i = 0; i < list->loaded; i++) {
		if ((rc = UnloadBlob_UINT32_s(offset, &list->handle[i], blob, capacity))) {
			free(list->handle);
			list->handle = NULL;
			list->loaded = 0;
			return rc;
		}
	}

	return TSS_SUCCESS;
}

TSS_RESULT
UnloadBlob_KEY_HANDLE_LIST(UINT64 *offset, BYTE *blob, TCPA_KEY_HANDLE_LIST *list)
{
	return UnloadBlob_KEY_HANDLE_LIST_s(offset, blob, UINT64_MAX, list);
}

void
LoadBlob_DIGEST(UINT64 *offset, BYTE *blob, TPM_DIGEST *digest)
{
	LoadBlob(offset, TPM_SHA1_160_HASH_LEN, blob, digest->digest);
}

void
UnloadBlob_DIGEST(UINT64 *offset, BYTE *blob, TPM_DIGEST *digest)
{
	UnloadBlob(offset, TPM_SHA1_160_HASH_LEN, blob, digest->digest);
}

void
LoadBlob_NONCE(UINT64 *offset, BYTE *blob, TPM_NONCE *nonce)
{
	LoadBlob(offset, TCPA_NONCE_SIZE, blob, nonce->nonce);
}

void
UnloadBlob_NONCE(UINT64 *offset, BYTE *blob, TPM_NONCE *nonce)
{
	UnloadBlob(offset, TCPA_NONCE_SIZE, blob, nonce->nonce);
}

void
LoadBlob_AUTHDATA(UINT64 *offset, BYTE *blob, TPM_AUTHDATA *authdata)
{
	LoadBlob(offset, TPM_SHA1_160_HASH_LEN, blob, authdata->authdata);
}

void
UnloadBlob_AUTHDATA(UINT64 *offset, BYTE *blob, TPM_AUTHDATA *authdata)
{
	UnloadBlob(offset, TPM_SHA1_160_HASH_LEN, blob, authdata->authdata);
}
