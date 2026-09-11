
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

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_Data_Bind(TSS_HENCDATA hEncData,	/* in */
	       TSS_HKEY hEncKey,	/* in */
	       UINT32 ulDataLength,	/* in */
	       BYTE *rgbDataToBind)	/* in */
{
	UINT32 encDataLength = 0;
	BYTE encData[256];
	BYTE *keyData = NULL;
	UINT32 keyDataLength = 0;
	TCPA_BOUND_DATA boundData;
	UINT64 offset = 0;
	BYTE bdblob[256];
	TCPA_RESULT result;
	TSS_KEY keyContainer;
	TSS_HCONTEXT tspContext;
	UINT32 maxPayloadLength;

	LogTrace();
	if (rgbDataToBind == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if (!obj_is_encdata(hEncData))
		return TSPERR(TSS_E_INVALID_HANDLE);

	if ((result = obj_rsakey_get_tsp_context(hEncKey, &tspContext)))
		return result;

	/* XXX Just get the pubkey here */
	if ((result = obj_rsakey_get_blob(hEncKey, &keyDataLength, &keyData)))
		return result;

	memset(&keyContainer, 0, sizeof(TSS_KEY));
	offset = 0;
	result = UnloadBlob_TSS_KEY_s(&offset, keyData, keyDataLength, &keyContainer);
	free_tspi(tspContext, keyData);
	if (result)
		goto done;

	if (keyContainer.keyUsage != TPM_KEY_BIND &&
	    keyContainer.keyUsage != TPM_KEY_LEGACY) {
		result = TSPERR(TSS_E_INVALID_KEYUSAGE);
		goto done;
	}

	/* RSA_public_encrypt() writes RSA_size(rsa) (= modulus length) bytes.
	 * Validate key modulus against encData stack buffer bounds. */
	if (keyContainer.pubKey.key == NULL ||
	    keyContainer.pubKey.keyLength == 0 ||
	    keyContainer.pubKey.keyLength > sizeof(encData)) {
		result = TSPERR(TSS_E_ENC_INVALID_LENGTH);
		goto done;
	}

	/* Compute maximum plaintext payload length based on padding scheme.
	 * For legacy keys using PKCS#1 v1.5, overhead is 11 bytes.
	 * For bind keys using PKCS#1 v1.5, bound data header adds 5 bytes (16 total).
	 * For bind keys using OAEP (default), overhead is 42 bytes + 5 byte header (47 total).
	 * Reject invalid or unsupported schemes with TSS_E_INVALID_ENCSCHEME.
	 * Reject payloads that exceed bounds to prevent stack overflow in bdblob[256]. */
	if (keyContainer.keyUsage == TPM_KEY_LEGACY) {
		if (keyContainer.algorithmParms.encScheme != TCPA_ES_RSAESPKCSv15) {
			result = TSPERR(TSS_E_INVALID_ENCSCHEME);
			goto done;
		}
		if (keyContainer.pubKey.keyLength < 11) {
			result = TSPERR(TSS_E_ENC_INVALID_LENGTH);
			goto done;
		}
		maxPayloadLength = keyContainer.pubKey.keyLength - 11;
	} else { /* TPM_KEY_BIND */
		if (keyContainer.algorithmParms.encScheme == TCPA_ES_RSAESPKCSv15) {
			if (keyContainer.pubKey.keyLength < 16) {
				result = TSPERR(TSS_E_ENC_INVALID_LENGTH);
				goto done;
			}
			maxPayloadLength = keyContainer.pubKey.keyLength - 16;
		} else if (keyContainer.algorithmParms.encScheme == TCPA_ES_RSAESOAEP_SHA1_MGF1) {
			if (keyContainer.pubKey.keyLength < 47) {
				result = TSPERR(TSS_E_ENC_INVALID_LENGTH);
				goto done;
			}
			maxPayloadLength = keyContainer.pubKey.keyLength - 47;
		} else {
			result = TSPERR(TSS_E_INVALID_ENCSCHEME);
			goto done;
		}
	}

	if (ulDataLength > maxPayloadLength ||
	    (keyContainer.keyUsage == TPM_KEY_BIND &&
	     (sizeof(TCPA_VERSION) + sizeof(BYTE) + (UINT64)ulDataLength > sizeof(bdblob)))) {
		result = TSPERR(TSS_E_ENC_INVALID_LENGTH);
		goto done;
	}

	if (keyContainer.keyUsage == TPM_KEY_LEGACY) {
		if ((result = Trspi_RSA_PKCS15_Encrypt(rgbDataToBind, ulDataLength, encData,
						       &encDataLength, keyContainer.pubKey.key,
						       keyContainer.pubKey.keyLength)))
			goto done;
	} else if (keyContainer.algorithmParms.encScheme == TCPA_ES_RSAESPKCSv15) {
		boundData.payload = TCPA_PT_BIND;
		memcpy(&boundData.ver, &VERSION_1_1, sizeof(TCPA_VERSION));
		boundData.payloadData = rgbDataToBind;

		offset = 0;
		Trspi_LoadBlob_BOUND_DATA(&offset, boundData, ulDataLength, bdblob);

		if ((result = Trspi_RSA_PKCS15_Encrypt(bdblob, offset, encData,
						       &encDataLength, keyContainer.pubKey.key,
						       keyContainer.pubKey.keyLength)))
			goto done;
	} else {
		/* TCPA_ES_RSAESOAEP_SHA1_MGF1 */
		boundData.payload = TCPA_PT_BIND;
		memcpy(&boundData.ver, &VERSION_1_1, sizeof(TCPA_VERSION));
		boundData.payloadData = rgbDataToBind;

		offset = 0;
		Trspi_LoadBlob_BOUND_DATA(&offset, boundData, ulDataLength, bdblob);

		if ((result = Trspi_RSA_Encrypt(bdblob, offset, encData, &encDataLength,
						keyContainer.pubKey.key,
						keyContainer.pubKey.keyLength)))
			goto done;
	}

	if (encDataLength > sizeof(encData)) {
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	}

	if ((result = obj_encdata_set_data(hEncData, encDataLength, encData))) {
		LogError("Error in calling SetAttribData on the encrypted data object.");
		result = TSPERR(TSS_E_INTERNAL_ERROR);
		goto done;
	}
done:
	free_key_refs(&keyContainer);
	return result;
}

TSS_RESULT
Tspi_Data_Unbind(TSS_HENCDATA hEncData,		/* in */
		 TSS_HKEY hKey,			/* in */
		 UINT32 * pulUnboundDataLength,	/* out */
		 BYTE ** prgbUnboundData)	/* out */
{
	TCPA_RESULT result;
	TPM_AUTH privAuth;
	TCPA_DIGEST digest;
	TSS_HPOLICY hPolicy;
	BYTE *encData;
	UINT32 encDataSize;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_BOOL usesAuth;
	TPM_AUTH *pPrivAuth;
        TSS_HCONTEXT tspContext;
	Trspi_HashCtx hashCtx;

	LogTrace();
	if (pulUnboundDataLength == NULL || prgbUnboundData == NULL)
		return TSPERR(TSS_E_BAD_PARAMETER);

	if ((result = obj_encdata_get_tsp_context(hEncData, &tspContext)))
		return result;

	if ((result = obj_rsakey_get_policy(hKey, TSS_POLICY_USAGE, &hPolicy, &usesAuth)))
		return result;

	if ((result = obj_encdata_get_data(hEncData, &encDataSize, &encData)))
		return result == (TSS_E_INVALID_OBJ_ACCESS | TSS_LAYER_TSP) ?
		       TSPERR(TSS_E_ENC_NO_DATA) :
		       result;

	if ((result = obj_rsakey_get_tcs_handle(hKey, &tcsKeyHandle)))
		return result;

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_UnBind);
		result |= Trspi_Hash_UINT32(&hashCtx, encDataSize);
		result |= Trspi_HashUpdate(&hashCtx, encDataSize, encData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			return result;

		if ((result = secret_PerformAuth_OIAP(hKey, TPM_ORD_UnBind, hPolicy, FALSE, &digest,
						      &privAuth)))
			return result;
		pPrivAuth = &privAuth;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = TCS_API(tspContext)->UnBind(tspContext, tcsKeyHandle, encDataSize, encData,
						  pPrivAuth, pulUnboundDataLength,
						  prgbUnboundData)))
		return result;

	if (usesAuth) {
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, result);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_UnBind);
		result |= Trspi_Hash_UINT32(&hashCtx, *pulUnboundDataLength);
		result |= Trspi_HashUpdate(&hashCtx, *pulUnboundDataLength, *prgbUnboundData);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto error;

		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth)))
			goto error;
	}

	if ((result = __tspi_add_mem_entry(tspContext, *prgbUnboundData)))
		goto error;

	return TSS_SUCCESS;
error:
	free(*prgbUnboundData);
	*prgbUnboundData = NULL;
	*pulUnboundDataLength = 0;
	return result;
}
