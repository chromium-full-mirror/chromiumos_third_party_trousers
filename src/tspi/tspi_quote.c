
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
#include <inttypes.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "obj.h"


TSS_RESULT
Tspi_TPM_Quote(TSS_HTPM hTPM,				/* in */
	       TSS_HKEY hIdentKey,			/* in */
	       TSS_HPCRS hPcrComposite,			/* in */
	       TSS_VALIDATION * pValidationData)	/* in, out */
{
	TCPA_RESULT result = TSS_SUCCESS;
	TPM_AUTH privAuth;
	TPM_AUTH *pPrivAuth = &privAuth;
	UINT64 offset;
	TCPA_DIGEST digest;
	TCS_KEY_HANDLE tcsKeyHandle;
	TSS_HPOLICY hPolicy;
	TCPA_NONCE antiReplay;
	UINT32 pcrDataSize;
	BYTE pcrData[128];
	UINT32 validationLength = 0;
	BYTE *validationData = NULL;
	UINT32 pcrDataOutSize;
	BYTE *pcrDataOut = NULL;
	UINT32 keyDataSize;
	BYTE *keyData = NULL;
	TSS_KEY keyContainer;
	BYTE quoteinfo[1024];
	TSS_BOOL usesAuth;
	TSS_HCONTEXT tspContext;
	TCPA_VERSION version = {1, 1, 0, 0};
	Trspi_HashCtx hashCtx;
	TCPA_PCR_COMPOSITE pcrComp;

	__tspi_memset(&keyContainer, 0, sizeof(TSS_KEY));
	__tspi_memset(&pcrComp, 0, sizeof(pcrComp));
	if (pValidationData) {
		pValidationData->rgbValidationData = NULL;
		pValidationData->rgbData = NULL;
		pValidationData->ulValidationDataLength = 0;
		pValidationData->ulDataLength = 0;
	}

	if ((result = obj_tpm_get_tsp_context(hTPM, &tspContext)))
		goto done;

	if (hPcrComposite && !obj_is_pcrs(hPcrComposite)) {
		result = TSPERR(TSS_E_INVALID_HANDLE);
		goto done;
	}

	/*  get the identKey Policy */
	if ((result = obj_rsakey_get_policy(hIdentKey, TSS_POLICY_USAGE, &hPolicy, &usesAuth)))
		goto done;

	/*  get the Identity TCS keyHandle */
	if ((result = obj_rsakey_get_tcs_handle(hIdentKey, &tcsKeyHandle)))
		goto done;

	if (pValidationData == NULL) {
		if ((result = get_local_random(tspContext, FALSE, sizeof(TCPA_NONCE),
					       (BYTE **)antiReplay.nonce)))
			goto done;
	} else {
		if (pValidationData->ulExternalDataLength < sizeof(antiReplay.nonce)) {
			result = TSPERR(TSS_E_BAD_PARAMETER);
			goto done;
		}

		memcpy(antiReplay.nonce, pValidationData->rgbExternalData,
		       sizeof(antiReplay.nonce));
	}

	pcrDataSize = 0;
	if (hPcrComposite) {
		if ((result = obj_pcrs_get_selection(hPcrComposite, &pcrDataSize, pcrData)))
			goto done;
	}

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Quote);
	result |= Trspi_HashUpdate(&hashCtx, TPM_SHA1_160_HASH_LEN, antiReplay.nonce);
	result |= Trspi_HashUpdate(&hashCtx, pcrDataSize, pcrData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		goto done;

	if (usesAuth) {
		if ((result = secret_PerformAuth_OIAP(hIdentKey, TPM_ORD_Quote, hPolicy, FALSE,
						      &digest, &privAuth))) {
			goto done;
		}
		pPrivAuth = &privAuth;
	} else {
		pPrivAuth = NULL;
	}

	if ((result = TCS_API(tspContext)->Quote(tspContext, tcsKeyHandle, &antiReplay, pcrDataSize,
						 pcrData, pPrivAuth, &pcrDataOutSize, &pcrDataOut,
						 &validationLength, &validationData)))
		goto done;

	result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
	result |= Trspi_Hash_UINT32(&hashCtx, result);
	result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_Quote);
	result |= Trspi_HashUpdate(&hashCtx, pcrDataOutSize, pcrDataOut);
	result |= Trspi_Hash_UINT32(&hashCtx, validationLength);
	result |= Trspi_HashUpdate(&hashCtx, validationLength, validationData);
	if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
		goto done;

	if (usesAuth == TRUE) {
		if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest, &privAuth))) {
			goto done;
		}
	}

	if (hPcrComposite) {
		offset = 0;
		if ((result = Trspi_UnloadBlob_PCR_COMPOSITE(&offset, pcrDataOut, &pcrComp))) {
			goto done;
		}

		if ((result = obj_pcrs_set_values(hPcrComposite, &pcrComp)))
			goto done;
	}

	if ((result = Tspi_GetAttribData(hIdentKey, TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB, &keyDataSize, &keyData))) {
		goto done;
	}

	/* create the validation data */
	offset = 0;
	if ((result = UnloadBlob_TSS_KEY(&offset, keyData, &keyContainer)))
		goto done;

	/*  creating pcrCompositeHash */
	Trspi_Hash(TSS_HASH_SHA1, pcrDataOutSize, pcrDataOut, digest.digest);

	/* generate Quote_info struct */
	/* 1. add version */
	offset = 0;
	if (keyContainer.hdr.key12.tag == TPM_TAG_KEY12)
		Trspi_LoadBlob_TCPA_VERSION(&offset, quoteinfo, version);
	else
		Trspi_LoadBlob_TCPA_VERSION(&offset, quoteinfo, keyContainer.hdr.key11.ver);
	/* 2. add "QUOT" */
	quoteinfo[offset++] = 'Q';
	quoteinfo[offset++] = 'U';
	quoteinfo[offset++] = 'O';
	quoteinfo[offset++] = 'T';
	/* 3. Composite Hash */
	Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
		       digest.digest);
	/* 4. AntiReplay Nonce */
	Trspi_LoadBlob(&offset, TCPA_SHA1_160_HASH_LEN, quoteinfo,
		       antiReplay.nonce);

	if (pValidationData == NULL) {
		/* validate the data here */
		Trspi_Hash(TSS_HASH_SHA1, offset, quoteinfo, digest.digest);

		if ((result = Trspi_Verify(TSS_HASH_SHA1, digest.digest, 20,
					   keyContainer.pubKey.key,
					   keyContainer.pubKey.keyLength,
					   validationData,
					   validationLength))) {
			goto done;
		}
	} else {
		pValidationData->rgbValidationData = calloc_tspi(tspContext, validationLength);
		if (pValidationData->rgbValidationData == NULL) {
			LogError("malloc of %u bytes failed.", validationLength);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		pValidationData->ulValidationDataLength = validationLength;
		memcpy(pValidationData->rgbValidationData, validationData, validationLength);

		pValidationData->rgbData = calloc_tspi(tspContext, offset);
		if (pValidationData->rgbData == NULL) {
			LogError("malloc of %" PRIu64 " bytes failed.", offset);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto done;
		}
		pValidationData->ulDataLength = (UINT32)offset;
		memcpy(pValidationData->rgbData, quoteinfo, offset);
	}

done:
	free(validationData);
	free(pcrDataOut);
	if (keyData)
		free_tspi(tspContext, keyData);
	free_key_refs(&keyContainer);
	free(pcrComp.pcrValue);
	free(pcrComp.select.pcrSelect);
	if (result && pValidationData) {
		if (pValidationData->rgbData) {
			free_tspi(tspContext, pValidationData->rgbData);
			pValidationData->rgbData = NULL;
		}
		if (pValidationData->rgbValidationData) {
			free_tspi(tspContext, pValidationData->rgbValidationData);
			pValidationData->rgbValidationData = NULL;
		}
		pValidationData->ulValidationDataLength = 0;
		pValidationData->ulDataLength = 0;
	}

	return result;
}
