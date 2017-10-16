
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
#include "authsess.h"

TSS_RESULT
owner_get_pubek(TSS_HCONTEXT tspContext, TSS_HTPM hTPM, TSS_HKEY *hPubEk)
{
	TSS_RESULT result;
	UINT32 tpmVersion, pubEKSize;
	TSS_HPOLICY hPolicy;
	UINT32 delegationType = TSS_DELEGATIONTYPE_NONE;
	Trspi_HashCtx hashCtx;
	BYTE *pubEK = NULL;
	TSS_HKEY hRetKey;
	TPM_AUTH ownerAuth;
	TPM_DIGEST digest;
	TPM_AUTH *pAuth;
	struct authsess *xsap = NULL;

	if ((result = obj_context_get_tpm_version(tspContext, &tpmVersion)))
		return result;

	if ((result = obj_tpm_get_policy(hTPM, TSS_POLICY_USAGE, &hPolicy)))
		return result;

	if ((result = obj_policy_get_delegation_type(hPolicy, &delegationType)))
		return result;

	switch (tpmVersion) {
	case 2:
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadInternalPub);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_KH_EK);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if (delegationType == TSS_DELEGATIONTYPE_NONE) {
			if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerReadInternalPub,
					hPolicy, FALSE, &digest, &ownerAuth)))
				goto done;
			pAuth = &ownerAuth;
		} else {
			if ((result = authsess_xsap_init(tspContext, hTPM, 0,
					TSS_AUTH_POLICY_REQUIRED, TPM_ORD_OwnerReadInternalPub, TPM_ET_OWNER,
					&xsap)))
				goto done;
			if ((result = authsess_xsap_hmac(xsap, &digest)))
				goto done;
			pAuth = xsap->pAuth;
		}

		if ((result = TCS_API(tspContext)->OwnerReadInternalPub(tspContext,
				TPM_KH_EK, pAuth, &pubEKSize, &pubEK)))
			goto done;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_SUCCESS);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadInternalPub);
		result |= Trspi_HashUpdate(&hashCtx, pubEKSize, pubEK);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if (delegationType == TSS_DELEGATIONTYPE_NONE) {
			if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest,
					&ownerAuth)))
				goto done;
		} else {
			if ((result = authsess_xsap_verify(xsap, &digest)))
				goto done;
		}

		break;
	default:
		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadPubek);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if (delegationType == TSS_DELEGATIONTYPE_NONE) {
			if ((result = secret_PerformAuth_OIAP(hTPM, TPM_ORD_OwnerReadPubek,
					hPolicy, FALSE, &digest, &ownerAuth)))
				goto done;
			pAuth = &ownerAuth;
		} else {
			if ((result = authsess_xsap_init(tspContext, hTPM, 0,
					TSS_AUTH_POLICY_REQUIRED, TPM_ORD_OwnerReadPubek, TPM_ET_OWNER,
					&xsap)))
				goto done;
			if ((result = authsess_xsap_hmac(xsap, &digest)))
				goto done;
			pAuth = xsap->pAuth;
		}

		if ((result = TCS_API(tspContext)->OwnerReadPubek(tspContext, pAuth,
				&pubEKSize, &pubEK)))
			goto done;

		result = Trspi_HashInit(&hashCtx, TSS_HASH_SHA1);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_SUCCESS);
		result |= Trspi_Hash_UINT32(&hashCtx, TPM_ORD_OwnerReadPubek);
		result |= Trspi_HashUpdate(&hashCtx, pubEKSize, pubEK);
		if ((result |= Trspi_HashFinal(&hashCtx, digest.digest)))
			goto done;

		if (delegationType == TSS_DELEGATIONTYPE_NONE) {
			if ((result = obj_policy_validate_auth_oiap(hPolicy, &digest,
					&ownerAuth)))
				goto done;
		} else {
			if ((result = authsess_xsap_verify(xsap, &digest)))
				goto done;
		}

		break;
	}

	if ((result = obj_rsakey_add(tspContext, TSS_KEY_SIZE_2048|TSS_KEY_TYPE_LEGACY, &hRetKey)))
		goto done;

	if ((result = obj_rsakey_set_pubkey(hRetKey, TRUE, pubEK)))
		goto done;

	*hPubEk = hRetKey;
done:
	free(pubEK);
	authsess_free(xsap);
	return result;
}
