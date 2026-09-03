/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	Tspi_ChangeAuth01
 *
 * DESCRIPTION
 *	This test will verify Tspi_ChangeAuth
 *	The goal of this test is to return TSS_SUCCESS.
 *		To have it return success, you need to follow the
 *		algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create hKeyChild
 *		Load Key By UUID for hSRK
 *		Get Policy Object for the srk
 *		Set Secret
 *		Create Storage Key
 *		Create Signing Key
 *		Load keys
 *		Get Default Policy for the hPolicy
 *
 *	Test:	Load both keys in a second context, so that the signing key
 *		is loaded by two contexts
 *		Call ChangeAuth on the signing key. If it is not a success
 *		Make sure that it returns the proper return codes
 *		Check that the storage key is still loaded and is the same key
 *		Check that neither context can use the signing key with its
 *		old secret, and that tcsd still knows both handles
 *		Reload the signing key and sign with its new secret
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hMSigningKey Object
 *		Close hKeyChild Object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"



int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

/* What tcsd returns for a key handle it knows whose key isn't loaded. */
#define KEY_NOT_LOADED	(TSS_LAYER_TCS | TCS_E_KM_LOADFAILED)

/* Prints the error and exits, closing hContext and, if open, hContext2. */
static void
fail_test(char *nameOfFunction, char *what, TSS_RESULT result,
	  TSS_HCONTEXT hContext, TSS_HCONTEXT hContext2)
{
	print_error(what, result);
	print_end_test(nameOfFunction);
	if (hContext2) {
		Tspi_Context_FreeMemory(hContext2, NULL);
		Tspi_Context_Close(hContext2);
	}
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(result ? result : TSS_E_FAIL);
}

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_ChangeAuth01";
	TSS_HKEY	hKeyChild, hKeyParent, hSRK;
	TSS_HPOLICY	srkUsagePolicy, hKeyChildPolicy, hNewPolicy;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	UINT32		ulParentPubKeyLength = 0;
	BYTE		*rgbParentPubKey = NULL;
	TSS_HCONTEXT	hContext2 = 0;
	TSS_HKEY	hKeyChild2, hKeyParent2, hSRK2;
	TSS_HPOLICY	hKeyChildPolicy2;
	TSS_HHASH	hHash, hHash2;
	UINT32		ulParentBlobLength = 0, ulChildBlobLength = 0;
	BYTE		*rgbParentBlob = NULL, *rgbChildBlob = NULL;
	UINT32		ulPubKeyLength = 0, ulSignatureLength = 0;
	BYTE		*rgbPubKey = NULL, *rgbSignature = NULL;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	// Set up the SRK

		//Load SRK By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM,
			SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID for hSRK", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif

	// Create Parent Key (no auth, storage)
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE |
			TSS_KEY_NO_AUTHORIZATION,
			&hKeyParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(hKeyParent, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hKeyParent, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// Set up Child Key (signing, auth)

		//Create Object for Child Key
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING |
			TSS_KEY_AUTHORIZATION,
			&hKeyChild);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_CloseObject(hContext, hKeyChild);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Get existing Policy Object
	//result = Tspi_GetPolicyObject(hKeyChild, TSS_POLICY_USAGE, &hKeyChildPolicy);
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE, &hKeyChildPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		// Set Secret
	result = Tspi_Policy_SetSecret(hKeyChildPolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Policy_AssignToObject(hKeyChildPolicy, hKeyChild);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hKeyChild, hKeyParent, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKeyChild, hKeyParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}




		// create a new Policy
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE, &hNewPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicy ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set the new policy's Secret
	result = Tspi_Policy_SetSecret(hNewPolicy, TESTSUITE_NEW_SECRET_MODE,
				       TESTSUITE_NEW_SECRET_LEN, TESTSUITE_NEW_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Record the parent's public key so we can check that hKeyParent
		// still refers to the same key after Tspi_ChangeAuth
	result = Tspi_Key_GetPubKey(hKeyParent, &ulParentPubKeyLength,
				    &rgbParentPubKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey (hKeyParent)", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// Load the same parent and child in a second context, so that two
	// contexts have the child loaded when its secret is changed
	result = Tspi_GetAttribData(hKeyParent, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_BLOB,
				    &ulParentBlobLength, &rgbParentBlob);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_GetAttribData (hKeyParent blob)",
			  result, hContext, hContext2);

	result = Tspi_GetAttribData(hKeyChild, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_BLOB,
				    &ulChildBlobLength, &rgbChildBlob);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_GetAttribData (hKeyChild blob)",
			  result, hContext, hContext2);

	// connect_load_srk closes hContext2 itself if it fails
	result = connect_load_srk(&hContext2, &hSRK2);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "connect_load_srk (hContext2)",
			  result, hContext, 0);

	result = Tspi_Context_LoadKeyByBlob(hContext2, hSRK2, ulParentBlobLength,
					    rgbParentBlob, &hKeyParent2);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Context_LoadKeyByBlob (hKeyParent2)",
			  result, hContext, hContext2);

	result = Tspi_Context_LoadKeyByBlob(hContext2, hKeyParent2,
					    ulChildBlobLength, rgbChildBlob,
					    &hKeyChild2);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Context_LoadKeyByBlob (hKeyChild2)",
			  result, hContext, hContext2);

		// Give hKeyChild2 the child's current (old) secret
	result = set_secret(hContext2, hKeyChild2, &hKeyChildPolicy2);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "set_secret (hKeyChild2)",
			  result, hContext, hContext2);

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
					   TSS_HASH_SHA1, &hHash);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Context_CreateObject (hHash)",
			  result, hContext, hContext2);

	result = Tspi_Hash_SetHashValue(hHash, 20, (BYTE *)"12345678901234567890");
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Hash_SetHashValue (hHash)",
			  result, hContext, hContext2);

	result = Tspi_Context_CreateObject(hContext2, TSS_OBJECT_TYPE_HASH,
					   TSS_HASH_SHA1, &hHash2);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Context_CreateObject (hHash2)",
			  result, hContext, hContext2);

	result = Tspi_Hash_SetHashValue(hHash2, 20, (BYTE *)"12345678901234567890");
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Hash_SetHashValue (hHash2)",
			  result, hContext, hContext2);

		// hKeyChild2 works with the old secret before ChangeAuth
	result = Tspi_Hash_Sign(hHash2, hKeyChild2, &ulSignatureLength,
				&rgbSignature);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Hash_Sign (hKeyChild2, before ChangeAuth)",
			  result, hContext, hContext2);

		// Call Change Auth
	result = Tspi_ChangeAuth(hKeyChild, hKeyParent, hNewPolicy);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	// Check the state after Tspi_ChangeAuth, before reloading anything:
	//   1. hKeyParent is still loaded and still refers to the same key.
	//   2. The copy of the child that was loaded with the old secret has
	//      been flushed for both contexts. tcsd keeps both handles but
	//      doesn't reload evicted keys, so both fail with KEY_NOT_LOADED
	//      until the key is loaded again. (A handle that tcsd had dropped
	//      would fail with TCS_E_INVALID_KEY instead.)
	//   3. hKeyChild can be reloaded with its new blob and signs with the
	//      new secret.
	// The old-secret checks never send a wrong secret to the TPM: either
	// tcsd rejects the request because the key isn't loaded, or the old
	// copy is still loaded and the old secret is correct for it. That
	// relies on tcsd not reloading evicted keys by itself, and on these
	// checks running before hKeyChild is reloaded, since both contexts
	// then share the copy loaded from the new blob.

	// 1. hKeyParent is still loaded and is the same key
	result = Tspi_Key_GetPubKey(hKeyParent, &ulPubKeyLength, &rgbPubKey);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Key_GetPubKey (hKeyParent after ChangeAuth)",
			  result, hContext, hContext2);
	if (ulPubKeyLength != ulParentPubKeyLength ||
	    memcmp(rgbPubKey, rgbParentPubKey, ulPubKeyLength))
		fail_test(nameOfFunction, "hKeyParent public key changed after ChangeAuth",
			  TSS_E_FAIL, hContext, hContext2);

	// 2a. The second context's handle, with the old secret
	result = Tspi_Hash_Sign(hHash2, hKeyChild2, &ulSignatureLength,
				&rgbSignature);
	if (result != KEY_NOT_LOADED)
		fail_test(nameOfFunction,
			  "Tspi_Hash_Sign (hKeyChild2, old secret), expected KM_LOADFAILED",
			  result, hContext, hContext2);

	// 2b. hKeyChild, with the old secret. Tspi_ChangeAuth assigned
	// hNewPolicy to hKeyChild, so put the old policy back first.
	result = Tspi_Policy_AssignToObject(hKeyChildPolicy, hKeyChild);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Policy_AssignToObject (old policy)",
			  result, hContext, hContext2);

	result = Tspi_Hash_Sign(hHash, hKeyChild, &ulSignatureLength, &rgbSignature);
	if (result != KEY_NOT_LOADED)
		fail_test(nameOfFunction,
			  "Tspi_Hash_Sign (hKeyChild, old secret), expected KM_LOADFAILED",
			  result, hContext, hContext2);

	result = Tspi_Policy_AssignToObject(hNewPolicy, hKeyChild);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Policy_AssignToObject (new policy)",
			  result, hContext, hContext2);

	// 3. Reload hKeyChild with its new blob and sign with the new secret
	result = Tspi_Key_LoadKey(hKeyChild, hKeyParent);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Key_LoadKey (hKeyChild after ChangeAuth)",
			  result, hContext, hContext2);

	result = Tspi_Hash_Sign(hHash, hKeyChild, &ulSignatureLength, &rgbSignature);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Hash_Sign (hKeyChild, new secret)",
			  result, hContext, hContext2);

	result = Tspi_Hash_VerifySignature(hHash, hKeyChild, ulSignatureLength,
					   rgbSignature);
	if (result != TSS_SUCCESS)
		fail_test(nameOfFunction, "Tspi_Hash_VerifySignature",
			  result, hContext, hContext2);

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_FreeMemory(hContext2, NULL);
	Tspi_Context_Close(hContext2);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(0);
}
