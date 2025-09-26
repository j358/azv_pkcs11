/*
 *  Copyright 2011-2025 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 *  Modified for azv-pkcs11 by:
 *  Joshua Lee https://github.com/j358
 */


#include "azv-pkcs11.h"

#define ID_OFFSET 10000
#define SERIAL_OFFSET 20000
#define KEY_OFFSET 30000
#define SESSION_ID 12345
#define MY_PRIVATE_KEY_HANDLE 54321
#define MY_PUBLIC_KEY_HANDLE 65432
#define MY_CERTIFICATE_HANDLE 76543

CK_ULONG gSessionSearchClass = 0;
CK_ULONG gSessionSearchCount = 0;

CK_ULONG gSignMechanism = 0;
CK_ULONG gSignLength = 0;

CK_FUNCTION_LIST empty_pkcs11_2_40_functions = 
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};


CK_INTERFACE empty_pkcs11_2_40_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_2_40_functions,
	0
};


CK_FUNCTION_LIST_3_0  empty_pkcs11_3_1_functions =
{
	{0x03, 0x01},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent,
	&C_GetInterfaceList,
	&C_GetInterface,
	&C_LoginUser,
	&C_SessionCancel,
	&C_MessageEncryptInit,
	&C_EncryptMessage,
	&C_EncryptMessageBegin,
	&C_EncryptMessageNext,
	&C_MessageEncryptFinal,
	&C_MessageDecryptInit,
	&C_DecryptMessage,
	&C_DecryptMessageBegin,
	&C_DecryptMessageNext,
	&C_MessageDecryptFinal,
	&C_MessageSignInit,
	&C_SignMessage,
	&C_SignMessageBegin,
	&C_SignMessageNext,
	&C_MessageSignFinal,
	&C_MessageVerifyInit,
	&C_VerifyMessage,
	&C_VerifyMessageBegin,
	&C_VerifyMessageNext,
	&C_MessageVerifyFinal
};


CK_INTERFACE empty_pkcs11_3_1_interface =
{
	(CK_CHAR*)"PKCS 11",
	&empty_pkcs11_3_1_functions,
	0
};


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	UNUSED(pInitArgs);

	AzvLog("C_Initialize called");

	// Initialize the azvlib package
	if (0 != AzvInit())
	{
		AzvLog("Failed to initialize azvlib package");
		return CKR_FUNCTION_FAILED;
	}


	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	UNUSED(pReserved);

	AzvLog("C_Finalize called");

	AzvCancel();

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	UNUSED(pInfo);

	AzvLog("C_GetInfo called");

	if (pInfo == NULL_PTR) {
		AzvLog("C_GetInfo called with NULL pInfo");
		return CKR_ARGUMENTS_BAD;
	}

	pInfo->cryptokiVersion.major = 3;
	pInfo->cryptokiVersion.minor = 1;
	pInfo->libraryVersion.major = 4;
	pInfo->libraryVersion.minor = 0;
	pInfo->flags = 0;
	sprintf((char * restrict)pInfo->manufacturerID, "%s", AzvGetVaultName());
	sprintf((char * restrict)pInfo->libraryDescription, "azv-pkcs11 library");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	AzvLog("C_GetFunctionList called");

	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &empty_pkcs11_2_40_functions;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	UNUSED(tokenPresent);

	if (pulCount == NULL_PTR) {
		AzvLog("C_GetSlotList called with NULL pulCount");
		return CKR_ARGUMENTS_BAD;
	}

	*pulCount = AzvGetVaultKeyCount();
	if (pSlotList == NULL_PTR) {
		AzvLog("C_GetSlotList called with NULL pSlotList, returning count");
		return CKR_OK;
	}
	
	AzvLog("C_GetSlotList called with valid pSlotList, returning list");
	for (int i = 0; i < (int)*pulCount && i < AzvGetVaultKeyCount(); i++) {
		pSlotList[i] = ID_OFFSET + i; // Example slot ID, adjust as needed
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_GetSlotInfo called with slotID: %lu", slotID);
	AzvLog(cntString);

	int index = (int)(slotID - ID_OFFSET);

	if (pInfo == NULL_PTR) {
		AzvLog("C_GetSlotInfo called with NULL pInfo");
		return CKR_ARGUMENTS_BAD;
	}

	if (index < 0 || index >= AzvGetVaultKeyCount()) {
		AzvLog("C_GetSlotInfo called with invalid slotID");
		return CKR_SLOT_ID_INVALID;
	}

	sprintf((char * restrict)pInfo->slotDescription, "%s", AzvGetKeyListName(index));
	sprintf((char * restrict)pInfo->manufacturerID, "%s", AzvGetVaultName());
	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	AzvLog((char *)pInfo->slotDescription);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_GetTokenInfo called with slotID: %lu", slotID);
	AzvLog(cntString);

	int index = (int)(slotID - ID_OFFSET);
	if (index < 0 || index >= AzvGetVaultKeyCount()) {
		AzvLog("C_GetTokenInfo called with invalid slotID");
		return CKR_SLOT_ID_INVALID;
	}

	if (pInfo == NULL_PTR) {
		AzvLog("C_GetTokenInfo called with NULL pInfo");
		return CKR_ARGUMENTS_BAD;
	}
	//char *n = AzvGetKeyListName(index);
	// get only first 29 characters

	sprintf((char * restrict)pInfo->label, "T-%s", AzvGetKeyListName(index));
	sprintf((char * restrict)pInfo->manufacturerID,"%s", AzvGetVaultName());
	sprintf((char * restrict)pInfo->model, "libazv");
	sprintf((char * restrict)pInfo->serialNumber, "%05x", (unsigned int)slotID);

	snprintf(cntString, sizeof(cntString), "pInfo->label: '%s'", pInfo->label);
	AzvLog(cntString);

	pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_CLOCK_ON_TOKEN;
	pInfo->ulMaxSessionCount = 100;
	pInfo->ulSessionCount = 1;
	pInfo->ulMaxRwSessionCount = 100;
	pInfo->ulRwSessionCount = 1;
	pInfo->ulMaxPinLen = 64;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory = 1024 * 1024; // 1
	pInfo->ulFreePublicMemory = 512 * 1024; // 512 KB
	pInfo->ulTotalPrivateMemory = 1024 * 1024; // 1
	pInfo->ulFreePrivateMemory = 512 * 1024; // 512 KB
	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;
	sprintf((char * restrict)pInfo->utcTime, "%s", AzvGetUTC());

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	UNUSED(slotID);
	UNUSED(pMechanismList);
	UNUSED(pulCount);

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_GetMechanismList called with slotID: %lu, NULL pMechanismList: %lu", slotID, (CK_ULONG)(pMechanismList == NULL_PTR));
	AzvLog(cntString);

	int index = (int)(slotID - ID_OFFSET);
	if (index < 0 || index >= AzvGetVaultKeyCount()) {
		AzvLog("C_GetMechanismList invalid slotID");
		return CKR_SLOT_ID_INVALID;
	}

	if (pMechanismList == NULL_PTR) {
		*pulCount = 2;
		return CKR_OK;
	} else {
		pMechanismList[0] = CKM_SHA256_RSA_PKCS;
		pMechanismList[1] = CKM_RSA_PKCS;
		*pulCount = 2;
		//*pulCount = 1;
		return CKR_OK;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	UNUSED(slotID);
	UNUSED(type);
	UNUSED(pInfo);

	int index = (int)(slotID - ID_OFFSET);
	if (index < 0 || index >= AzvGetVaultKeyCount()) {
		AzvLog("C_GetMechanismList invalid slotID");
		return CKR_SLOT_ID_INVALID;
	}

	switch (type) {
		case CKM_RSA_PKCS:
			if (pInfo != NULL_PTR) {
				AzvLog("C_GetMechanismInfo called with CKM_RSA_PKCS");
				pInfo->ulMinKeySize = 4096;
				pInfo->ulMaxKeySize = 4096;
				pInfo->flags = CKF_HW | CKF_SIGN | CKF_MESSAGE_SIGN | CKF_SIGN_RECOVER;
			} else {
				AzvLog("C_GetMechanismInfo called with CKM_RSA_PKCS NULL");
			}
			return CKR_OK;
		case CKM_SHA256_RSA_PKCS:
			if (pInfo != NULL_PTR) {
				AzvLog("C_GetMechanismInfo called with CKM_SHA256_RSA_PKCS");
				pInfo->ulMinKeySize = 4096;
				pInfo->ulMaxKeySize = 4096;
				pInfo->flags = CKF_HW | CKF_SIGN | CKF_MESSAGE_SIGN | CKF_SIGN_RECOVER;
			} else {
				AzvLog("C_GetMechanismInfo called with CKM_SHA256_RSA_PKCS NULL");
			}
			return CKR_OK;
		default:
			AzvLog("C_GetMechanismInfo called with unknown mechanism type");
			return CKR_MECHANISM_INVALID;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	UNUSED(slotID);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pLabel);

	AzvLog("C_InitToken called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	AzvLog("C_InitPIN called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	UNUSED(hSession);
	UNUSED(pOldPin);
	UNUSED(ulOldLen);
	UNUSED(pNewPin);
	UNUSED(ulNewLen);

	AzvLog("C_SetPIN called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	UNUSED(pApplication);
	UNUSED(Notify);

	if (phSession == NULL_PTR) {
		AzvLog("C_OpenSession called with NULL pInfo");
		return CKR_ARGUMENTS_BAD;
	}
	
	int index = (int)(slotID - ID_OFFSET);

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_OpenSession called with flags: 0x%02lx, slotID: %lu, session: %lu", flags, slotID, *phSession);
	AzvLog(cntString);

	if (index < 0 || index >= AzvGetVaultKeyCount()) {
		AzvLog("C_OpenSession called with invalid slotID");
		return CKR_SLOT_ID_INVALID;
	}

	if (*phSession == 0) {
		*phSession = SESSION_ID;
	}

	AzvSetKeyIndex(index);
	gSessionSearchClass = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_CloseSession called");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	UNUSED(slotID);

	AzvLog("C_CloseAllSessions called");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	UNUSED(hSession);
	UNUSED(pInfo);

	AzvLog("C_GetSessionInfo called");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(pulOperationStateLen);

	AzvLog("C_GetOperationState called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	UNUSED(hSession);
	UNUSED(pOperationState);
	UNUSED(ulOperationStateLen);
	UNUSED(hEncryptionKey);
	UNUSED(hAuthenticationKey);

	AzvLog("C_SetOperationState called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);

	
	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_Login called with hSession: %lu, userType: %lu, ulPinLen: %lu", hSession, userType, ulPinLen);
	AzvLog(cntString);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_Logout called");

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phObject);

	AzvLog("C_CreateObject called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phNewObject);

	AzvLog("C_CopyObject called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	UNUSED(hSession);
	UNUSED(hObject);

	AzvLog("C_DestroyObject called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pulSize);

	AzvLog("C_GetObjectSize called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{

	if (pTemplate == NULL_PTR) {
		AzvLog("C_GetAttributeValue called with NULL pTemplate");
		return CKR_OK;
	}

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_GetAttributeValue called with count: 0x%lu, session: %lu, handle %lu, attr: %04lx, len: %lu", ulCount, hSession, hObject, pTemplate->type, pTemplate->ulValueLen);
	AzvLog(cntString);

	CK_ULONG inLen = pTemplate->ulValueLen;

	// CK_ULONG length objects
	if (sizeof(CK_ULONG) == inLen) {
		switch(pTemplate->type) {
			case CKA_CLASS:
			switch (hObject) {
				case MY_PRIVATE_KEY_HANDLE:
					AzvLog("C_GetAttributeValue type: CKA_CLASS = CKO_PRIVATE_KEY");	
					*((CK_OBJECT_CLASS*)pTemplate->pValue) = CKO_PRIVATE_KEY;
					break;
				case MY_PUBLIC_KEY_HANDLE:
					AzvLog("C_GetAttributeValue type: CKA_CLASS = CKO_PUBLIC_KEY");
					*((CK_OBJECT_CLASS*)pTemplate->pValue) = CKO_PUBLIC_KEY;
					break;
				case MY_CERTIFICATE_HANDLE:
					AzvLog("C_GetAttributeValue type: CKA_CLASS = CKO_CERTIFICATE");
					*((CK_OBJECT_CLASS*)pTemplate->pValue) = CKO_CERTIFICATE;
					break;
				default:
					AzvLog("C_GetAttributeValue type: CKA_CLASS unknown handle");
					return CKR_OBJECT_HANDLE_INVALID;
				}
				break;
			case CKA_KEY_TYPE:
				AzvLog("C_GetAttributeValue type: CKA_KEY_TYPE = CKK_RSA");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CKK_RSA;
				pTemplate->ulValueLen = sizeof(CK_KEY_TYPE);
				break;
			case CKA_ID:
				AzvLog("C_GetAttributeValue CK_ULONG type: CKA_ID");
				pTemplate->ulValueLen = 0;
				break;
			case CKA_MODULUS_BITS:
				AzvLog("C_GetAttributeValue type: CKA_MODULUS_BITS = 4096");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = (CK_ULONG)(4096);
				pTemplate->ulValueLen = sizeof(CK_ULONG);
				break;
			case CKA_PUBLIC_KEY_INFO:
				AzvLog("C_GetAttributeValue type: CKA_PUBLIC_KEY_INFO");
				pTemplate->ulValueLen = 0;
				break;
			case CKA_CERTIFICATE_TYPE:
				AzvLog("C_GetAttributeValue type: CKA_CERTIFICATE_TYPE = CKC_X_509");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CKC_X_509;
				pTemplate->ulValueLen = sizeof(CK_ULONG);
				break;
			default:
				AzvLog("C_GetAttributeValue CK_ULONG unknown type");
				printf("%lx\n", pTemplate->type);
				break;
		}
	}

	// CK_BBOOL length objects
	if (sizeof(CK_BBOOL) == inLen) {
		switch(pTemplate->type) {
			case CKA_SENSITIVE:
				AzvLog("C_GetAttributeValue type: CKA_SENSITIVE = CK_TRUE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			case CKA_PRIVATE:
				AzvLog("C_GetAttributeValue type: CKA_PRIVATE = CK_TRUE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			case CKA_SIGN:
				AzvLog("C_GetAttributeValue type: CKA_SIGN = CK_TRUE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			case CKA_ALWAYS_AUTHENTICATE:
				AzvLog("C_GetAttributeValue type: CKA_ALWAYS_AUTHENTICATE = CK_FALSE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_FALSE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			case CKA_NEVER_EXTRACTABLE:
				AzvLog("C_GetAttributeValue type: CKA_NEVER_EXTRACTABLE = CK_TRUE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			case CKR_KEY_NOT_NEEDED:
				AzvLog("C_GetAttributeValue type: CKR_KEY_NOT_NEEDED = CK_TRUE");
				*((CK_OBJECT_CLASS*)pTemplate->pValue) = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
				break;
			default:
				AzvLog("C_GetAttributeValue CK_BBOOL unknown type");
				printf("%lx\n", pTemplate->type);
				break;
		}
	}
	
	// Other length objects

	//if ((sizeof(CK_BBOOL) != inLen) && (sizeof(CK_ULONG) != inLen)) 
	if (1) 
	{
		// Other length objects
		CK_ULONG byteLen;
		switch(pTemplate->type) {
			case CKA_PUBLIC_EXPONENT:
				AzvLog("C_GetAttributeValue type: CKA_PUBLIC_EXPONENT");
				byteLen = (CK_ULONG)(32 / 8); // 4 bytes
				if (pTemplate->pValue == NULL_PTR) {
					AzvLog("C_GetAttributeValue pValue is NULL");
					pTemplate->ulValueLen = byteLen;
					return CKR_OK;
				}
				if (pTemplate->ulValueLen < byteLen) {
					AzvLog("C_GetAttributeValue CKA_PUBLIC_EXPONENT length is too small");
					return CKR_BUFFER_TOO_SMALL;
				}
				CK_BYTE_PTR expData = (CK_BYTE_PTR)AzvGetKeyExponent();
				if (expData == NULL_PTR) {
					AzvLog("C_GetAttributeValue CKA_PUBLIC_EXPONENT data is NULL");
					return CKR_FUNCTION_FAILED;
				}
				//memcpy(pTemplate->pValue, expData, pTemplate->ulValueLen);
				for (int i = 0; i < (int)byteLen; i++) {
					((CK_BYTE*)pTemplate->pValue)[i] = expData[i];
					printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
				}
				printf("\n");
				break;
			case CKA_MODULUS:
				AzvLog("C_GetAttributeValue type: CKA_MODULUS");
				byteLen = (CK_ULONG)AzvGetKeyModulusLen();
				if (pTemplate->pValue == NULL_PTR) {
					AzvLog("C_GetAttributeValue pValue is NULL");
					pTemplate->ulValueLen = byteLen;
					return CKR_OK;
				}
				if (pTemplate->ulValueLen < byteLen) {
					AzvLog("C_GetAttributeValue CKA_MODULUS length is too small");
					pTemplate->ulValueLen = byteLen;
					return CKR_BUFFER_TOO_SMALL;
				}
				CK_BYTE_PTR modData = (CK_BYTE_PTR)AzvGetKeyModulus();
				if (modData == NULL_PTR) {
					AzvLog("C_GetAttributeValue CKA_MODULUS data is NULL");
					return CKR_FUNCTION_FAILED;
				}
				//memcpy(pTemplate->pValue, modData, pTemplate->ulValueLen);
				for (int i = 0; i < (int)byteLen; i++) {
					((CK_BYTE*)pTemplate->pValue)[i] = modData[i];
					printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
				}
				printf("\n");
				break;
			case CKA_LABEL:
				AzvLog("C_GetAttributeValue type: CKA_LABEL");
				char *keyName = AzvGetKeyName();
				byteLen = strlen(keyName);
				if (pTemplate->pValue == NULL_PTR) {
					AzvLog("C_GetAttributeValue pValue is NULL");
					pTemplate->ulValueLen = byteLen;
					return CKR_OK;
				}
				if (pTemplate->ulValueLen < byteLen) {
					AzvLog("C_GetAttributeValue CKA_LABEL length is too small");
					pTemplate->ulValueLen = byteLen;
					return CKR_BUFFER_TOO_SMALL;
				}
				pTemplate->ulValueLen = byteLen;
				//memcpy(pTemplate->pValue, modData, pTemplate->ulValueLen);
				for (int i = 0; i < (int)byteLen; i++) {
					((CK_BYTE*)pTemplate->pValue)[i] = keyName[i];
					printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
				}
				/*
				((CK_BYTE*)pTemplate->pValue)[byteLen-5] = '-';
				if (hObject == MY_CERTIFICATE_HANDLE) {
					((CK_BYTE*)pTemplate->pValue)[byteLen-4] = 'c';
					((CK_BYTE*)pTemplate->pValue)[byteLen-3] = 'r';
					((CK_BYTE*)pTemplate->pValue)[byteLen-2] = 't';
				} else {
					((CK_BYTE*)pTemplate->pValue)[byteLen-4] = 'k';
					((CK_BYTE*)pTemplate->pValue)[byteLen-3] = 'e';
					((CK_BYTE*)pTemplate->pValue)[byteLen-2] = 'y';
				}
				((CK_BYTE*)pTemplate->pValue)[byteLen-1] = '\0';
				printf("\n");
				pTemplate->ulValueLen = 0;
				*/
				break;
			case CKA_ID:
				AzvLog("C_GetAttributeValue type: CKA_ID");
				/*
				pTemplate->ulValueLen = 0;
				return CKR_OK;
				*/
				/*
				*/
				if (hObject == MY_CERTIFICATE_HANDLE && AzvLoadCert() == 0)
				{
					byteLen = AzvGetCertLen();
					if (pTemplate->pValue == NULL_PTR) {
						AzvLog("C_GetAttributeValue pValue is NULL");
						pTemplate->ulValueLen = byteLen;
						return CKR_OK;
					}
					if (pTemplate->ulValueLen < byteLen) {
						AzvLog("C_GetAttributeValue CKA_ID length is too small");
						pTemplate->ulValueLen = byteLen;
						return CKR_BUFFER_TOO_SMALL;
					}
					pTemplate->ulValueLen = byteLen;
					CK_BYTE_PTR certId = (CK_BYTE_PTR)AzvGetCertId();
					if (certId == NULL_PTR) {
						AzvLog("C_GetAttributeValue CKA_ID data is NULL");
						return CKR_FUNCTION_FAILED;
					}
					for (int i = 0; i < (int)byteLen; i++) {
						((CK_BYTE*)pTemplate->pValue)[i] = certId[i];
						printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
					}
					printf("\n");
				}
				if (hObject == MY_PRIVATE_KEY_HANDLE)
				{
					CK_LONG index;
					if ((index = (CK_LONG)AzvGetKeyIndex()) >= 0)
					{
						index += KEY_OFFSET;
						byteLen = 4;
						if (pTemplate->pValue == NULL_PTR) {
							AzvLog("C_GetAttributeValue pValue is NULL");
							pTemplate->ulValueLen = byteLen;
							return CKR_OK;
						}
						if (pTemplate->ulValueLen < byteLen) {
							AzvLog("C_GetAttributeValue CKA_ID length is too small");
							pTemplate->ulValueLen = byteLen;
							return CKR_BUFFER_TOO_SMALL;
						}
						pTemplate->ulValueLen = byteLen;
						CK_BYTE idData[4];
						idData[0] = (CK_BYTE)((index >> 24) & 0xFF);
						idData[1] = (CK_BYTE)((index >> 16) & 0xFF);
						idData[2] = (CK_BYTE)((index >> 8) & 0xFF);
						idData[3] = (CK_BYTE)(index & 0xFF);
						for (int i = 0; i < (int)byteLen; i++) {
							((CK_BYTE*)pTemplate->pValue)[i] = idData[i];
							printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
						}
						printf("\n");
					}
				}
				break;
			case CKA_VALUE:
				AzvLog("C_GetAttributeValue type: CKA_VALUE");
				if (hObject == MY_CERTIFICATE_HANDLE && AzvLoadCert() == 0)
				{
					byteLen = AzvGetCertLen();
					if (pTemplate->pValue == NULL_PTR) {
						AzvLog("C_GetAttributeValue pValue is NULL");
						pTemplate->ulValueLen = byteLen;
						return CKR_OK;
					}
					if (pTemplate->ulValueLen < byteLen) {
						AzvLog("C_GetAttributeValue CKA_VALUE length is too small");
						pTemplate->ulValueLen = byteLen;
						return CKR_BUFFER_TOO_SMALL;
					}
					pTemplate->ulValueLen = byteLen;
					CK_BYTE_PTR certData = (CK_BYTE_PTR)AzvGetCert();
					if (certData == NULL_PTR) {
						AzvLog("C_GetAttributeValue CKA_VALUE data is NULL");
						return CKR_FUNCTION_FAILED;
					}
					for (int i = 0; i < (int)byteLen; i++) {
						((CK_BYTE*)pTemplate->pValue)[i] = certData[i];
						printf("%02x:", ((CK_BYTE*)pTemplate->pValue)[i]);
					}
					printf("\n");
				} else {
					AzvLog("C_GetAttributeValue CKA_VALUE called with unknown handle");
					return CKR_OBJECT_HANDLE_INVALID;
				}
				break;
			default:
			if ((sizeof(CK_BBOOL) == inLen) || (sizeof(CK_ULONG) == inLen)) {
				AzvLog("C_GetAttributeValue - size change, assumed handled earlier");
				break;
			} else {
				AzvLog("C_GetAttributeValue unknown type");
				printf("%lx\n", pTemplate->type);
				break;
			}
	}
	}
	if (pTemplate->pValue == NULL_PTR) {
		AzvLog("C_GetAttributeValue pValue is NULL");
		return CKR_OK;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(hObject);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	AzvLog("C_SetAttributeValue called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	UNUSED(hSession);
	UNUSED(pTemplate);
	UNUSED(ulCount);

	unsigned int isNull = 0;
	if (pTemplate == NULL_PTR) {
		isNull = 1;
	} else if (pTemplate->pValue == NULL_PTR) {
		isNull = 2;
	}

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_FindObjectsInit called with count: 0x%lu, session: %lu, NULL pTemplate: %u", ulCount, hSession, isNull);
	AzvLog(cntString);

	gSessionSearchClass = 0;
	gSessionSearchCount = 0;

	if (pTemplate == NULL_PTR) {
		return CKR_OK;
	} else {
		CK_ULONG ulIndex;
		CK_ATTRIBUTE xAttribute;

		for( ulIndex = 0; ulIndex < ulCount; ulIndex++ )
        {
            xAttribute = pTemplate[ ulIndex ];

			if (xAttribute.type == CKA_CLASS) {
				if (sizeof(CK_OBJECT_CLASS) != xAttribute.ulValueLen) {
					AzvLog("C_FindObjectsInit invalid CKA_CLASS length");
					return CKR_ARGUMENTS_BAD;
				}
				CK_OBJECT_CLASS classValue = *(CK_OBJECT_CLASS *)xAttribute.pValue;
				switch (classValue) {
					case CKO_CERTIFICATE:
						AzvLog("C_FindObjectsInit CK_OBJECT_CLASS=CKO_CERTIFICATE");
						break;
					case CKO_SECRET_KEY:
						AzvLog("C_FindObjectsInit CK_OBJECT_CLASS=CKO_SECRET_KEY");
						break;
					case CKO_PUBLIC_KEY:
						AzvLog("C_FindObjectsInit CK_OBJECT_CLASS=CKO_PUBLIC_KEY");
						break;
					case CKO_PRIVATE_KEY:
						AzvLog("C_FindObjectsInit CK_OBJECT_CLASS=CKO_PRIVATE_KEY");
						break;
					default:	
						AzvLog("C_FindObjectsInit unknown CK_OBJECT_CLASS value");
						return CKR_ARGUMENTS_BAD;
				}
				gSessionSearchClass = classValue;
			}
			if (xAttribute.type == CKA_LABEL) {
				char l[] = "C_FindObjectsInit CKA_LABEL='";
				if ((sizeof(l) + xAttribute.ulValueLen + 1) < sizeof(cntString)) {
					snprintf(cntString, sizeof(l) + xAttribute.ulValueLen+1, "%s%s'", l, (char *)xAttribute.pValue);
				}
				AzvLog(cntString);
			}
			snprintf(cntString, sizeof(cntString), "C_FindObjectsInit template type: 0x%lx, ulValueLen: %lu", xAttribute.type, xAttribute.ulValueLen);
			AzvLog(cntString);
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	UNUSED(hSession);
	UNUSED(phObject);
	UNUSED(ulMaxObjectCount);
	UNUSED(pulObjectCount);

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_FindObjects called with countMax: 0x%lu, session: %lu", ulMaxObjectCount, hSession);
	AzvLog(cntString);

	if (pulObjectCount == NULL_PTR) {
		AzvLog("C_FindObjects called with NULL pulObjectCount");
		return CKR_ARGUMENTS_BAD;
	}

	if (phObject == NULL_PTR) {
		AzvLog("C_FindObjects called with NULL phObject");
		return CKR_ARGUMENTS_BAD;
	}

	*pulObjectCount = 0;
	if (gSessionSearchCount == 0) {
		switch (gSessionSearchClass) {
			case CKO_CERTIFICATE:
				AzvLog("C_FindObjects CKO_CERTIFICATE");
				if (AzvLoadCert() != 0) {
					AzvLog("C_FindObjects CKO_CERTIFICATE failed to load certificate");
					return CKR_OK;
				}
				*phObject = MY_CERTIFICATE_HANDLE;
				break;
			case CKO_PUBLIC_KEY:
				AzvLog("C_FindObjects CKO_PUBLIC_KEY");
				*phObject = MY_PUBLIC_KEY_HANDLE;
				break;
			case CKO_PRIVATE_KEY:
				AzvLog("C_FindObjects CKO_PRIVATE_KEY");
				*phObject = MY_PRIVATE_KEY_HANDLE;
				break;
			default:	
				AzvLog("C_FindObjects unknown CKA_CLASS value");
				return CKR_OK;
		}
		*pulObjectCount = 1;
		gSessionSearchCount = 1;
	/*} else if (gSessionSearchCount == 1) {
		if (gSessionSearchClass == CKO_PRIVATE_KEY) {
			*phObject = MY_CERTIFICATE_HANDLE;
			*pulObjectCount = 1;
			gSessionSearchCount = 2;
		} */
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_FindObjectsFinal called");
	
	gSessionSearchClass = 0;
	gSessionSearchCount = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_EncryptInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pEncryptedData);
	UNUSED(pulEncryptedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastEncryptedPart);
	UNUSED(pulLastEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedData);
	UNUSED(ulEncryptedDataLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	UNUSED(hSession);
	UNUSED(pLastPart);
	UNUSED(pulLastPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	UNUSED(hSession);
	UNUSED(pMechanism);

	AzvLog("C_DigestInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	AzvLog("C_Digest called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	AzvLog("C_DigestUpdate called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(hKey);

	AzvLog("C_DigestKey called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	UNUSED(hSession);
	UNUSED(pDigest);
	UNUSED(pulDigestLen);

	AzvLog("C_DigestFinal called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_SignInit called");
	
	if (pMechanism == NULL_PTR) {
		AzvLog("C_SignInit NULL pMechanism");
		return CKR_ARGUMENTS_BAD;
	}

	gSignLength = 0;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			AzvLog("C_SignInit CKM_RSA_PKCS");
			gSignLength = 512;
			break;
		case CKM_SHA256_RSA_PKCS:
			AzvLog("C_SignInit CKM_SHA256_RSA_PKCS");
			gSignLength = 512;
			break;
		case CKM_SHA512_RSA_PKCS:
			AzvLog("C_SignInit CKM_SHA512_RSA_PKCS");
			gSignLength = 512;
			break;
		default:
			AzvLog("C_SignInit called with unsupported mechanism");
			return CKR_MECHANISM_INVALID;
	}

	gSignMechanism = pMechanism->mechanism;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);

	//AzvLog("C_Sign called");

	if (pData == NULL_PTR || ulDataLen == 0) {
		AzvLog("C_Sign called with NULL pData or zero length");
		return CKR_ARGUMENTS_BAD;
	}

	char cntString[128];
	snprintf(cntString, sizeof(cntString), "C_Sign called with ulDataLen: %lu, session: %lu", ulDataLen, hSession);
	AzvLog(cntString);

	if (pulSignatureLen == NULL_PTR) {
		AzvLog("C_Sign NULL pulSignatureLen");
		return CKR_ARGUMENTS_BAD;
	}

	//printf("SigLen: %lu\n", *pulSignatureLen);

	if (pSignature == NULL_PTR || *pulSignatureLen == 0) {
		AzvLog("C_Sign called with NULL pSignature or pulSignatureLen=0");
		*pulSignatureLen = gSignLength;
		return CKR_OK;
	}

	for (int i = 0; i < (int)ulDataLen; i++) {
		printf("%02x", pData[i]);
	}
	printf("\n");

	if (*pulSignatureLen == gSignLength) {

		CK_ULONG sigLength = 0;
		CK_BYTE_PTR sigData;

		switch (gSignMechanism) {
			case CKM_RSA_PKCS:
				sigData = AzvSign_RSA_PKCS(pData, ulDataLen, &sigLength);
				break;
			case CKM_SHA256_RSA_PKCS:
				sigData = AzvSign_SHA256_RSA_PKCS(pData, ulDataLen, &sigLength);
				break;
			default:
				AzvLog("C_Sign called with unsupported mechanism");
				return CKR_MECHANISM_INVALID;
		}

		if (sigLength != *pulSignatureLen) {
			return CKR_SIGNATURE_LEN_RANGE;
		}

		for (int i = 0; i < (int)sigLength; i++) {
			pSignature[i] = sigData[i];
			printf("%02x", sigData[i]);
		}
		printf("\nSigLen: %lu\n", sigLength);
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	AzvLog("C_SignUpdate called");

	if (pPart == NULL_PTR || ulPartLen == 0) {
		AzvLog("C_SignUpdate called with NULL pPart or zero length");
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	AzvLog("C_SignFinal called");
	gSignLength = 0;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_SignRecoverInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	AzvLog("C_SignRecover called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_VerifyInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	AzvLog("C_Verify called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);

	AzvLog("C_VerifyUpdate called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	AzvLog("C_VerifyFinal called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_VerifyRecoverInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	UNUSED(hSession);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);
	UNUSED(pData);
	UNUSED(pulDataLen);

	AzvLog("C_VerifyRecover called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	UNUSED(hSession);
	UNUSED(pPart);
	UNUSED(ulPartLen);
	UNUSED(pEncryptedPart);
	UNUSED(pulEncryptedPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	UNUSED(hSession);
	UNUSED(pEncryptedPart);
	UNUSED(ulEncryptedPartLen);
	UNUSED(pPart);
	UNUSED(pulPartLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pTemplate);
	UNUSED(ulCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(pPublicKeyTemplate);
	UNUSED(ulPublicKeyAttributeCount);
	UNUSED(pPrivateKeyTemplate);
	UNUSED(ulPrivateKeyAttributeCount);
	UNUSED(phPublicKey);
	UNUSED(phPrivateKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hWrappingKey);
	UNUSED(hKey);
	UNUSED(pWrappedKey);
	UNUSED(pulWrappedKeyLen);
	
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hUnwrappingKey);
	UNUSED(pWrappedKey);
	UNUSED(ulWrappedKeyLen);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hBaseKey);
	UNUSED(pTemplate);
	UNUSED(ulAttributeCount);
	UNUSED(phKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	UNUSED(hSession);
	UNUSED(pSeed);
	UNUSED(ulSeedLen);

	AzvLog("C_SeedRandom called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	UNUSED(hSession);
	UNUSED(RandomData);
	UNUSED(ulRandomLen);

	AzvLog("C_GenerateRandom called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_GetFunctionStatus called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_CancelFunction called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	UNUSED(flags);
	UNUSED(pSlot);
	UNUSED(pReserved);

	AzvLog("C_WaitForSlotEvent called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterfaceList)(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pInterfacesList)
	{
		*pulCount = 2;
	}
	else
	{
		if (*pulCount < 2)
			return CKR_BUFFER_TOO_SMALL;

		pInterfacesList[0].pInterfaceName = empty_pkcs11_2_40_interface.pInterfaceName;
		pInterfacesList[0].pFunctionList = empty_pkcs11_2_40_interface.pFunctionList;
		pInterfacesList[0].flags = empty_pkcs11_2_40_interface.flags;

		pInterfacesList[1].pInterfaceName = empty_pkcs11_3_1_interface.pInterfaceName;
		pInterfacesList[1].pFunctionList = empty_pkcs11_3_1_interface.pFunctionList;
		pInterfacesList[1].flags = empty_pkcs11_3_1_interface.flags;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInterface)(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion, CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	if (NULL == ppInterface)
		return CKR_ARGUMENTS_BAD;

	if (flags != 0)
	{
		*ppInterface = NULL;
		return CKR_OK;
	}

	if (NULL != pInterfaceName)
	{
		const char* requested_interface_name = (const char*)pInterfaceName;
		const char* supported_interface_name = "PKCS 11";

		if (strlen(requested_interface_name) != strlen(supported_interface_name) || 0 != strcmp(requested_interface_name, supported_interface_name))
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	if (NULL != pVersion)
	{
		if (pVersion->major == empty_pkcs11_2_40_functions.version.major && pVersion->minor == empty_pkcs11_2_40_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_2_40_interface;
			return CKR_OK;
		}
		else if (pVersion->major == empty_pkcs11_3_1_functions.version.major && pVersion->minor == empty_pkcs11_3_1_functions.version.minor)
		{
			*ppInterface = &empty_pkcs11_3_1_interface;
			return CKR_OK;
		}
		else
		{
			*ppInterface = NULL;
			return CKR_OK;
		}
	}

	*ppInterface = &empty_pkcs11_3_1_interface;
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_LoginUser)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	UNUSED(hSession);
	UNUSED(userType);
	UNUSED(pPin);
	UNUSED(ulPinLen);
	UNUSED(pUsername);
	UNUSED(ulUsernameLen);

	AzvLog("C_LoginUser called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SessionCancel)(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(flags);

	AzvLog("C_SessionCancel called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pPlaintext);
	UNUSED(ulPlaintextLen);
	UNUSED(pCiphertext);
	UNUSED(pulCiphertextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pPlaintextPart);
	UNUSED(ulPlaintextPartLen);
	UNUSED(pCiphertextPart);
	UNUSED(pulCiphertextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageEncryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);
	UNUSED(pCiphertext);
	UNUSED(ulCiphertextLen);
	UNUSED(pPlaintext);
	UNUSED(pulPlaintextLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pAssociatedData);
	UNUSED(ulAssociatedDataLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen, CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pCiphertextPart);
	UNUSED(ulCiphertextPartLen);
	UNUSED(pPlaintextPart);
	UNUSED(pulPlaintextPartLen);
	UNUSED(flags);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageDecryptFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	AzvLog("C_MessageSignInit called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	AzvLog("C_SignMessage called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	AzvLog("C_SignMessageBegin called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(pulSignatureLen);

	AzvLog("C_SignMessageNext called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageSignFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	AzvLog("C_MessageSignFinal called");

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	UNUSED(hSession);
	UNUSED(pMechanism);
	UNUSED(hKey);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessage)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageBegin)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyMessageNext)(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	UNUSED(hSession);
	UNUSED(pParameter);
	UNUSED(ulParameterLen);
	UNUSED(pData);
	UNUSED(ulDataLen);
	UNUSED(pSignature);
	UNUSED(ulSignatureLen);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_MessageVerifyFinal)(CK_SESSION_HANDLE hSession)
{
	UNUSED(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}
