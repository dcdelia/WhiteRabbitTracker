#include "wmi.h"
#include <iostream>
using namespace std;

static W::HRESULT(WINAPI* pSafeArrayAccessData)(W::SAFEARRAY* psa, void HUGEP** ppvData);
static W::HRESULT(WINAPI* pSafeArrayGetLBound)(W::SAFEARRAY* psa, UINT nDim, W::LONG* plLbound);
static W::HRESULT(WINAPI* pSafeArrayGetUBound)(W::SAFEARRAY* psa, UINT nDim, W::LONG* plUbound);
static W::HRESULT(WINAPI* pSafeArrayGetElement)(W::SAFEARRAY* psa, W::LONG* rgIndices, void* pv);

VOID WMI_Patch(iclock_t &clock, W::LPCWSTR query, W::VARIANT* var, LoggingInfo* logInfo) {

	// Get the data from the query
	if (var == NULL) 
		return;

	if ((var)->n1.n2.vt != W::VT_NULL) {

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(query, value, PATH_BUFSIZE);

		char logName[256] = "WMI-Get ";

		// TODO FILENAME case?

		if (strstr(value, "NUMBEROFCORES") != NULL) {
			//set N cores in the machine
			var->n1.n2.n3.uintVal = BP_NUMCORES;
			strcat(logName, value);
			logInfo->logBypass(clock, logName);
		}

		else if (strstr(value, "SIZE") != NULL) {
			//set new size of HDD
			var->n1.n2.n3.llVal = (BP_DISKSIZE * (1024LL * (1024LL * (1024LL))));
			strcat(logName, value);
			logInfo->logBypass(clock, logName);
		}

		else if (strstr(value, "DEVICEID") != NULL) {
			//set the new device ID
			if (wcsstr(var->n1.n2.n3.bstrVal, L"PCI\\VEN_80EE&DEV_CAFE")) {
				memset(var->n1.n2.n3.bstrVal, 0, wcslen(var->n1.n2.n3.bstrVal) * 2);
				wcscpy(var->n1.n2.n3.bstrVal, BP_ACPIDEV);
				sprintf(logName, "%s PCI\\VEN_80EE&DEV_CAFE", value);
				logInfo->logBypass(clock, logName);
			}
		}

		else if (strstr(value, "MACADDRESS") != NULL) {
			//set new MAC Address
			memset(var->n1.n2.n3.bstrVal, 0, wcslen(var->n1.n2.n3.bstrVal) * 2);
			wcscpy(var->n1.n2.n3.bstrVal, BP_MACADDR);
			strcat(logName, value);
			logInfo->logBypass(clock, logName);
		}

		else if (strstr(value, "MUILANGUAGES") != NULL) {
			//MUI language string
			W::HMODULE hmod = W::LoadLibraryA("OleAut32.dll");
			*(W::FARPROC*)&pSafeArrayAccessData = W::GetProcAddress(hmod, "SafeArrayAccessData");
			*(W::FARPROC*)&pSafeArrayGetLBound = W::GetProcAddress(hmod, "SafeArrayGetLBound");
			*(W::FARPROC*)&pSafeArrayGetUBound = W::GetProcAddress(hmod, "SafeArrayGetUBound");
			*(W::FARPROC*)&pSafeArrayGetElement = W::GetProcAddress(hmod, "SafeArrayGetElement");

			W::SAFEARRAY* saSources = var->n1.n2.n3.parray;
			W::LONG* pVals;
			W::HRESULT hr = pSafeArrayAccessData(saSources, (VOID**)&pVals); // direct access to SA memory

			if (SUCCEEDEDNEW(hr)) {
				W::LONG lowerBound, upperBound;
				pSafeArrayGetLBound(saSources, 1, &lowerBound);
				pSafeArrayGetUBound(saSources, 1, &upperBound);
				W::LONG iLength = upperBound - lowerBound + 1;

				// iterate over our array of BTSR
				W::TCHAR* bstrItem;
				for (W::LONG ix = 0; ix < iLength; ix++) {
					pSafeArrayGetElement(saSources, &ix, (void*)&bstrItem);

					char value1[PATH_BUFSIZE];
					GET_WSTR_TO_UPPER(bstrItem, value1, PATH_BUFSIZE);

					if (strcmp(value1, "EN-US") == 0) {
						long* pData = (long*)saSources->pvData + ix;

						memset((char*)*pData, 0, strlen((char*)*pData));
						PIN_SafeCopy((char*)*pData, BP_MUI, strlen(BP_MUI));

						strcat(logName, value);
						logInfo->logBypass(clock, logName);
					}
				}
			}
		}

		else if (strstr(value, "SOURCES") != NULL) {
			//clean NTLog file
			W::HMODULE hmod = W::LoadLibraryA("OleAut32.dll");
			*(W::FARPROC*)&pSafeArrayAccessData = W::GetProcAddress(hmod, "SafeArrayAccessData");
			*(W::FARPROC*)&pSafeArrayGetLBound = W::GetProcAddress(hmod, "SafeArrayGetLBound");
			*(W::FARPROC*)&pSafeArrayGetUBound = W::GetProcAddress(hmod, "SafeArrayGetUBound");
			*(W::FARPROC*)&pSafeArrayGetElement = W::GetProcAddress(hmod, "SafeArrayGetElement");

			W::SAFEARRAY* saSources = var->n1.n2.n3.parray;
			W::LONG* pVals;
			W::HRESULT hr = pSafeArrayAccessData(saSources, (VOID**)&pVals); // direct access to SA memory

			if (SUCCEEDEDNEW(hr)) {
				W::LONG lowerBound, upperBound;
				pSafeArrayGetLBound(saSources, 1, &lowerBound);
				pSafeArrayGetUBound(saSources, 1, &upperBound);
				W::LONG iLength = upperBound - lowerBound + 1;

				// iterate over our array of BTSR
				W::TCHAR* bstrItem;
				for (W::LONG ix = 0; ix < iLength; ix++) {
					pSafeArrayGetElement(saSources, &ix, (void*)&bstrItem);

					char value1[PATH_BUFSIZE];
					GET_WSTR_TO_UPPER(bstrItem, value1, PATH_BUFSIZE);

					if (strcmp(value1, "VBOXVIDEO") == 0) {
						sprintf(logName, "%s %s", value, value);
						logInfo->logBypass(clock, logName);

						long* pData = (long*)saSources->pvData + ix;

						memset((char*)*pData, 0, strlen((char*)*pData));
						PIN_SafeCopy((char*)*pData, FALSESTR, strlen(FALSESTR));
					}
				}
			}
		}
	}
}
