#pragma once
#include "functions.h"
#include "types.h"
#include "process.h"
#include "helper.h"
#include "HiddenElements.h"
#include "LoggingInfo.h"
#include "taint.h"
#include "bypass.h"
#include "state.h"
#include <string>
#include <iostream>


/* ============================================================================= */
/* Define macro to check the return address in ESP and check if is program code  */
/* ============================================================================= */
#define CHECK_ESP_RETURN_ADDRESS(esp_pointer) do { \
ADDRINT espValue = *((ADDRINT*) esp_pointer); \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, espValue); \
if(node != NULL) return; \
} while (0)


extern LoggingInfo* logInfo; // TODO why not Functions::?

namespace Functions {
	// TODO make this visible outside
	std::map<const char*, int> apiCallCounts;

	static std::map<std::string, int> fLoggingMap; // other hooks - see loghooks.cpp

	// main source: malapi.io + custom filtering
	static const char* apiname_only[] = {
		// processes
		"CreateProcessA","CreateRemoteThread","CreateRemoteThreadEx","NtCreateProcess",
		"NtCreateProcessEx","NtCreateUserProcess","CreateThread", //"SetThreadPriority",
		"NtSetContextThread","NtSetInformationProcess","NtSetInformationThread",
		"TerminateProcess","TerminateThread","NtTerminateProcess","NtTerminateThread",
		"RtlSetProcessIsCritical","Wow64SetThreadContext","SetThreadContext",
		"NtSuspendProcess","NtResumeProcess","KeInsertQueueApc","QueueUserAPC",
		"SetProcessDEPPolicy","SetThreadContext","SuspendThread","ResumeThread",
		"AdjustTokenPrivileges","NtAdjustPrivilegesToken","CreateProcessWithTokenW",
		"NtResumeThread","NtQueueApcThread","NtQueueApcThreadEx","NtQueueApcThreadEx2",
		// service stuff
		"ControlService","ControlServiceExA","CreateServiceA","DeleteService",
		"OpenSCManagerA","OpenServiceA","StartServiceA","StartServiceCtrlDispatcherA",
		// registry stuff
		"RegCreateKeyExA","RegCreateKeyA","RegSetValueExA","RegSetKeyValueA",
		"RegDeleteValueA","RegFlushKey","RegLoadKeyA","RegOpenKeyTransactedA",
		"RegOpenUserClassesRoot","RegOverridePredefKey","RegReplaceKeyA",
		"RegRestoreKeyA","RegSaveKeyA","RegSaveKeyExA","RegSetKeySecurity",
		"RegUnLoadKeyA","RegConnectRegistryA","RegCopyTreeA","RegCreateKeyTransactedA",
		"RegDeleteKeyA","RegDeleteKeyExA", "RegDeleteKeyTransactedA", "RegDeleteKeyValueA",
		"RegDeleteTreeA", "RegDeleteValueA", "NtDeleteKey","NtDeleteValueKey","NtSetValueKey",
		// crypto stuff
		"CryptAcquireContextA","EncryptFileA","CryptEncrypt","CryptDecrypt",
		"CryptCreateHash","CryptHashData","CryptDeriveKey","CryptSetKeyParam",
		"CryptGetHashParam","CryptSetKeyParam","CryptDestroyKey","CryptGenRandom",
		"DecryptFileA","FlushEfsCache","CryptStringToBinary","CryptBinaryToString",
		"CryptReleaseContext","CryptDestroyHash",
		// files
		"ConnectNamedPipe","CopyFileA","GetTempPathA","MoveFileA","MoveFileExA",
		"PeekNamedPipe","WriteFile","CopyFile2","CopyFileExA","GetTempFileNameA",
		"CreatePipe","SetFileTime"
		// injection (see non-self hooks for more)
		"MapViewOfFile","NtMapViewOfSection","NtDuplicateObject","DuplicateHandle",
		// GUI & spying
		"CallWindowProcA","ShowWindow","OpenClipboard","SetForegroundWindow",
		"BringWindowToTop","SetFocus","DrawTextExA","GetDesktopWindow",
		"SetClipboardData","SetWindowLongA","SetWindowLongPtrA",
		"AttachThreadInput","CallNextHookEx","GetAsyncKeyState","GetClipboardData",
		"GetDC","GetDCEx","GetForegroundWindow","GetKeyboardState","GetKeyState",
		"GetMessageA","GetRawInputData","GetWindowDC","MapVirtualKeyA","MapVirtualKeyExA",
		"PeekMessageA","PostMessageA","PostThreadMessageA","RegisterHotKey",
		"RegisterRawInputDevices","SendMessageA","SendMessageCallbackA",
		"SendMessageTimeoutA","SendNotifyMessageA","SetWindowsHookExA",
		"SetWinEventHook","UnhookWindowsHookEx","BitBlt","StretchBlt","GetKeynameTextA",
		"CreateWindowExA","SetPropA",
		// misc
		"NtSetSystemEnvironmentValueEx","SetEnvironmentVariableA",
		"ImpersonateLoggedOnUser","SetThreadToken",
		"NetShareSetInfo","NetShareAdd","WNetAddConnection2A",
		// undecided
		// DeleteFileA NtMakeTemporaryObject SetCurrentDirectory NtContinue
	};

	typedef struct {
		const char* name;
		uint8_t handle_arg_idx;
	} api_filter_self_t;

	static const api_filter_self_t apinames_if_not_self[] = {
		{ "ReadProcessMemory", 0 },
		{ "NtAllocateVirtualMemory", 0 },
		{ "VirtualAllocEx", 0 },
		{ "VirtualAllocExNuma", 0 },
		{ "WriteProcessMemory", 0 },
		{ "NtUnmapViewOfSection", 0 },
		{ "NtWriteVirtualMemory", 0 },
		{ "NtReadVirtualMemory", 0 },
		{ "NtProtectVirtualMemory", 0}
	};

	void InitLoggingHooks() {
		// hooks for logging
		for (size_t i = 0; i < sizeof(apiname_only) / sizeof(apiname_only[0]); ++i) {
			fLoggingMap.insert(std::pair<std::string, int>(apiname_only[i], LOG_IOC_APINAME_ONLY));
		}
		for (size_t i = 0; i < sizeof(apinames_if_not_self) / sizeof(apinames_if_not_self[0]); ++i) {
			fLoggingMap.insert(std::pair<std::string, int>(apinames_if_not_self[i].name, LOG_IOC_APINAME_IF_NOT_SELF));
		}

		// hooks for string functions (selective logging)
		if (!_knobApiTracing) return;

		fLoggingMap.insert(std::pair<std::string, int>("RtlCompareUnicodeString", LOG_RTLSTR));
		fLoggingMap.insert(std::pair<std::string, int>("RtlEqualUnicodeString", LOG_RTLSTR));

		fLoggingMap.insert(std::pair<std::string, int>("wcsstr", LOG_WCPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("wcscmp", LOG_WCPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("wcsncmp", LOG_WCPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("_wcsnicmp", LOG_WCPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("StrCmpIW", LOG_WCPAIR_ONETWO));
		
		fLoggingMap.insert(std::pair<std::string, int>("strstr", LOG_CPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("strcmp", LOG_CPAIR_ONETWO));
		fLoggingMap.insert(std::pair<std::string, int>("_strcmpi", LOG_CPAIR_ONETWO));


		// TODO check what breaks with A... likely will happen
		fLoggingMap.insert(std::pair<std::string, int>("CompareString", LOG_KCMPSTR)); // Pin?
		fLoggingMap.insert(std::pair<std::string, int>("CompareStringA", LOG_KCMPSTR));
		fLoggingMap.insert(std::pair<std::string, int>("CompareStringW", LOG_KCMPSTR));
		fLoggingMap.insert(std::pair<std::string, int>("CompareStringEx", LOG_KCMPSTR));
		fLoggingMap.insert(std::pair<std::string, int>("CompareStringExA", LOG_KCMPSTR)); // Pin?
		fLoggingMap.insert(std::pair<std::string, int>("CompareStringExW", LOG_KCMPSTR));
		// TODO CompareStringOrdinal (-1 on arguments)
	}

	static int lookupArgForAPINotSelf(const char* name) {
		for (size_t i = 0; i < sizeof(apinames_if_not_self) / sizeof(apinames_if_not_self[0]); ++i) {
			const api_filter_self_t* item = &apinames_if_not_self[i];
			if (!strcmp(name, item->name)) return item->handle_arg_idx;
		}
	}

	void AddLoggingHooks(IMG img) {
		for (std::map<std::string, int>::iterator it = fLoggingMap.begin(), end = fLoggingMap.end(); it != end; ++it) {
			// Get the function name 
			const char* func_name = it->first.c_str();
			// Get a pointer to the function
			RTN rtn = RTN_FindByName(img, func_name);
			// Check if the routine (function) is valid
			if (rtn != RTN_Invalid()) {
				int index = it->second;
				// Open the routine
				RTN_Open(rtn);
				switch (index) {
				case(LOG_IOC_APINAME_ONLY):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LogFunctionByName,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_PTR, func_name,
						IARG_END);
					break;
				case(LOG_IOC_APINAME_IF_NOT_SELF):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)LogFunctionIfNotSelfByName,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_PTR, func_name,
						IARG_END);
					break;
				case(LOG_RTLSTR):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LogTwoUnicodeStrings,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_PTR, func_name,
						IARG_END);
					break;
				case(LOG_KCMPSTR):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LogTwoWcharStrings,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
						IARG_PTR, func_name,
						IARG_END);
					break;
				case(LOG_WCPAIR_ONETWO):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LogTwoWcharStrings,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_PTR, func_name,
						IARG_END);
					break;
				case(LOG_CPAIR_ONETWO):
					RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)LogTwoCharStrings,
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_PTR, func_name,
						IARG_END);
					break;
				default: break;
				}
				// Close the routine
				RTN_Close(rtn);
			}
		}

	}
}

/* Special-purpose logging hooks */

VOID LogFunctionIfNotSelfByName(ADDRINT esp, W::HANDLE hProcess, const char* name) {
	if (hProcess == (W::HANDLE)-1) return;
	CHECK_ESP_RETURN_ADDRESS(esp);
	if (!Functions::apiCallCounts[name]++) { // only on first invocation
		logInfo->logMisc(name);
	}
}

VOID LogFunctionByName(ADDRINT esp, const char* name) {
	CHECK_ESP_RETURN_ADDRESS(esp);
	if (!Functions::apiCallCounts[name]++) { // only on first invocation
		logInfo->logMisc(name);
	}
}


#define WBUFSIZE	(2*MAX_PATH*sizeof(wchar_t)+64) // 64 for API name and other stuff
#define SBUFSIZE	(2*MAX_PATH+64)


static VOID LogInvalidArgs(const char* apiname) {
	char buf[64];
	sprintf(buf, "%s with invalid args", apiname);
	logInfo->logMisc(buf);
}

VOID LogTwoUnicodeStrings(ADDRINT esp, W::PCUNICODE_STRING s1, W::PCUNICODE_STRING s2, const char* apiname) {
	if (!_alertApiTracingCounter) return;
	CHECK_ESP_RETURN_ADDRESS(esp);

	if (s1 || s2) { // print either argument
		char buf[WBUFSIZE];
		char* p = buf;
		int len = sprintf(buf, "%s", apiname);
		p += len;
		if (s1) {
			*p++ = ' ';
			len = wcstombs(p, s1->Buffer, s1->Length);
			if (len != -1) p += len;
		}
		if (s2) {
			*p++ = ' ';
			len = wcstombs(p, s2->Buffer, s2->Length);
			if (len != -1) p += len;
		}
		*p = '\0';
		logInfo->logMisc(buf);
	}
	else LogInvalidArgs(apiname);
}

VOID LogTwoWcharStrings(ADDRINT esp, W::LPCWCH s1, W::LPCWCH s2, const char* apiname) {
	if (!_alertApiTracingCounter) return;
	CHECK_ESP_RETURN_ADDRESS(esp);

	if (s1 || s2) { // print either argument
		char buf[WBUFSIZE];
		char* p = buf;
		int len = sprintf(buf, "%s", apiname);
		p += len;
		if (s1) {
			*p++ = ' ';
			len = wcstombs(p, s1, MAX_PATH);
			if (len != -1) p += len;
		}
		if (s2) {
			*p++ = ' ';
			len = wcstombs(p, s2, MAX_PATH);
			if (len != -1) p += len;
		}
		*p = '\0';
		logInfo->logMisc(buf);
	}
	else LogInvalidArgs(apiname);
}

VOID LogTwoCharStrings(ADDRINT esp, const char* s1, const char* s2, const char* apiname) {
	if (!_alertApiTracingCounter) return;
	CHECK_ESP_RETURN_ADDRESS(esp);

	if (s1 || s2) { // print either argument
		char buf[SBUFSIZE];
		if (s1 && s2) {
			sprintf(buf, "%s %s %s", apiname, s1, s2);
		}
		else if (s1) {
			sprintf(buf, "%s %s", apiname, s1);
		}
		else {
			sprintf(buf, "%s %s", apiname, s2);
		}
		// common path
		logInfo->logMisc(buf);
	}
	else LogInvalidArgs(apiname);
}
