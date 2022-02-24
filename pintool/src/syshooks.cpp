#include "syshooks.h"
#include "memory.h"
#include "state.h"
#include "HiddenElements.h"
#include "taint.h"
#include "helper.h"
#include "bypass.h"

/* ============================================================================= */
/* Define macro to get reference/copy clock to information from CONTEXT object   */
/* ============================================================================= */
extern REG thread_ctx_ptr;
#define GET_INTERNAL_CLOCK(ctx) (((thread_ctx_t*)PIN_GetContextReg(ctx, thread_ctx_ptr))->clock)

namespace SYSHOOKS {

	/* ===================================================================== */
	/* Obtain where a ntdll syscall stub would return                        */
	/* ===================================================================== */
	static ADDRINT getRAfromNtdllStub(ADDRINT* esp) {
		State::globalState* gs = State::getGlobalState();
		ADDRINT addr = *esp;
		if (addr < gs->ntdll_start || addr > gs->ntdll_end) return NULL; // direct syscall

		uint8_t bytes[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		PIN_SafeCopy(bytes, (void*)addr, 6);

		// credits: https://github.com/dcdelia/sniper/blob/master/DBI/src/syscalls.cpp
		ADDRINT ra;
		if (bytes[0] == 0xC2 || bytes[0] == 0xC3) {
			ra = *esp;
		}
		else {
			if (!(bytes[0] == 0x83 && bytes[1] == 0xC4 && bytes[2] == 0x04)) {
				fprintf(stderr, "Didn't meet an add esp, 4 but those instead: %x%x%x\n",
					(unsigned char)bytes[0], (unsigned char)bytes[1], (unsigned char)bytes[2]);
				return NULL;
			}
			if (!(bytes[3] == 0xC2 || bytes[3] == 0xC3)) { // TODO also byte[5] == 0 for C3?
				fprintf(stderr, "Didn't meet a retn [??] but those instead: %x%x%x\n",
					(unsigned char)bytes[3], (unsigned char)bytes[4], (unsigned char)bytes[5]);
				return NULL;
			}
			// the RA for the caller will be at ESP+4
			ra = *((ADDRINT*)esp + 1);
		}

		return ra;
	}

	/* ===================================================================== */
	/* Workaround for IcmpSendEcho* missed by Pin                            */
	/* ===================================================================== */

	// Win7 SP1 WoW64 values
#define ICMP_SENDECHO2EX_RET_OFFSET	0x85E9
#define ICMP_SENDECHO2_RET_OFFSET	0x8768
#define ICMP_SENDECHO_RET_OFFSET	0x8732

	W::LARGE_INTEGER NtWFSO_timeout;

	VOID NtWaitForSingleObject_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		if (!BYPASS(BP_ICMPSENDECHO)) return;

		// TODO for now it will be Win7-WOW64-specific
		ADDRINT *esp = (ADDRINT*)PIN_GetContextReg(ctx, REG_STACK_PTR);
		
		ADDRINT raFromNtdll = getRAfromNtdllStub(esp);
		if (!raFromNtdll) return;

		State::globalState* gs = State::getGlobalState();

		if (raFromNtdll == gs->iphlpapi_start + ICMP_SENDECHO2EX_RET_OFFSET) {
			ADDRINT ebp = PIN_GetContextReg(ctx, REG_GBP);
			ADDRINT retToCaller = *(ADDRINT*)(ebp+4);
			
			// internal call from IcmpSendEcho2
			if (retToCaller == gs->iphlpapi_start + ICMP_SENDECHO2_RET_OFFSET) {
				// ret 0x30 upon leaving, then there is only a pop ebp before ret 2c
				retToCaller = *(ADDRINT*)(ebp + 4 + 0x30 + 8);
				// further walk up if from IcmpSendEcho
				if (retToCaller == gs->iphlpapi_start + ICMP_SENDECHO_RET_OFFSET) {
					// ret 0x2c upon leaving, then there is only a pop ebp before ret 20
					retToCaller = *(ADDRINT*)(ebp + 4 + 0x30 + 8 + 4 + 0x2c + 4);
				}
			}
			
			if (!itree_search(gs->dllRangeITree, retToCaller)) { // from program code
				//fprintf(stderr, "Call to IcmpSendEcho* from program code returning to %x\n", retToCaller);
				//fprintf(stderr, "Third argument for NtWaitForSingleObject: %d\n", sc->arg2);
				if (sc->arg2 == 0) {
					PIN_SetSyscallArgument(ctx, std, 2, (ADDRINT)&NtWFSO_timeout);
					NtWFSO_timeout.LowPart = BP_ICMP_ECHO;
					NtWFSO_timeout.HighPart = 0;				
				}
			}
		}
	}

	/* ===================================================================== */
	/* NtQueryObject - Transplanted from BluePill                            */
	/* ===================================================================== */
	VOID NtQueryObject_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		// TODO: BYPASS and proper handling of ntQueryCounter
		if (sc->arg1 == 3) { // credits: Al-Khaser
			FetchGlobalState;
			gs->ntQueryCounter = (gs->ntQueryCounter + 1) % 2;

			if (gs->ntQueryCounter != 0)
				return;

			POBJECT_ALL_INFORMATION pObjectAllInfo = (POBJECT_ALL_INFORMATION)sc->arg2;
			W::ULONG NumObjects = pObjectAllInfo->NumberOfObjects;
			W::UCHAR* pObjInfoLocation = (W::UCHAR*)pObjectAllInfo->ObjectTypeInformation;

			for (UINT i = 0; i < NumObjects; i++) {

				POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

				if (wcscmp(L"DebugObject", pObjectTypeInfo->TypeName.Buffer) == 0) {
					if (pObjectTypeInfo->TotalNumberOfObjects > 0) {
						logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NtQueryObject");
						pObjectTypeInfo->TotalNumberOfObjects = 0;
					}
				}

				pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

				pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

				// TODO check this
				W::ULONG_PTR tmp = ((W::ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

				if ((W::ULONG_PTR)tmp != (W::ULONG_PTR)pObjInfoLocation)
					tmp += sizeof(void*);
				pObjInfoLocation = ((unsigned char*)tmp);
			}
		}

	}

	/* ===================================================================== */
	/* Handle the NtDelayExecution API                                       */
	/* ===================================================================== */
	VOID NtDelayexecution_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		if (!BYPASS(BP_NTDELAYEXEC)) return;

		W::LARGE_INTEGER* li = (W::LARGE_INTEGER*)sc->arg1;
		W::UINT ll = (-li->QuadPart) / 10000LL;
		if (ll == 0 || ll > 1000000000)
			return;

		FetchTimeState;
		tinfo->sleepMs += ll;
		tinfo->sleepMsTick += ll;
		if (tinfo->lastMs == ll) {
			tinfo->numLastMs++;
		}
		else {
			tinfo->lastMs = ll;
			tinfo->numLastMs = 0;
		}

		// Reset the sleep value
		if (tinfo->numLastMs >= 5) {
			li->QuadPart = 0;
		}
		else {
			if (tinfo->sleepTime == 0)
				li->QuadPart = -BP_TIMER * 10000LL;
			else
				li->QuadPart = -tinfo->sleepTime * 10000LL;
		}
	}

	/* ===================================================================== */
	/* Handle the NtCreateFile API (Virtualbox/VMware files access)          */
	/* ===================================================================== */
	VOID NtCreateFile_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES *Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); 
		apiOutputs->ntCreateFileBuffer = p->Buffer;
		if (BYPASS(BP_NTCREATEFILE) && HiddenElements::shouldHideGenericFileNameStr(value)) {
			char logName[PATH_BUFSIZE] = "NtCreateFile ";
			strcat(logName, value);
			logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
			//VBOXGUEST pass for Obsidium anti-vm and anti-dbi
			char* defaultGenericFilenames[] = { "VBOXGUEST", NULL };
			if (lookupSubstring(value, defaultGenericFilenames) && mode == 1) {
				apiOutputs->obsidiumCreateFile = true;
			}
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				memcpy((char*)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
				PIN_SafeCopy((char*)p->Buffer + i, WSTR_CREATEFILE, sizeof(wchar_t));
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtCreateFile API (Virtualbox/VMware files access)          */
	/* ===================================================================== */
	VOID NtCreateFile_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::PHANDLE handle = (W::PHANDLE)sc->arg0;
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg2;
		W::ULONG mode = (W::ULONG)sc->arg7;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(apiOutputs->ntCreateFileBuffer, value, PATH_BUFSIZE);
		if (HiddenElements::shouldHideGenericFileNameStr(value)) {
			// High false positive rate, taint only suspicious files
			uint8_t color = GET_TAINT_COLOR(TT_NTCREATEFILE);
			if (color) {
				logHookId(ctx, "NtCreateFile", (ADDRINT)handle, sizeof(W::HANDLE));
				addTaintMemory(ctx, (ADDRINT)handle, sizeof(W::HANDLE), color, true, "NtCreateFile");
			}
			if (apiOutputs->obsidiumCreateFile && BYPASS(BP_NTCREATEFILE)) {
				PIN_SetContextReg(ctx, REG_GAX, -1);
				apiOutputs->obsidiumCreateFile = false;
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtOpenKey API (registry access)                            */
	/* ===================================================================== */
	VOID NtOpenKey_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::PHANDLE khandle = (W::PHANDLE)sc->arg0;
		if (khandle == nullptr)
			return;

		OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES*)sc->arg2;
		W::PWSTR path = oa->ObjectName->Buffer;

		if (PIN_GetContextReg(ctx, REG_GAX) != ERROR_SUCCESS || path == NULL || *path == NULL)
			return;

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(path, value, PATH_BUFSIZE);
		if (HiddenElements::shouldHideRegOpenKeyStr(value)) { // for sensitive keys only
			// Free right handle
			if (BYPASS(BP_NTOPENKEY)) {
				char logName[PATH_BUFSIZE] = "NtOpenKey ";
				strcat(logName, value);
				logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
				W::CloseHandle(*khandle);
				*khandle = (W::HANDLE) - 1;
				ADDRINT _eax = CODEFORINVALIDHANDLE;
				PIN_SetContextReg(ctx, REG_GAX, _eax);
			}
			uint8_t color = GET_TAINT_COLOR(TT_NTOPENKEY);
			if (color) {
				// Taint registry handler
				TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);
				// High false positive rate, taint only suspicious registry access
				logHookId(ctx, "NtOpenKey", (ADDRINT)khandle, sizeof(W::HANDLE));
				addTaintMemory(ctx, (ADDRINT)khandle, sizeof(W::HANDLE), color, true, "NtOpenKey");
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtEnumerateKey API (registry access)                       */
	/* ===================================================================== */
	VOID NtEnumerateKey_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		KEY_INFORMATION_CLASS cl = (KEY_INFORMATION_CLASS)sc->arg2;
		if (cl == KeyBasicInformation) {
			PKEY_BASIC_INFORMATION str = (PKEY_BASIC_INFORMATION)sc->arg3;
			char value[PATH_BUFSIZE];
			GET_STR_TO_UPPER(str->Name, value, PATH_BUFSIZE);
			if (HiddenElements::shouldHideReqQueryValueStr(value)) { // for sensitive keys only
				if (BYPASS(BP_NTENUMKEY)) {
					char logName[256] = "NtEnumerateKey ";
					strcat(logName, value);
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
					for (W::USHORT i = 0; i < str->NameLength - 1; i += 2) {
						PIN_SafeCopy((char*)str->Name + i, WSTR_REGKEYORVAL, sizeof(wchar_t));
					}
				}
				uint8_t color = GET_TAINT_COLOR(TT_NTENUMERATEKEY);
				if (color) {
					// High false positive rate, taint only suspicious registry access
					logHookId(ctx, "NtEnumerateKey", (ADDRINT)str->Name, str->NameLength);
					addTaintMemory(ctx, (ADDRINT)str->Name, str->NameLength, color, true, "NtEnumerateKey");
				}
			}
		}
	}


	/* ===================================================================== */
	/* Handle the NtQueryValueKey API (registry access)                      */
	/* ===================================================================== */
	VOID NtQueryValueKey_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		if ((KEY_VALUE_INFORMATION_CLASS)sc->arg2 == KeyValuePartialInformation) {
			W::LPVOID str = (W::LPVOID)sc->arg3;
			W::PUNICODE_STRING query = (W::PUNICODE_STRING)sc->arg1;
			if (query->Buffer != NULL) {
				char value[PATH_BUFSIZE];
				GET_STR_TO_UPPER(query->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideReqQueryValueStr(value)) { // for sensitive values only
					if (BYPASS(BP_NTQUERYVALUEKEY)) {
						char logName[256] = "NtQueryValueKey ";
						strcat(logName, value);
						logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
						for (W::USHORT i = 0; i < query->Length * 2 - 1; i += 2) {
							PIN_SafeCopy((char*)str + i, WSTR_REGKEYORVAL, sizeof(wchar_t));
						}
					}
					uint8_t color = GET_TAINT_COLOR(TT_NTQUERYVALUEKEY);
					if (color) {
						// High false positive rate, taint only suspicious registry access
						logHookId(ctx, "NtQueryValueKey", (ADDRINT)str, query->Length * 2 - 1);
						addTaintMemory(ctx, (ADDRINT)str, query->Length * 2 - 1, color, true, "NtQueryValueKey");
					}
				}
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryInformationProcess API (process information access) */
	/* ===================================================================== */
	VOID NtQueryInformationProcess_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		W::PROCESSINFOCLASS ProcessInformationClass = (W::PROCESSINFOCLASS)sc->arg1;
		W::PVOID ProcessInformation = (W::PVOID)sc->arg2;
		W::ULONG ProcessInformationLength = (W::ULONG)sc->arg3;
		W::PULONG ReturnLength = (W::PULONG)sc->arg4;

		if (ProcessInformation != 0 && ProcessInformationLength != 0) {
			W::ULONG backupReturnLength = 0;
			if (ReturnLength != nullptr && (W::ULONG_PTR)ReturnLength >= (W::ULONG_PTR)ProcessInformation && (W::ULONG_PTR)ReturnLength <= (W::ULONG_PTR)ProcessInformation + ProcessInformationLength) {
				backupReturnLength = *ReturnLength;
			}

			if (ProcessInformationClass == ProcessDebugFlags) {
				// Gives Pin away as a debugger
				if (BYPASS(BP_NTQUERYINFOPROC_31)) {
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NTQIP-ProcessDebugFlags");
					*((W::ULONG*)ProcessInformation) = PROCESS_DEBUG_INHERIT;
				}
				uint8_t color = GET_TAINT_COLOR(TT_NTQIP_DEBUGFLAG);
				if (color) {
					logHookId(ctx, "NTQIP-ProcessDebugFlags-31", (ADDRINT)ProcessInformation, ProcessInformationLength);
					addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, color, true, "NTQIP-ProcessDebugFlags");
				}
			}			
			else if (ProcessInformationClass == ProcessDebugObjectHandle) {
				// Set return value to STATUS_PORT_NOT_SET
				if (BYPASS(BP_NTQUERYINFOPROC_30)) {
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NTQIP-ProcessDebugObjectHandle");
					*((W::HANDLE*)ProcessInformation) = (W::HANDLE)0;
					ADDRINT _eax = CODEFORSTATUSPORTNOTSET;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
				uint8_t color = GET_TAINT_COLOR(TT_NTQIP_DEBUGOBJECT);
				if (color) {
					logHookId(ctx, "NTQIP-ProcessDebugObjectHandle", (ADDRINT)ProcessInformation, ProcessInformationLength);
					addTaintMemory(ctx, (ADDRINT)ProcessInformation, ProcessInformationLength, color, true, "NTQIP-ProcessDebugObjectHandle");
				}
			}
			else if (ProcessInformationClass == ProcessDebugPort) {
				// Set debug port to null
				if (BYPASS(BP_NTQUERYINFOPROC_7)) {
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NTQIP-ProcessDebugPort");
					*((W::HANDLE *)ProcessInformation) = (W::HANDLE)0;
				}
			}
			else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
			{
				// TODO high false positives rate
				logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NTQIP-ProcessBasicInformation");
				((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = (W::HANDLE)Helper::GetProcessIdByName("explorer.exe"); // TODO PID okay?
			}
			if (backupReturnLength != 0) {
				*ReturnLength = backupReturnLength;
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtQuerySystemInformation API (firmware table access)       */
	/* ===================================================================== */
	VOID NtQuerySystemInformation_exit(syscall_t * sc, CONTEXT * ctx, SYSCALL_STANDARD std) {
		if (sc->arg0 == SystemProcessInformation) {
			//cast to our structure in order to retrieve the information returned from the NtSystemQueryInformation function
			PSYSTEM_PROCESS_INFO spi;
			spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
			W::ULONG s = (W::ULONG)sc->arg2;
			//avoid null pointer exception
			if (spi == NULL)
				return;

			while (spi->NextEntryOffset) {

				if (spi->ImageName.Buffer != nullptr) {
					char value[PATH_BUFSIZE];
					memset(value, 0, PATH_BUFSIZE); // see print below
					GET_STR_TO_UPPER(spi->ImageName.Buffer, value, PATH_BUFSIZE);
					if (BYPASS(BP_NTQUERYSYSINFO_5)) {
						if (HiddenElements::shouldHideProcessStr(value)) {
							char logName[PATH_BUFSIZE];
							sprintf(logName, "NtQSI-SystemProcessInformation %s", value);
							logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
							PIN_SafeCopy(spi->ImageName.Buffer, BP_FAKEPROCESSW, sizeof(BP_FAKEPROCESSW));
						}
					}
					uint8_t color = GET_TAINT_COLOR(TT_NTQSI_PROCESSINFO);
					if (color) {
						// TODO selectivity?
						logHookId(ctx, "NTQSI-SystemProcessInformation", (ADDRINT)spi, s);
						TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);

						// TODO why not a single operation?
						addTaintMemory(ctx, (ADDRINT) & (spi->NextEntryOffset), sizeof(W::ULONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->NumberOfThreads), sizeof(W::ULONG), color, true, "NTQSI-SystemProcessInformation");

						addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.u.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.u.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->CreateTime.QuadPart), sizeof(W::LONGLONG), color, true, "NTQSI-SystemProcessInformation");

						addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.u.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.u.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->UserTime.QuadPart), sizeof(W::LONGLONG), color, true, "NTQSI-SystemProcessInformation");

						addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.u.HighPart), sizeof(W::LONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.u.LowPart), sizeof(W::DWORD), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->KernelTime.QuadPart), sizeof(W::LONGLONG), color, true, "NTQSI-SystemProcessInformation");

						addTaintMemory(ctx, (ADDRINT)(spi->ImageName.Buffer), spi->ImageName.Length, color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->BasePriority), sizeof(W::ULONG), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->ProcessId), sizeof(W::HANDLE), color, true, "NTQSI-SystemProcessInformation");
						addTaintMemory(ctx, (ADDRINT) & (spi->InheritedFromProcessId), sizeof(W::HANDLE), color, true, "NTQSI-SystemProcessInformation");
					}
				}
				spi = (PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry
			}
		}
		else if (sc->arg0 == SystemModuleInformation) {

			PRTL_PROCESS_MODULES pmi = (PRTL_PROCESS_MODULES)sc->arg1;

			if (pmi == NULL)
				return;

			if ((W::ULONG*)sc->arg3 == nullptr) 
				return;

			ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
			ADDRINT sizeIn = (W::ULONG)sc->arg2;
			W::ULONG s = (W::ULONG)sc->arg2;
			if (sizeOut > sizeIn) 
				return;

			unsigned long size = pmi->NumberOfModules;

			uint8_t color = GET_TAINT_COLOR(TT_NTQSI_MODULEINFO);
			if (color) {
				logHookId(ctx, "NTQSI-SystemModuleInformation", (ADDRINT)pmi, s);
			}

			for (size_t i = 0; i < size; i++) {
				if (strstr((char*)pmi->Modules[i].FullPathName, "VBox") != NULL) {
					if (color) {
						TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);
					}
					char* tmpAddr = (char*)pmi->Modules[i].FullPathName;
					size_t len = strlen(tmpAddr) + 1;
					if (color) {
						addTaintMemory(ctx, (ADDRINT) & (pmi->NumberOfModules), sizeof(W::ULONG), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].Section), sizeof(W::HANDLE), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].MappedBase), 4U, color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].ImageBase), 4U, color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].ImageSize), sizeof(W::ULONG), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].Flags), sizeof(W::ULONG), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].LoadOrderIndex), sizeof(W::USHORT), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].InitOrderIndex), sizeof(W::USHORT), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].LoadCount), sizeof(W::USHORT), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT) & (pmi->Modules[i].OffsetToFileName), sizeof(W::USHORT), color, true, "NTQSI-SystemModuleInformation");
						addTaintMemory(ctx, (ADDRINT)(pmi->Modules[i].FullPathName), len, color, true, "NTQSI-SystemModuleInformation");
					}
					for (size_t i = 0; i < len - 1; i++) {
						if(BYPASS(BP_NTQUERYSYSINFO_11))
							PIN_SafeCopy(tmpAddr + i, "a", sizeof(char));
					}
				}
			}
		}
		else if (sc->arg0 == SystemFirmwareTableInformation) {
			PSYSTEM_FIRMWARE_TABLE_INFORMATION sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;
			if (sfti->Action == SystemFirmwareTable_Get) {
				ADDRINT sizeOut = *(W::ULONG*)sc->arg3;
				ADDRINT sizeIn = (W::ULONG)sc->arg2;
				if (sizeOut > sizeIn) return;

				PSYSTEM_FIRMWARE_TABLE_INFORMATION info = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)sc->arg1;

				if (BYPASS(BP_NTQUERYSYSINFO_76)) {
					// Virtualbox part
					// TODO? different colors for each suspicious string
					char vbox[] = { "VirtualBox" };
					char vbox2[] = { "vbox" };
					char vbox3[] = { "VBOX" };
					char vbox4[] = { "Virtual Machine" };
					char escape[] = { "aaaaaaaaaa" };
					char escape2[] = { "aaaa" };
					char escape3[] = { "aaaaaaa aaaaaaa" };
					W::ULONG sizeVbox = (W::ULONG)Helper::_strlen_a(vbox);
					W::ULONG sizeVbox2 = (W::ULONG)Helper::_strlen_a(vbox2);
					W::ULONG sizeVbox3 = (W::ULONG)Helper::_strlen_a(vbox3);
					W::ULONG sizeVbox4 = (W::ULONG)Helper::_strlen_a(vbox4);

					// Scan entire bios in order to find vbox strings
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NtQSI-SystemFirmwareTableInformation VBox");
					for (size_t i = 0; i < info->TableBufferLength - sizeVbox; i++) {
						if (memcmp(info->TableBuffer + i, vbox, sizeVbox) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape, sizeof(escape));
						}
						else if (memcmp(info->TableBuffer + i, vbox2, sizeVbox2) == 0 ||
							memcmp(info->TableBuffer + i, vbox3, sizeVbox3) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape2, sizeof(escape2));
						}
						else if (memcmp(info->TableBuffer + i, vbox4, sizeVbox4) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape3, sizeof(escape3));
						}
					}

					// Scan entire bios in order to find VMware string
					char vmware[] = { "VMware" };
					char vmware2[] = { "Virtual Machine" };
					char escape4[] = { "aaaaaa" };
					char escape5[] = { "aaaaaaa aaaaaaa" };
					W::ULONG vmwareSize = (W::ULONG)Helper::_strlen_a(vmware);
					W::ULONG vmwareSize2 = (W::ULONG)Helper::_strlen_a(vmware2);

					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NtQSI-SystemFirmwareTableInformation VMWare");
					for (size_t i = 0; i < info->TableBufferLength - vmwareSize; i++) {
						if (memcmp(info->TableBuffer + i, vmware, vmwareSize) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape4, sizeof(escape4));
						}
						else if (memcmp(info->TableBuffer + i, vmware2, vmwareSize2) == 0) {
							PIN_SafeCopy(info->TableBuffer + i, escape5, sizeof(escape5));
						}
					}

				}

				// Taint the table buffer
				uint8_t color = GET_TAINT_COLOR(TT_NTQSI_FIRMWAREINFO);
				if (color) {
					logHookId(ctx, "NtQSI-SystemFirmwareTableInformation", (ADDRINT)info->TableBuffer, info->TableBufferLength);
					addTaintMemory(ctx, (ADDRINT)info->TableBuffer, info->TableBufferLength, color, true, "NtQSI-SystemFirmwareTableInformation");
				}
			}
		}
		else if (sc->arg0 == SystemKernelDebuggerInformation) {
			PSYSTEM_KERNEL_DEBUGGER_INFORMATION skdi = (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)sc->arg1;
			W::ULONG s = (W::ULONG)sc->arg2;
			// No bypass needed here (see BluePill for reference)
			//logModule->logBypass(GET_INTERNAL_CLOCK(ctx), "NtQSI-SystemKernelDebuggerInformation");
			uint8_t color = GET_TAINT_COLOR(TT_NTQSI_KERNELINFO);
			if (color) {
				logHookId(ctx, "NtQSI-SystemKernelDebuggerInformation", (ADDRINT)skdi, s);
				TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);
				addTaintMemory(ctx, (ADDRINT) & (skdi->KernelDebuggerEnabled), sizeof(W::BOOLEAN), color, true, "NtQSI-SystemKernelDebuggerInformation");
				addTaintMemory(ctx, (ADDRINT) & (skdi->KernelDebuggerNotPresent), sizeof(W::BOOLEAN), color, true, "NtQSI-SystemKernelDebuggerInformation");
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryAttributesFile API (file information access)        */
	/* ===================================================================== */
	VOID NtQueryAttributesFile_entry(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg0;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(p->Buffer, value, PATH_BUFSIZE); 
		apiOutputs->ntQueryAttributesFileBuffer = p->Buffer;

		if (BYPASS(BP_NTQUERYATTRFILE) && HiddenElements::shouldHideGenericFileNameStr(value)) {
			char logName[PATH_BUFSIZE] = "NtQueryAttributesFile ";
			strcat(logName, value);
			logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
			for (W::USHORT i = p->Length - 8; i < p->Length - 1; i += 2) {
				PIN_SafeCopy((char*)p->Buffer + i, WSTR_FILE, sizeof(wchar_t));
			}
		}
	}

	/* ===================================================================== */
	/* Handle the NtQueryAttributesFile API (file information access)        */
	/* ===================================================================== */
	VOID NtQueryAttributesFile_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::OBJECT_ATTRIBUTES* Obj = (W::OBJECT_ATTRIBUTES*)sc->arg0;
		W::FILE_BASIC_INFO* basicInfo = (W::FILE_BASIC_INFO*)sc->arg1;
		W::PUNICODE_STRING p = Obj->ObjectName;
		State::apiOutputs* apiOutputs = State::getApiOutputs();

		char value[PATH_BUFSIZE];
		GET_STR_TO_UPPER(apiOutputs->ntQueryAttributesFileBuffer, value, PATH_BUFSIZE);

		uint8_t color = GET_TAINT_COLOR(TT_NTQUERYATTRIBUTESFILE);
		if (color && HiddenElements::shouldHideGenericFileNameStr(value)) { // taint sensitive files only
			TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);
			logHookId(ctx, "NtQueryAttributesFile", (ADDRINT)basicInfo, sizeof(W::FILE_BASIC_INFO));
			
			//Tainting the whole FILE_BASIC_INFO data structure
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.u.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.u.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->CreationTime.QuadPart), sizeof(W::LONGLONG), color, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.u.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.u.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastAccessTime.QuadPart), sizeof(W::LONGLONG), color, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.u.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.u.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->LastWriteTime.QuadPart), sizeof(W::LONGLONG), color, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.u.HighPart), sizeof(W::LONG), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.u.LowPart), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
			addTaintMemory(ctx, (ADDRINT) & (basicInfo->ChangeTime.QuadPart), sizeof(W::LONGLONG), color, true, "NtQueryAttributesFile");

			addTaintMemory(ctx, (ADDRINT) & (basicInfo->FileAttributes), sizeof(W::DWORD), color, true, "NtQueryAttributesFile");
		}
	}

	/* ===================================================================== */
	/* Handle the NtUserFindWindowEx API (Virtualbox/VMware window access)   */
	/* ===================================================================== */
	VOID NtUserFindWindowEx_exit(syscall_t* sc, CONTEXT* ctx, SYSCALL_STANDARD std) {
		W::PUNICODE_STRING path1 = (W::PUNICODE_STRING)sc->arg2;
		W::PUNICODE_STRING path2 = (W::PUNICODE_STRING)sc->arg3;

		char value[PATH_BUFSIZE] = { 0 };

		if (BYPASS(BP_NTUSERFINDWIND)) {
			// Bypass the first path
			if (path1 != NULL && path1->Buffer != NULL) {
				GET_STR_TO_UPPER(path1->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					char logName[256] = "NtUserFindWindow ";
					strcat(logName, value);
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);
					ADDRINT _eax = 0;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
			}

			// Bypass the second path
			if (path2 != NULL && path2->Buffer != NULL) {
				memset(value, 0, PATH_BUFSIZE);
				GET_STR_TO_UPPER(path2->Buffer, value, PATH_BUFSIZE);
				if (HiddenElements::shouldHideWindowStr(value)) {
					char logName[256] = "NtUserFindWindow ";
					strcat(logName, value);
					logModule->logBypass(GET_INTERNAL_CLOCK(ctx), logName);					
					ADDRINT _eax = 0;
					PIN_SetContextReg(ctx, REG_GAX, _eax);
				}
			}
		}
		// Taint registry handler
		uint8_t color = GET_TAINT_COLOR(TT_NTFINDWINDOW);
		if (color) {
			TAINT_TAG_REG(ctx, GPR_EAX, color, color, color, color);
		}
	}
}
