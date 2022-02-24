/* ================================================================== */
/* Imports                                                            */
/* ================================================================== */
#pragma once
#include "main.h"
#include "bypass.h"

/* ================================================================== */
/* Global variables                                                   */ 
/* ================================================================== */

// Define page size
#ifndef PAGE_SIZE
	#define PAGE_SIZE 0x1000
#endif
// Tool name and relative version
#define TOOL_NAME "WhiteRabbitTracker"
#define VERSION "2.0"
// Object that contains useful functions to access the process
ProcessInfo pInfo;
// Object that contains useful functions for logging
LoggingInfo logInfo;
// Object that contains useful functions for special instructions instrumentation (cpuid, rdtsc)
SpecialInstructionsHandler* specialInstructionsHandlerInfo;
// Define TLS key
TLS_KEY tls_key = INVALID_TLS_KEY;
// Policy for taint tracking
uint8_t policyForTT[TT_TOTAL_SIZE];
// Policy for bypasses
uint8_t policyForBP[BP_TOTAL_SIZE];

/* ================================================================== */
/* Knobs definitions                                                  */
/* ================================================================== */

// Define knobs
KNOB<BOOL> knobApiTracing(KNOB_MODE_WRITEONCE, "pintool", "trace", "false", "Enable API tracing at instruction level after each tainted conditional branch (high load, disabled by default)");
KNOB<BOOL> knobBypass(KNOB_MODE_WRITEONCE, "pintool", "bypass", "false", "Enable return value bypass for APIs and instructions to avoid sandbox/VM detection (disabled by default)");
KNOB<BOOL> knobLeak(KNOB_MODE_WRITEONCE, "pintool", "leak", "false", "Enable bypass to avoid leaks of real EIP through FPU instructions (disabled by default)");
KNOB<BOOL> knobSystemCodeAlert(KNOB_MODE_WRITEONCE, "pintool", "alertSystemCode", "false", "Enable taint alert for tainted system code (disabled by default)");
KNOB<BOOL> knobNoTainting(KNOB_MODE_WRITEONCE, "pintool", "notaint", "false", "Disable taint tracking (helpful with -bypass only, disabled by default)");


/* ============================================================================= */
/* Define macro to check the instruction address and check if is program code    */
/* ============================================================================= */
#define CHECK_EIP_ADDRESS(eip_address) do { \
State::globalState* gs = State::getGlobalState(); \
itreenode_t* node = itree_search(gs->dllRangeITree, eip_address); \
if(node != NULL) return; \
} while (0)

/* ===================================================================== */
/* Function called for every loaded module                               */
/* ===================================================================== */
VOID ImageLoad(IMG Image, VOID *v) {
	// Add the module to the current process
	pInfo.addModule(Image);
	// Insert the current image to the interval tree
	pInfo.addCurrentImageToTree(Image);
	// Add APIs hooking for the current image
	Functions::AddHooks(Image);
}

/* ===================================================================== */
/* Function called for every unload module                               */
/* ===================================================================== */
VOID ImageUnload(IMG Image, VOID* v) {
	// Remote the current image from the interval tree
	pInfo.removeCurrentImageFromTree(Image);
}

/* ===================================================================== */
/* Function to help with "tainted" API calls                             */
/* ===================================================================== */
ADDRINT PIN_FAST_ANALYSIS_CALL TaintAPICallIf() {
	return _alertApiTracingCounter;
}


/* ===================================================================== */
/* Functions to help with single-stepping anti-debugging tricks          */
/* ===================================================================== */
VOID handleInt2d(CONTEXT* ctx, THREADID tid, ADDRINT eip) {
	std::cerr << std::hex << eip << " int2d playing HERE!" << std::endl;
	std::cerr << "Value into EAX: " << std::hex << PIN_GetContextReg(ctx, REG_GAX) << std::endl;
	
	// int 2d takes 2 bytes + Windows skips an extra byte according to EAX value
	EXCEPTION_INFO exc;
	PIN_InitWindowsExceptionInfo(&exc, NTSTATUS_STATUS_BREAKPOINT, eip+0x3);
	PIN_SetContextReg(ctx, REG_INST_PTR, eip + 0x3); // advance EIP
	PIN_RaiseException(ctx, tid, &exc);
}

bool isHandlingPopFd = FALSE;

VOID handlePopFd(CONTEXT* ctx, THREADID tid, ADDRINT eip, ADDRINT esp) {
	ADDRINT eflags = *((ADDRINT*)esp);
	if (!(eflags & 0x100)) return; // benign popfd

	std::cerr << std::hex << eip << " popf PLAYING WITH TRAP FLAG HERE!" << std::endl;

	*((ADDRINT*)esp) = eflags & (~0x100);
	isHandlingPopFd = TRUE;
	PIN_RemoveInstrumentationInRange(eip + 1, eip + 20); // +20 to be on the safe side
}

VOID handlePopFdAfter(CONTEXT* ctx, THREADID tid, ADDRINT eip, ADDRINT esp) {
	static int count = 0;
	if (!count++) return; // skip very first instruction

	*((ADDRINT*)(esp-4)) |= 1UL << 8;; // restore wiped trap flag
	EXCEPTION_INFO exc;
	PIN_InitWindowsExceptionInfo(&exc, NTSTATUS_STATUS_SINGLE_STEP, eip);
	isHandlingPopFd = FALSE;
	count = 0;
	PIN_RaiseException(ctx, tid, &exc);
}

/* ===================================================================== */
/* AOT instrumentation for some instructions (more stable than TRACE)    */
/* ===================================================================== */
VOID InstrumentInstructionAOT(INS ins, VOID* v) {
	if (isHandlingPopFd) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handlePopFdAfter,
			IARG_CONTEXT, IARG_THREAD_ID,
			IARG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
	}
	// TODO optimizations
	if (INS_IsInterrupt(ins) && INS_Disassemble(ins).find("int 0x2d") != string::npos) {
		if (BYPASS(BP_INT2D)) {
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handleInt2d,
				IARG_CONTEXT, IARG_THREAD_ID,
				IARG_INST_PTR,
				IARG_END);
		}
	} else {
		// Pin type is: OPCODE
		// XED reference: https://intelxed.github.io/ref-manual/xed-iclass-enum_8h.html
		xed_iclass_enum_t opcode = (xed_iclass_enum_t)INS_Opcode(ins);

		// popfd only (no XED_ICLASS_POPF or XED_ICLASS_POPFQ)
		if (opcode == XED_ICLASS_POPFD) { // TODO add check on knob
			//std::cerr << str << " at " << std::hex << INS_Address(ins) << std::endl;
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handlePopFd,
				IARG_CONTEXT, IARG_THREAD_ID,
				IARG_INST_PTR, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
		}
	}
}


/* ===================================================================== */
/* Function called BEFORE every TRACE                                    */
/* ===================================================================== */
VOID InstrumentInstruction(TRACE trace, VOID *v) {
	// Define iterators 
	BBL bbl;
	INS ins;

	State::globalState* gs;
	if (_knobApiTracing) gs = State::getGlobalState();

	// Traverse all the BBLs in the trace 
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		// Traverse all the instructions in the BBL 
		for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			// special-purpose instruction-level hooks (non-AOT)
			specialInstructionsHandlerInfo->checkSpecialInstruction(ins);

			// API logging for "tainted" calls 
			if (_knobApiTracing && (INS_IsControlFlow(ins) || INS_IsFarJump(ins))) {
				itreenode_t* node = itree_search(gs->dllRangeITree, INS_Address(ins));
				if (!node) { // we hook code from program code only
					INS_InsertIfCall(ins, IPOINT_BEFORE,
						(AFUNPTR)TaintAPICallIf,
						IARG_FAST_ANALYSIS_CALL,
						IARG_END);
					INS_InsertThenCall(ins, IPOINT_BEFORE,
						(AFUNPTR)SaveTransitions,
						IARG_INST_PTR,
						IARG_BRANCH_TARGET_ADDR,
						IARG_END
					);
				}
			}
		}
	}
}

/* ===================================================================== */
/* Utility function to search the nearest address in the export map of   */
/* the current DLL to find which system API is called                    */
/* ===================================================================== */
W::DWORD searchNearestAddressExportMap(std::map<W::DWORD, std::string> exportsMap, ADDRINT addr) {
	W::DWORD currentAddr = 0;
	for (const auto& p : exportsMap) {
		if (!currentAddr) {
			currentAddr = p.first;
		}
		else {
			if (std::abs((long)(p.first - addr)) < std::abs((long)(currentAddr - addr))) {
				currentAddr = p.first;
			}
		}
	}
	return currentAddr;
}

/* ===================================================================== */
/* Function called BEFORE the analysis routine to enter critical section */
/* ===================================================================== */
VOID SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo) {
	//CHECK_EIP_ADDRESS(cur_eip);
	// Enter critical section (ensure that we can call PIN APIs)
	PIN_LockClient();
	// Call analysis routine
	_SaveTransitions(addrFrom, addrTo);
	// Exit critical section
	PIN_UnlockClient();
}

/* ===================================================================== */
/* Function called for each ANALYSIS ROUTINE (instruction analysis)      */
/* Parameters: addrFrom (address of instruction), addrTo (target address)*/
/* ===================================================================== */
VOID _SaveTransitions(const ADDRINT addrFrom, const ADDRINT addrTo) {
	// Get access to global state variables
	State::globalState* gs = State::getGlobalState();

	// Last shellcode to which the transition got redirected
	static ADDRINT lastShellc = UNKNOWN_ADDR;

	// Variables to check caller/target process
	const bool isCallerMy = pInfo.isMyAddress(addrFrom);
	const bool isTargetMy = pInfo.isMyAddress(addrTo);

	// Variables to get caller/target module
	IMG callerModule = IMG_FindByAddress(addrFrom);
	IMG targetModule = IMG_FindByAddress(addrTo);

	// Variables to get the address of the page relative to addresses
	ADDRINT pageFrom = GetPageOfAddr(addrFrom);
	ADDRINT pageTo = GetPageOfAddr(addrTo);

	// [API CALL TRACING]
	// Is it a transition FROM THE TRACED MODULE TO A FOREIGN MODULE? (my process is calling the instruction and pointing to a foreign module) 
	std::map<W::DWORD, std::string> exportsMap;
	std::string dllName;
	W::DWORD nearestAddressExportsMap;
	if (isCallerMy && !isTargetMy) {
		// Get relative virtual address (address - get_base(address)) of the foreign module
		ADDRINT RvaFrom = addr_to_rva(addrFrom);
		// Check if the image of the foreign module is VALID
		if (IMG_Valid(targetModule)) {
			const std::string func = get_func_at(addrTo);
			// Get DLL name (Image name) from the Pin APIs and the interval tree
			itreenode_t* currentNode = itree_search(gs->dllRangeITree, addrTo);
			for (size_t i = 0; i < gs->dllExports.size(); i++) {
				if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
					exportsMap = gs->dllExports[i].exports;
					dllName = std::string((char*)gs->dllExports[i].dllPath);
					nearestAddressExportsMap = searchNearestAddressExportMap(exportsMap, addrTo);
				}
			}
			// Write to log file the API call with dll name and function name
			logInfo.logCall(0, RvaFrom, true, dllName, (exportsMap)[nearestAddressExportsMap].c_str());
			_alertApiTracingCounter -= 1;
		}
		else {
			// Image not valid (no mapped module), let's save the beginning of this area as possible shellcode
			lastShellc = pageTo;
		}
	}
	// [SHELLCODE API CALL TRACING]
	// Trace calls from witin the last shellcode that was called from the traced module
	if (!IMG_Valid(callerModule)) {
		const ADDRINT callerPage = pageFrom;
		// If the caller page is a known address and correspond to the last possible shellcode, log it
		if (callerPage != UNKNOWN_ADDR && callerPage == lastShellc) {
			// If the target of the shellcode is valid continue
			if (IMG_Valid(targetModule)) {
				// Log the API call of the called shellcode (get function name and dll name)
				itreenode_t* currentNode = itree_search(gs->dllRangeITree, addrTo);
				for (size_t i = 0; i < gs->dllExports.size(); i++) {
					if (strcmp((char*)gs->dllExports[i].dllPath, (char*)currentNode->data) == 0) {
						exportsMap = gs->dllExports[i].exports;
						dllName = std::string((char*)gs->dllExports[i].dllPath);
						nearestAddressExportsMap = searchNearestAddressExportMap(exportsMap, addrTo);
					}
				}
				logInfo.logCall(callerPage, addrFrom, false, dllName, (exportsMap)[nearestAddressExportsMap].c_str());
				_alertApiTracingCounter -= 1;
			}
			// Otherwise, set the variable lastShellc if the mode is recursive (shellcode inside shellcode)
			else if (pageFrom != pageTo) {
				lastShellc = pageTo;
			}
		}
	}
}

/* ===================================================================== */
/* Function to handle context change and retrieve exception reason       */
/* ===================================================================== */
static void OnCtxChange(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom, CONTEXT *ctxtTo, INT32 info, VOID *v) {
	// Check if context variable exists
	if (ctxtTo == NULL || ctxtFrom == NULL) {
		return;
	}
	// Update global variables on Windows generic exception
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION) { 
		FetchGlobalState;
	}
	// Enter critical section (ensure that we can call PIN APIs)
	PIN_LockClient();
	// Extract address from and address to from the registry context
	const ADDRINT addrFrom = (ADDRINT)PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
	const ADDRINT addrTo = (ADDRINT)PIN_GetContextReg(ctxtTo, REG_INST_PTR);
	// Add logging based on reason
	std::string reasonDescription = "";
	switch(reason) {
		case CONTEXT_CHANGE_REASON_FATALSIGNAL:
			reasonDescription = "fatal unix signal";
			break;
		case CONTEXT_CHANGE_REASON_SIGNAL:
			reasonDescription = "handled unix signal";
			break;
		case CONTEXT_CHANGE_REASON_SIGRETURN:
			reasonDescription = "return from unix signal handler";
			break;
		case CONTEXT_CHANGE_REASON_APC:
			reasonDescription = "windows apc";
			break;
		case CONTEXT_CHANGE_REASON_EXCEPTION:
			reasonDescription = "windows generic exception";
			break; 
		case CONTEXT_CHANGE_REASON_CALLBACK:
			reasonDescription = "windows callback";
			break;
	}
	// Log the exception
	logInfo.logException(addrFrom, reasonDescription);
	// Exit critical section
	PIN_UnlockClient();
}


/* ===================================================================== */
/* Function to handle each thread start and retrieve useful informations */
/* for libdft                                                            */
/* ===================================================================== */
VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *) {
	// TLS handling
	pintool_tls* tdata = new pintool_tls;
	if (PIN_SetThreadData(tls_key, tdata, tid) == FALSE) {
		std::cerr << "Cannot initialize the TLS key for the thread " + tid << "!" << std::endl;
		PIN_ExitProcess(1);
	}
	// Initialize libdft thread context
	thread_ctx_t *thread_ctx = libdft_thread_start(ctxt);
	// Setup thread informations
	#define TTINFO(field) thread_ctx->ttinfo.field
	// Retrieve thread ID
	TTINFO(tid) = tid;
	// Retrieve OS thread ID
	TTINFO(os_tid) = PIN_GetTid();
	// Initialize other fields
	TTINFO(firstOperandTainted) = 0;
	TTINFO(secondOperandTainted) = 0;
	TTINFO(offendingInstruction) = 0;
	TTINFO(logTaintedSystemCode) = 0;
	// Initialize shadow stack
	TTINFO(shadowStackThread) = new callStackThread;
	TTINFO(shadowStackThread)->callStack = new std::vector<callStackFrame>;
	TTINFO(shadowStackThread)->callStack->reserve(32);
	TTINFO(shadowStackThread)->callStackTop = 0;
	// Undefine thread informations (used later in bridge.cpp for libdft tainting)
	#undef TTINFO
	// Initialize buffered logger for the current thread
	threadInitLogger(tid, tdata);
}

/* ===================================================================== */
/* Function to handle each thread end and destroy libdft thread context  */
/* ===================================================================== */
VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32, VOID *) {
	// Destroy libdft thread context
	libdft_thread_fini(ctxt);
	// Destroy buffered logger for the current thread
	pintool_tls *tdata = static_cast<pintool_tls*>(PIN_GetThreadData(tls_key, tid));
	threadExitLogger(tid, tdata);
}

/* ===================================================================== */
/* Function to handle the exceptions (anti-DBI checks)                   */
/* ===================================================================== */
EXCEPT_HANDLING_RESULT internalExceptionHandler(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v) {
	std::cout << PIN_ExceptionToString(pExceptInfo).c_str() << " Code: " << pExceptInfo->GetExceptCode() << std::endl;
	// Handle single-step exception
	if (pExceptInfo->GetExceptCode() == EXCEPTCODE_DBG_SINGLE_STEP_TRAP) {
		std::cerr << "Uncaught single-step exception: this should not be happening..." << std::endl;
		return EHR_HANDLED; // TODO see if we ever get here with untested anti-dbg techniques
	} 
	// Libdft hack for EFLAGS (unaligned memory access)
	else if (PIN_GetExceptionCode(pExceptInfo) == EXCEPTCODE_ACCESS_MISALIGNED) {
		// Clear EFLAGS.AC 
		PIN_SetPhysicalContextReg(pPhysCtxt, REG_EFLAGS, CLEAR_EFLAGS_AC(PIN_GetPhysicalContextReg(pPhysCtxt, REG_EFLAGS)));
		return EHR_HANDLED;
	}
	return EHR_CONTINUE_SEARCH;
}

/* ===================================================================== */
/* Method to initialize taint tracking configuration                     */
/* ===================================================================== */
VOID setupTaintTrackingPolicy() {
	policyForTT[TT_CPUID] = TAINT_CPUID;
	policyForTT[TT_RDTSC] = TAINT_RDTSC;
	policyForTT[TT_IN] = TAINT_IN;
	policyForTT[TT_OBSIDIUM_DISK_DRIVE] = TAINT_OBSIDIUM_DISK_DRIVE;
	policyForTT[TT_NTCREATEFILE] = TAINT_NTCREATEFILE;
	policyForTT[TT_NTOPENKEY] = TAINT_NTOPENKEY;
	policyForTT[TT_NTENUMERATEKEY] = TAINT_NTENUMERATEKEY;
	policyForTT[TT_NTQUERYVALUEKEY] = TAINT_NTQUERYVALUEKEY;
	policyForTT[TT_NTQIP_DEBUGFLAG] = TAINT_NTQIP_DEBUGFLAG;
	policyForTT[TT_NTQIP_DEBUGOBJECT] = TAINT_NTQIP_DEBUGOBJECT;
	policyForTT[TT_NTQSI_PROCESSINFO] = TAINT_NTQSI_PROCESSINFO;
	policyForTT[TT_NTQSI_MODULEINFO] = TAINT_NTQSI_MODULEINFO;
	policyForTT[TT_NTQSI_FIRMWAREINFO] = TAINT_NTQSI_FIRMWAREINFO;
	policyForTT[TT_NTQSI_KERNELINFO] = TAINT_NTQSI_KERNELINFO;
	policyForTT[TT_NTQUERYATTRIBUTESFILE] = TAINT_NTQUERYATTRIBUTESFILE;
	policyForTT[TT_NTFINDWINDOW] = TAINT_NTFINDWINDOW;
	policyForTT[TT_ISDEBUGGERPRESENT] = TAINT_ISDEBUGGERPRESENT;
	policyForTT[TT_CHECKREMOTEDEBUGGER] = TAINT_CHECKREMOTEDEBUGGER;
	policyForTT[TT_ENUMPROCESSES] = TAINT_ENUMPROCESSES;
	policyForTT[TT_PROCESS32FIRSTNEXT] = TAINT_PROCESS32FIRSTNEXT;
	policyForTT[TT_GETDISKFREESPACE] = TAINT_GETDISKFREESPACE;
	policyForTT[TT_GLOBALMEMORYSTATUS] = TAINT_GLOBALMEMORYSTATUS;
	policyForTT[TT_GETSYSTEMINFO] = TAINT_GETSYSTEMINFO;
	policyForTT[TT_GETCURSORPOS] = TAINT_GETCURSORPOS;
	policyForTT[TT_GETMODULEFILENAME] = TAINT_GETMODULEFILENAME;
	policyForTT[TT_GETDEVICEDRIVERNAME] = TAINT_GETDEVICEDRIVERNAME;
	policyForTT[TT_GETADAPTERSINFO] = TAINT_GETADAPTERSINFO;
	policyForTT[TT_ENUMDISPLAYSETTINGS] = TAINT_ENUMDISPLAYSETTINGS;
	policyForTT[TT_GETTICKCOUNT] = TAINT_GETTICKCOUNT;
	policyForTT[TT_ICMPSENDECHO] = TAINT_ICMPSENDECHO;
	policyForTT[TT_LOADLIBRARY] = TAINT_LOADLIBRARY;
	policyForTT[TT_GETUSERNAME] = TAINT_GETUSERNAME;
	policyForTT[TT_FINDWINDOW] = TAINT_FINDWINDOW;

	// leftovers from Andrea
	policyForTT[TT_BLOCKINPUT] = 0;
	policyForTT[TT_SETUPDEVICEREGISTRY] = 0;
}


/* ===================================================================== */
/* Method to initialize evasion bypass configuration                     */
/* ===================================================================== */
VOID setupBypassPolicy() {
	if (!_knobBypass) return;

	// default: enable all
	memset(policyForBP, 1, BP_TOTAL_SIZE);

	// TODO read from file what to skip (or set)
}

/* ===================================================================== */
/* Print Help Message (usage message)                                    */
/* ===================================================================== */
INT32 Usage() {
	cerr << "Hi there :-) Have fun with some Dynamic Taint Analysis!\n" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Heavy-duty debugger for pinpointing unsupported evasions              */
/* ===================================================================== */
VOID DirtyDebugForNewEvasion(const char* apiname, ADDRINT esp, ADDRINT arg0,
	ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT arg6, ADDRINT arg7) {
	CHECK_EIP_ADDRESS(*(ADDRINT*)esp);
	int argIdx = 0;

	std::cerr << "Arguments for API " << apiname << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg0 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg1 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg2 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg3 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg4 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg5 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg6 << std::endl;
	std::cerr << argIdx++ << " " << std::hex << arg7 << std::endl;
}

VOID InstrumentRoutineCallback(const char* apiname, ADDRINT esp) {
	static int count = 0;
	//CHECK_EIP_ADDRESS(*(ADDRINT*)esp);
	State::globalState* gs = State::getGlobalState();
	itreenode_t* node = itree_search(gs->dllRangeITree, *(ADDRINT*)esp);

	char buf[MAX_PATH];
	if (node != NULL) {
#if 0
		sprintf(buf, "====> %s", apiname); // internal calls
		gs->logInfo->logMisc(std::string(buf));
#endif
	}
	else {
		sprintf(buf, "%x %s", count++, apiname); // program call (with ID)
		gs->logInfo->logMisc(std::string(buf));
	}
}

static VOID InstrumentRoutine(RTN rtn, VOID*) {
	const char* rtnName = RTN_Name(rtn).c_str();

	if (!strcmp(rtnName, "ExpInterlockedPopEntrySListResume") ||
		!strcmp(rtnName, "LocalAlloc") ||
		!strcmp(rtnName, "LocalFree") || 
		!strcmp(rtnName, "RtlEnterCriticalSection") ||
		!strcmp(rtnName, "RtlLeaveCriticalSection") ||
		!strcmp(rtnName, "KiUserCallbackDispatcher")) return;

	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)InstrumentRoutineCallback,
		IARG_ADDRINT, rtnName,
		IARG_REG_VALUE, REG_STACK_PTR,
		IARG_END);
	/*if (!strcmp(rtnName, "EnumServicesStatusExW") || !strcmp(rtnName, "LoadLibraryA")) {
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)DirtyDebugForNewEvasion,
			IARG_ADDRINT, rtnName,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
			IARG_END);
	}*/

	RTN_Close(rtn);
}

STATIC VOID patchPEB() {
	PEB32* peb32 = NULL;
	PEB64* peb64 = NULL;

	W::BOOL bWow64;
	W::IsWow64Process((W::HANDLE)(-1), &bWow64);
	BOOL isWow64 = (bWow64 != 0);

	if (isWow64) {
		W::BYTE* teb32; // = (W::BYTE*)W::NtCurrentTeb();
		__asm {
			mov eax, fs:18h
			mov teb32, eax
		}
		W::BYTE* teb64 = teb32 - 0x2000;
		peb32 = (PEB32*)(*(W::DWORD*)(teb32 + 0x30));
		peb64 = (PEB64*)(*(W::DWORD64*)(teb64 + 0x60));
	}
	else {
		__asm {
			mov eax, fs:30h
			mov peb32, eax
		}
	}

	// patch PEB32
	W::DWORD zero = 0;
	//W::ULONG numCores = BP_NUMCORES;
	W::HANDLE hProc = (W::HANDLE)(-1);

	//W::WriteProcessMemory(hProc, (&peb32->NumberOfProcessors), &numCores, sizeof(W::DWORD), 0);
	W::WriteProcessMemory(hProc, (&peb32->BeingDebugged), &zero, sizeof(W::BYTE), 0);
	W::WriteProcessMemory(hProc, (&peb32->NtGlobalFlag), &zero, sizeof(W::DWORD), 0);

	if (isWow64) {
		//W::WriteProcessMemory(hProc, (W::LPVOID)(&peb64->NumberOfProcessors), &numCores, sizeof(W::DWORD), 0);
		W::WriteProcessMemory(hProc, (&peb64->BeingDebugged), &zero, sizeof(W::BYTE), 0);
		W::WriteProcessMemory(hProc, (&peb64->NtGlobalFlag), &zero, sizeof(W::DWORD), 0);
	}
}

/* =================================================================================================== */
/* Main function                                                                                       */
/* =================================================================================================== */
/* argc, argv are the entire command line: pin.exe -t <toolname.dll> <knobParameters> -- sample.exe    */
/* =================================================================================================== */
int main(int argc, char * argv[]) {
	// Initialize pin symbols
	PIN_InitSymbols();

	// Initialize pin (in case of error print usage)
	if (PIN_Init(argc, argv)) {
		return Usage();
	}

	// Open output file using the logging module (API tracing)
	OS_MkDir(LOGPATH, 755);
	logInfo.init(LOGPATH MAIN_LOG_NAME);
	initLoggerShadowCallStack(LOGPATH CALLSTACK_LOG_NAME);

	// Setup knob variables
	_knobBypass = knobBypass.Value();
	_knobLeak = knobLeak.Value();
	_knobApiTracing = knobApiTracing.Value();
	_knobAlertSystemCode = knobSystemCodeAlert.Value();
	_knobNoTainting = knobNoTainting.Value();

	// Initialize global state information
	State::init();
	State::globalState* gs = State::getGlobalState();
	gs->logInfo = &logInfo;

	// Initialize elements to be hidden and enable hooks for bypasses
	HiddenElements::initializeHiddenStuff();
	setupBypassPolicy();

	// Initialize taint hooks
	setupTaintTrackingPolicy();

	// Remove old file related to taint analysis
	W::WIN32_FIND_DATA ffd; 
	W::HANDLE hFind = FindFirstFile(LOGPATH_TAINT "*.log", &ffd);
	do {
		std::string fileName = ffd.cFileName;
		if (fileName.rfind("tainted-", 0) == 0) {
			char fullPath[256];
			sprintf(fullPath, LOGPATH_TAINT "%s", fileName.c_str());
			remove(fullPath);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	// Get module name from command line argument
	std::string appName = "";
	// Iterate over argc until "--"
	for (int i = 1; i < (argc - 1); i++) {
		if (strcmp(argv[i], "--") == 0) {
			appName = argv[i + 1];
			// If the app_name contains a directory, split it and get the file name
			if (appName.find("/") != std::string::npos) {
				appName = appName.substr(appName.rfind("/") + 1);
			}
			break;
		}
	}

	// Obtain a TLS key
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		std::cerr << "Cannot initialize TLS key!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Initialize ProcessInfo object 
	pInfo.init(appName);

	// Register system hooking
	SYSHOOKING::Init(&logInfo);

	// Initialize FPU leak evasions
	if(_knobLeak)
		SpecialInstructionsHandler::fpuInit();

	// Register function to be called BEFORE every TRACE (analysis routine for API TRACING, SHELLCODE TRACING AND SECTION TRACING)
	TRACE_AddInstrumentFunction(InstrumentInstruction, (VOID*)0);

	// Initialize SpecialInstructions (to handle special instructions) object with related modules (processInfo and logInfo)
	specialInstructionsHandlerInfo = SpecialInstructionsHandler::getInstance();
	specialInstructionsHandlerInfo->init(&pInfo, &logInfo);

	// AOT tricks to get around single-stepping and other corner cases (if any)
	INS_AddInstrumentFunction(InstrumentInstructionAOT, NULL);

	// Register function to be called for every loaded module (populate ProcessInfo object, populate interval tree and add API HOOKING FOR FURTHER TAINT ANALYSIS)
	IMG_AddInstrumentFunction(ImageLoad, NULL);

	// Register function to be called for evenry unload module (remove image from interval tree)
	IMG_AddUnloadFunction(ImageUnload, NULL);

	// Initialize Functions object (to handle API hooking and taint hooking) 
	Functions::Init(&logInfo);

	// Register context changes
	PIN_AddContextChangeFunction(OnCtxChange, NULL);

	// Register exception control flow
	PIN_AddInternalExceptionHandler(internalExceptionHandler, NULL);

	// Register thread start evenet to initialize libdft thread context
	PIN_AddThreadStartFunction(OnThreadStart, NULL);

	// Register thread end evenet to destroy libdft thread context
	PIN_AddThreadFiniFunction(OnThreadFini, NULL);

	// Initialize libdft engine
	if (libdft_init_data_only(_knobNoTainting)) {
		std::cerr << "Error during libdft initialization!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Initialize disassembler module
	if (initializeDisassembler()) {
		std::cerr << "Error during disassembler module initialization!" << std::endl;
		PIN_ExitProcess(1);
	}

	// Welcome message :-)
	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by " << TOOL_NAME << " v." << VERSION << std::endl;
	std::cerr << "Profiling module " << appName << std::endl;
	std::cerr << "===============================================" << std::endl;

	// routine instrumentation (for debugging/development only)
	RTN_AddInstrumentFunction(InstrumentRoutine, NULL);

	// some late patching :-)
	patchPEB();

	// Start the program, never returns
	PIN_StartProgram();

	// Stop libdft engine (typically not reached but make the compiler happy)
	libdft_die();

	// Exit program
	return EXIT_SUCCESS;
}