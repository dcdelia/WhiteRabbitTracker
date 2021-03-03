#include "functions.h"
#include "types.h"
#include "process.h"
#include <string>
#include <iostream>

/* ===================================================================== */
/* Define random stapp when we need to fill fields                       */
/* ===================================================================== */
#define CHAR_SDI	's'
#define STR_GUI_1A	"W" 
#define STR_GUI_1B	"a"
#define STR_GUI_2	"WantSuppli"
/* ===================================================================== */
/* Define taint color                                                    */
/* ===================================================================== */
#define TAINT_COLOR_1 0x01
#define TAINT_COLOR_2 0x02
#define TAINT_COLOR_3 0x03
#define TAINT_COLOR_4 0x04
#define TAINT_COLOR_5 0x05
#define TAINT_COLOR_6 0x06
#define TAINT_COLOR_7 0x07
#define TAINT_COLOR_8 0x08

/* ===================================================================== */
/* Instruction description for instruction tainting                      */
/* ===================================================================== */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

namespace Functions {
	/* ===================================================================== */
	/* Hook/API map (internal use)                                           */
	/* ===================================================================== */
	static std::map<std::string, int> fMap;

	/* ===================================================================== */
	/* Initialization function to define API map                             */
	/* ===================================================================== */
	void Init() {
		// Define API map
		fMap.insert(std::pair<std::string, int>("IsDebuggerPresent", ISDEBUGGERPRESENT_INDEX));
		fMap.insert(std::pair<std::string, int>("CheckRemoteDebuggerPresent", CHECKREMOTEDEBUGGERPRESENT_INDEX));
		fMap.insert(std::pair<std::string, int>("EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("K32EnumProcesses", ENUMPROCESSES_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32First", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32FirstW", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32Next", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("Process32NextW", PROCESS32FIRSTNEXT_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceEx", GETDISKFREESPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceA", GETDISKFREESPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GetDiskFreeSpaceExW", GETDISKFREESPACE_INDEX));
		fMap.insert(std::pair<std::string, int>("GlobalMemoryStatusEx", GLOBALMEMORYSTATUS_INDEX));
		fMap.insert(std::pair<std::string, int>("GetSystemInfo", GETSYSTEMINFO_INDEX));
		fMap.insert(std::pair<std::string, int>("GetTickCount", GETTICKCOUNT_INDEX));
		fMap.insert(std::pair<std::string, int>("GetUserName", GETUSERNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("GetUserNameA", GETUSERNAME_INDEX));
		fMap.insert(std::pair<std::string, int>("GetCursorPos", GETCURSORPOS_INDEX));

		// ACTUALLY DEFINED FOR EACH INSTRUCTION IN LIBDFT_API

		// Define instruction hooking for taint analysis (taint sinks) - control transfer instruction (call, jmp, ret????)
		/**
		// Instrument near call
		(void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR], dta_instrument_jmp_call);
		// Instrument jmp
		(void)ins_set_post(&ins_desc[XED_ICLASS_JMP], dta_instrument_jmp_call);
		**/
	}


	// Scan the image and try to hook any found function specified in the API map
	void AddHooks(IMG img) {
		// Iterate over functions that we want to hook/replace
		for (std::map<std::string, int>::iterator it = fMap.begin(), end = fMap.end(); it != end; ++it) {
			// Get the function name 
			const char* func_name = it->first.c_str();
			// Get a pointer to the function
			RTN rtn = RTN_FindByName(img, func_name);
			// Check if the routine (function) is valid
			if (rtn != RTN_Invalid()) {
				int index = it->second;
				// Open the routine
				RTN_Open(rtn);

				// Switch-case over possible APIs described in the API map
				switch (index) {
					// API IsDebuggerPresent
					case ISDEBUGGERPRESENT_INDEX:
						// Add hooking with IPOINT_AFTER to retrieve the API output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)IsDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_END);
						break;
					// API CheckRemoteDebuggerPresent 
					case CHECKREMOTEDEBUGGERPRESENT_INDEX:
						// Add hooking with IPOINT_AFTER to retrieve the API output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)CheckRemoteDebuggerPresentExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_END);
						break;
					// API EnumProcesses and K32Enumprocesses
					case ENUMPROCESSES_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve process array and returned bytes)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnumProcessesEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_END);
						// Add hooking with IPOINT_AFTER to taint the stored values
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)EnumProcessesExit,
							IARG_REG_VALUE, REG_EAX,
							IARG_END);
						break;
					// API PRocess32First and Process32Next
					case PROCESS32FIRSTNEXT_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve process informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Process32FirstNextEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_END);
					// API GetDiskFreeSpace
					case GETDISKFREESPACE_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve disk informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetDiskFreeSpaceEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 1,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 2,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 3,
							IARG_END);
					// API GlobalMemoryStatus
					case GLOBALMEMORYSTATUS_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve memory informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GlobalMemoryStatusEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
					// API GetSystemInfo
					case GETSYSTEMINFO_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve system informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetSystemInfoEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
					// API GetTickCount
					case GETTICKCOUNT_INDEX:
						// Add hooking with IPOINT_AFTER to retrieve the API output
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountExit,
							IARG_CONTEXT,
							IARG_REG_VALUE, REG_EAX,
							IARG_END);
					// API GetCursorPos
					case GETCURSORPOS_INDEX:
						// Add hooking with IPOINT_BEFORE to retrieve the API input (retrieve pointer informations)
						RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)GetCursorPosEntry,
							IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
							IARG_END);
					// screen resolution (GetDesktopWindow, GetWindowRect, GetSystemMetrics), GetUserName, GetComputerName, ....
					default:
						break;

				}
				// Close the routine
				RTN_Close(rtn);
			}
		}
	}
}

/* API HOOKS (taint sources) begin here */

VOID taintRegisterEax(CONTEXT* ctx) {
	thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); // thread_ctx_ptr or REG_EAX???
	tag_t reset_tags[] = R32TAG(REG32_INDX(REG_EAX));
	addTaintRegister(thread_ctx, REG32_INDX(REG_EAX), reset_tags, true); // double tags?? gpr???
}

VOID IsDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax) {
	// taint source: API return value
	taintRegisterEax(ctx);
}

VOID CheckRemoteDebuggerPresentExit(CONTEXT* ctx, ADDRINT eax) {
	// taint source: API return value
	taintRegisterEax(ctx);
}

VOID EnumProcessesEntry(ADDRINT* pointerToProcessesArray, ADDRINT* pointerToBytesProcessesArray) {
	// store the lpProcessesArray and bytes variable into global variables
	State::globalState* gs = State::getGlobalState();
	gs->pointerToLpidProcess = pointerToProcessesArray;
	gs->pointerToBytesLpidProcess = pointerToBytesProcessesArray;
}

VOID EnumProcessesExit(ADDRINT eax) {
	// taint source: API return value
	State::globalState* gs = State::getGlobalState();
	//addTaintMemory(*gs->pointerToLpidProcess, *gs->pointerToBytesLpidProcess, TAINT_COLOR_1, true, "EnumProcesses");  // big taint big slow down
}

VOID Process32FirstNextEntry(ADDRINT* pointerToProcessInformations) {
	// taint source: API processes array+
	addTaintMemory(*pointerToProcessInformations, sizeof(W::PROCESSENTRY32), TAINT_COLOR_1, true, "Process32First/Process32Next"); // lot of taints??
}

VOID GetDiskFreeSpaceEntry(ADDRINT* pointerToLpFreeBytesAvailableToCaller, ADDRINT* pointerToLpTotalNumberOfBytes, ADDRINT* pointerToLpTotalNumberOfFreeBytes) {
	// taint source: disk informations
	addTaintMemory(*pointerToLpFreeBytesAvailableToCaller, sizeof(W::PULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pointerToLpTotalNumberOfBytes, sizeof(W::PULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
	addTaintMemory(*pointerToLpTotalNumberOfFreeBytes, sizeof(W::PULARGE_INTEGER), TAINT_COLOR_1, true, "GetDiskFreeSpace");
}

VOID GlobalMemoryStatusEntry(ADDRINT* pointerToLpBuffer) {
	// taint source: memory informations
	addTaintMemory(*pointerToLpBuffer, sizeof(W::MEMORYSTATUSEX), TAINT_COLOR_1, true, "GlobalMemoryStatus");
}

VOID GetSystemInfoEntry(ADDRINT* pointerToLpSystemInfo) {
	// taint source: system informations
	addTaintMemory(*pointerToLpSystemInfo, sizeof(W::SYSTEM_INFO), TAINT_COLOR_1, true, "GetSystemInfo");
}

VOID GetTickCountExit(CONTEXT* ctx, ADDRINT eax) {
	// taint source: API return value
	taintRegisterEax(ctx);
}

VOID GetCursorPosEntry(ADDRINT* pointerToLpPoint) {
	// taint source: mouse pointer informations
	addTaintMemory(*pointerToLpPoint, sizeof(W::POINT), TAINT_COLOR_1, true, "GetCursorPos");
}


/* END OF API HOOKS */

// ACTUALLY DEFINED FOR EACH INSTRUCTION IN LIBDFT_API

/* INSTRUCTION HOOKS (taint sinks) begin here */

/**
static void dta_instrument_jmp_call(INS ins) {
	instrumentForTaintCheck(ins);
}
**/

/* END OF INSTRUCTION HOOKS */