#pragma once
#include <stdint.h>

enum bypass {
	/* syscalls */
	BP_NTDELAYEXEC,
	BP_NTCREATEFILE,
	BP_NTOPENKEY,
	BP_NTENUMKEY,
	BP_NTQUERYVALUEKEY,
	BP_NTQUERYINFOPROC_7,	// ProcessDebugPort
	BP_NTQUERYINFOPROC_30,	// ProcessDebugObjectHandle
	BP_NTQUERYINFOPROC_31,	// ProcessDebugFlags
	BP_NTQUERYSYSINFO_5,	// SystemProcessInformation
	BP_NTQUERYSYSINFO_11,	// SystemModuleInformation
	BP_NTQUERYSYSINFO_76,	// SystemFirmwareTableInformation
	//BP_NTQUERYSYSINFO_35,	// SystemKernelDebuggerInformation (no bypass needed)
	BP_NTQUERYATTRFILE,
	BP_NTUSERFINDWIND,
	//BP_NTWAITFORSOBJ,		// disabled as this is currently IcmpSendEcho-specific
	/* APIs */

	/* special instructions */

	// for sizing
	BP_TOTAL_SIZE
};

extern uint8_t policyForBP[BP_TOTAL_SIZE]; // storage in main.cpp

#define	BYPASS(x)	(policyForBP[(x)])