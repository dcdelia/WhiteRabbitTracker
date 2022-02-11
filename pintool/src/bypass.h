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
	BP_ISDEBUGGERPRESENT,
	BP_BLOCKINPUT,
	BP_CHECKREMOTEDEBUGGER,
	//BP_ENUMPROCESSES,		// currently bypassed somewhere else
	BP_PROCESS32FIRSTNEXT,
	BP_GETDISKFREESPACE,
	BP_GLOBALMEMORYSTATUS,
	BP_GETSYSTEMINFO,
	BP_GETCURSORPOS,
	BP_GETMODULEFILENAME,
	BP_GETDEVICEDRIVERNAME,
	BP_GETADAPTERSINFO,
	BP_ENUMDISPLAYSETTINGS,	// no bypass available (?)
	BP_SETUPDEVICEREGISTRY,
	BP_GETTICKCOUNT,
	BP_SETTIMER,
	BP_WFSO,
	BP_ICMPSENDECHO,
	BP_LOADLIBRARY,
	BP_GETUSERNAME,
	BP_FINDWINDOW,
	BP_CLOSEHANDLE,
	/* special cases */
	BP_WMI,
	BP_CPUID,
	BP_RDTSC,
	BP_INT2D, // I think the bypass is broken...
	BP_IN_EAX_DX,
	BP_OBSIDIUM_DRIVECHECK,
	BP_OBSIDIUM_DEADPATH,
	// for sizing
	BP_TOTAL_SIZE
};

extern uint8_t policyForBP[BP_TOTAL_SIZE]; // storage in main.cpp

#define	BYPASS(x)	(policyForBP[(x)])