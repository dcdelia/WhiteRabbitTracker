/* ===================================================================== */
/* Define taint color                                                    */
/* ===================================================================== */
#define TAINT_COLOR_1 0x01
#define TAINT_COLOR_2 0x02
#define TAINT_COLOR_3 0x04
#define TAINT_COLOR_4 0x08
#define TAINT_COLOR_5 0x10
#define TAINT_COLOR_6 0x20
#define TAINT_COLOR_7 0x40
#define TAINT_COLOR_8 0x80

/* ============================================================================= */
/* Define macro to taint a register using thread_ctx_ptr and GPR from libdft     */
/* ============================================================================= */
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)

/* ===================================================================== */
/* Enable/disable tainting capabilities                                  */
/* ===================================================================== */
enum taintTrack {
	// Low-level
	TT_CPUID,
	TT_RDTSC,
	TT_IN,
	TT_OBSIDIUM_DISK_DRIVE,
	// Windows syscalls
	TT_NTCREATEFILE,
	TT_NTOPENKEY,
	TT_NTENUMERATEKEY,
	TT_NTQUERYVALUEKEY,
	TT_NTQIP_DEBUGFLAG,
	TT_NTQIP_DEBUGOBJECT,
	TT_NTQIP_PROCESSBASICINFO,
	TT_NTQSI_PROCESSINFO,
	TT_NTQSI_MODULEINFO,
	TT_NTQSI_FIRMWAREINFO,
	TT_NTQSI_KERNELINFO,
	TT_NTQUERYATTRIBUTESFILE,
	TT_NTFINDWINDOW,
	// DLL functions 
	TT_ISDEBUGGERPRESENT,
	TT_CHECKREMOTEDEBUGGER,
	TT_ENUMPROCESSES,
	TT_PROCESS32FIRSTNEXT,
	TT_GETDISKFREESPACE,
	TT_GLOBALMEMORYSTATUS,
	TT_GETSYSTEMINFO,
	TT_GETCURSORPOS,
	TT_GETMODULEFILENAME,
	TT_GETDEVICEDRIVERNAME,
	TT_GETADAPTERSINFO,
	TT_ENUMDISPLAYSETTINGS,
	TT_GETTICKCOUNT,
	TT_ICMPSENDECHO,
	TT_LOADLIBRARY,
	TT_GETUSERNAME,
	TT_FINDWINDOW,
	// leftovers
	TT_BLOCKINPUT,
	TT_SETUPDEVICEREGISTRY,
	// for sizing
	TT_TOTAL_SIZE
};

extern uint8_t policyForTT[TT_TOTAL_SIZE]; // storage in main.cpp

#define	GET_TAINT_COLOR(x)	(policyForTT[(x)])

/*** Hard-wired policy ***/
// Low-level instructions
#define TAINT_CPUID                  1 // color 2
#define TAINT_RDTSC                  0
#define TAINT_IN                     0
#define TAINT_OBSIDIUM_DISK_DRIVE    0
// Windows syscalls
#define TAINT_NTCREATEFILE           0
#define TAINT_NTOPENKEY              0
#define TAINT_NTENUMERATEKEY         0
#define TAINT_NTQUERYVALUEKEY        0
#define TAINT_NTQIP_DEBUGFLAG        0
#define TAINT_NTQIP_DEBUGOBJECT      0
#define TAINT_NTQSI_PROCESSINFO      1 // color 5
#define TAINT_NTQSI_MODULEINFO       1 // color 4
#define TAINT_NTQSI_FIRMWAREINFO     0
#define TAINT_NTQSI_KERNELINFO       1 // color 6
#define TAINT_NTQUERYATTRIBUTESFILE  1
#define TAINT_NTFINDWINDOW           0
// Function calls
#define TAINT_ISDEBUGGERPRESENT      0
#define TAINT_CHECKREMOTEDEBUGGER    1
#define TAINT_ENUMPROCESSES          0
#define TAINT_PROCESS32FIRSTNEXT     0
#define TAINT_GETDISKFREESPACE       0
#define TAINT_GLOBALMEMORYSTATUS     0
#define TAINT_GETSYSTEMINFO          0
#define TAINT_GETCURSORPOS           0
#define TAINT_GETMODULEFILENAME      0
#define TAINT_GETDEVICEDRIVERNAME    0 // color 3
#define TAINT_GETADAPTERSINFO        1
#define TAINT_ENUMDISPLAYSETTINGS    1 // color 7
#define TAINT_GETTICKCOUNT           0
#define TAINT_ICMPSENDECHO           0
#define TAINT_LOADLIBRARY            1 // color 8
#define TAINT_GETUSERNAME            0
#define TAINT_FINDWINDOW             0