#include "LoggingInfo.h"

/* ===================================================================== */
/* Define delimeter (default format: RVA;event)                          */
/* ===================================================================== */
#define DELIMITER ';'

/* ===================================================================== */
/* Utility function to extract a dll name from module name (parsing)     */
/* ===================================================================== */
std::string LoggingInfo::get_dll_name(const std::string& str) {
	std::size_t len = str.length();
	std::size_t found = str.find_last_of("/\\");
	std::size_t ext = str.find_last_of(".");
	if (ext >= len) return "";

	std::string name = str.substr(found + 1, ext - (found + 1));
	std::transform(name.begin(), name.end(), name.begin(), tolower);
	return name;
}

/* ===================================================================== */
/* Log API call with dll name (module) and function name (func)          */
/* ===================================================================== */
void LoggingInfo::logCall(const ADDRINT prevModuleBase, const ADDRINT prevAddr, bool isRVA, const std::string module, const std::string func) {
	// Check if the file exist
	if (!createFile()) {
		return;
	} 
	// Write the RVA address into the output file 
	ADDRINT rva = (isRVA) ? prevAddr : prevAddr - prevModuleBase;
	if (!isRVA) {
		m_traceFile << "> " << prevModuleBase << "+";
	}
	m_traceFile << std::hex << rva << DELIMITER;

	// Extract the DLL name and write it into the output file (substitute with get_dll_name(module) for a short log)
	m_traceFile << module;

	// If the function name exists, write it into the output file
	if (func.length() > 0) {
		m_traceFile << "." << func;
	}
	// Otherwise, write end line and flush 
	m_traceFile << std::endl;
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log call to a called page base (shellcode?)                           */
/* ===================================================================== */
void LoggingInfo::logCall(const ADDRINT prevBase, const ADDRINT prevAddr, const ADDRINT calledPageBase, const ADDRINT callAddr) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the called page base and relative RVA to the output file
	if (prevBase) {
		m_traceFile << "> " << prevBase << "+";
	}
	const ADDRINT rva = callAddr - calledPageBase;
	m_traceFile 
		<< std::hex << prevAddr
		<< DELIMITER
		<< "called: ?? [" << calledPageBase << "+" << rva << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a section change                                                  */
/* ===================================================================== */
void LoggingInfo::logSectionChange(const ADDRINT prevAddr, std::string name) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the section change with relative previous address and section name
	m_traceFile
		<< std::hex << prevAddr
		<< DELIMITER
		<< "section: [" << name << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new section change                                              */
/* ===================================================================== */
void LoggingInfo::logNewSectionCalled(const ADDRINT prevAddr, std::string prevSection, std::string currSection) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write a new section change with relative previous address, previous section name and new section name
	m_traceFile
		<< std::hex << prevAddr
		<< DELIMITER
		<< "[" << prevSection << "] -> [" << currSection << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log a new exception                                                   */
/* ===================================================================== */
void LoggingInfo::logException(const ADDRINT addrFrom, std::string reason) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// Write the new exception with relative previous address
	m_traceFile
		<< std::hex << addrFrom
		<< DELIMITER
		<< "exception: [" << reason << "]"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log the cpuid instruction                                             */
/* ===================================================================== */
void LoggingInfo::logCpuid(const ADDRINT base, const ADDRINT rva, const ADDRINT param) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// If the base address exists, log it
	if (base) {
		m_traceFile << "> " << std::hex << base << "+";
	}
	// Log the cpuid instruction
	m_traceFile
		<< std::hex << rva
		<< DELIMITER
		<< "CPUID:"
		<< std::hex << param
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log the rdtsc instruction                                             */
/* ===================================================================== */
void LoggingInfo::logRdtsc(const ADDRINT base, const ADDRINT rva) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// If the base address exists, log it
	if (base) {
		m_traceFile << "> " << std::hex << base << "+";
	}
	// Log the rdtsc instruction
	m_traceFile
		<< std::hex << rva
		<< DELIMITER
		<< "RDTSC"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log the int 2d instruction                                            */
/* ===================================================================== */
void LoggingInfo::logInt2d(const ADDRINT base, const ADDRINT rva) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// If the base address exists, log it
	if (base) {
		m_traceFile << "> " << std::hex << base << "+";
	}
	// Log the rdtsc instruction
	m_traceFile
		<< std::hex << rva
		<< DELIMITER
		<< "INT 2D"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}

/* ===================================================================== */
/* Log the 'in eax, dx' instruction                                      */
/* ===================================================================== */
void LoggingInfo::logInEaxDx(const ADDRINT base, const ADDRINT rva) {
	// Check if the file exist
	if (!createFile()) {
		return;
	}
	// If the base address exists, log it
	if (base) {
		m_traceFile << "> " << std::hex << base << "+";
	}
	// Log the rdtsc instruction
	m_traceFile
		<< std::hex << rva
		<< DELIMITER
		<< "IN EAX, DX"
		<< std::endl;
	// Flush the file
	m_traceFile.flush();
}