#include "loaddll.h"

PVOID LoadLib(LPSTR lpLibraryName)
{
	PVOID pNtdll = fnGetModuleHandle(0x22d3b5ed);

	PVOID pLdrLoadDll = fnGetProcAddr(pNtdll, HASH_LdrLoadDll);
	PVOID pRtlAnsiStringToUnicodeString = fnGetProcAddr(pNtdll, HASH_RtlAnsiStringToUnicodeString);

	STRING strDll = { 0 };
	strDll.Buffer = lpLibraryName;
	strDll.Length = strDll.MaximumLength = fnStrLenA(lpLibraryName);

	UNICODE_STRING uniDll = { 0 };
	SPOOF(pRtlAnsiStringToUnicodeString, &uniDll, &strDll, TRUE);

	HMODULE hModule = NULL;
	NTSTATUS status = SPOOF(pLdrLoadDll, NULL, NULL, &uniDll, &hModule);
	if (status != 0)
		return 0x00;

	return hModule;
}