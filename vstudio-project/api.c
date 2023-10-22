#include "ntdll.h"
#include "hash.h"

PPEB GetCurrentPeb()
{
	return ((PTEB)__readgsqword(0x30))->ProcessEnvironmentBlock;
}

PVOID fnGetModuleHandle(DWORD dwHash)
{

	PPEB pCurrentPeb = GetCurrentPeb();
	PVOID pListParserFirstEntry = pCurrentPeb->Ldr->InLoadOrderModuleList.Flink;

	PLIST_ENTRY pParser = (PLIST_ENTRY)pListParserFirstEntry;

	if (dwHash == NULL)
	{
		return ((PLDR_DATA_TABLE_ENTRY)pParser)->DllBase;
	}
	else
	{
		do
		{
			PLDR_DATA_TABLE_ENTRY pTableEntry = (PLDR_DATA_TABLE_ENTRY)pParser;
			if (dwHash == HashStringDjb2W(pTableEntry->BaseDllName.Buffer))
				return pTableEntry->DllBase;

			pParser = pParser->Flink;
		} while (pParser->Flink != pListParserFirstEntry);
	}
	return 0;
}

PVOID fnGetProcAddr(PVOID pModuleAddr, DWORD dwHash)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)pModuleAddr + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)pModuleAddr + pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pImgExportDirectory->NumberOfFunctions; i++)
	{
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		PVOID pFunctionAddress = (PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];

		if (dwHash == HashStringDjb2A(pczFunctionName))
			return pFunctionAddress;

	}
	return NULL;
}

VOID fnMemcpy(PBYTE dst, PBYTE src, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
		dst[i] = src[i];
	
}

DWORD fnStrLenA(LPSTR str)
{
	DWORD dwCounter = 0;
	while (str[dwCounter] != 0x00)
		dwCounter++;

	return dwCounter;
}


PVOID FindRetGadget(PVOID pBaseAddr)
{
	while (TRUE)
	{
		if (
			((PBYTE)pBaseAddr)[0] == 0xC3
			)
			return pBaseAddr;
		else
			((UINT_PTR)pBaseAddr)++;
	}
}

