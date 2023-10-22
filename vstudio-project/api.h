#pragma once
#include "ntdll.h"

typedef struct _USTRING
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING, * PUSTRING;

PVOID	fnGetProcAddr(PVOID pModuleAddr, DWORD dwHash);
PVOID	fnGetModuleHandle(DWORD dwHash);
PPEB	GetCurrentPeb();
VOID	fnMemcpy(PBYTE dst, PBYTE src, DWORD dwSize);
DWORD	fnStrLenA(LPSTR str);
PVOID	FindRetGadget(PVOID pBaseAddr);
