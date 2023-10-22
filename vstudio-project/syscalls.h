#pragma once

#include <Windows.h>

#include "hash_k32.h"
#include "hash_ntdll.h"
#include "api.h"


typedef struct _NT_CALL {
	PVOID pFunctionAddr;
	PVOID pJmpAddr;
	DWORD dwSyscall;
} NT_CALL, * PNT_CALL;

typedef struct _SYSCALL {
	PVOID pNtdll;

	NT_CALL NtAllocateVirtualMemory;
	NT_CALL NtProtectVirtualMemory;
	NT_CALL NtSetContextThread;
	NT_CALL NtGetContextThread;
	NT_CALL NtFreeVirtualMemory;
	NT_CALL NtTerminateProcess;
} SYSCALL, * PSYSCALL;


BOOL InitSyscall(PSYSCALL pSyscall);
extern VOID		ntPrepare(DWORD, PVOID);
extern NTSTATUS ntCall();