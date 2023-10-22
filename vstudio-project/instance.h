#include <Windows.h>

#include "api.h"
#include "loaddll.h"
#include "hash_k32.h"
#include "hash_ntdll.h"

typedef struct _WIN_MODULE {
	PVOID pKernel32;
	PVOID pNtdll;
	PVOID pCryptsp;
	PVOID pBcrypt;
} WIN_MODULE, * PWIN_MODULE;

typedef struct _WIN_FUNCTION {
	PVOID pTpReleaseCleanupGroupMembers;
	PVOID pNtContinue;
	PVOID pNtTestAlert;
	PVOID pNtAlertResumeThread;
	PVOID pRtlExitUserThread;

	PVOID pCreateEventW;
	PVOID pCreateThread;
	PVOID pGetThreadContext;
	PVOID pVirtualProtect;
	PVOID pWaitForSingleObject;
	PVOID pSetEvent;
	PVOID pQueueUserAPC;
	PVOID pTerminateThread;
	PVOID pCloseHandle;
	PVOID pLoadLibraryA;

	PVOID pSystemFunction032;

	PVOID pBCryptOpenAlgorithmProvider;
	PVOID pBCryptGenRandom;
	PVOID pBCryptCloseAlgorithmProvider;
} WIN_FUNCTION, * PWIN_FUNCTION;

typedef struct _INSTANCE_KRAKEN {
	WIN_MODULE wModule;
	WIN_FUNCTION wFunction;
} INSTANCE_KRAKEN, * PINSTANCE_KRAKEN;

VOID InitInstanceKraken(PINSTANCE_KRAKEN Inst);

typedef struct _HOOK_FUNCTION {
	PVOID pSleep;
	PVOID pLoadLibraryA;
	PVOID pVirtualAlloc;
} HOOK_FUNCTION, *PHOOK_FUNCTION;

typedef struct _HOOK_INSTANCE {
	PVOID			pModule;
	HOOK_FUNCTION wFunction;
} HOOK_INSTANCE, *PHOOK_INSTANCE;

typedef struct _MAIN_FUNCTION {
	PVOID pCreateFileA;
	PVOID pGetFileSize;
	PVOID pReadFile;
	PVOID pCloseHandle;
	PVOID pAddVectoredExceptionHandler;
	PVOID pGetCurrentThread;
} MAIN_FUNCTION, *PMAIN_FUNCTION;

typedef struct _MAIN_MODULE {
	PVOID Kernel32;
	PVOID Ntdll;
} MAIN_MODULE, *PMAIN_MODULE;

typedef struct _MAIN_INSTANCE {
	MAIN_MODULE		wModule;
	MAIN_FUNCTION wFunction;
} MAIN_INSTANCE, * PMAIN_INSTANCE;

typedef struct _LOADER_INSTANCE {
	MAIN_INSTANCE main;
	HOOK_INSTANCE hook;
} LOADER_INSTANCE, * PLOADER_INSTANCE;

VOID InitLoaderInstance(PLOADER_INSTANCE InstLdr);