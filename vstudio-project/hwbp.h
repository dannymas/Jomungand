#include <Windows.h>

#include "syscalls.h"
#include "spoof.h"

BOOL SetHWBP(HANDLE hThread, DWORD dwReg, DWORD64 dwAddr, PSYSCALL syscall);
BOOL RemoveHWBP(HANDLE hThread, DWORD dwReg, PSYSCALL syscall);
