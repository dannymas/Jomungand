#include "hwbp.h"

// INDIRECT SYSCALL + SPOOF - OK
BOOL SetHWBP(HANDLE hThread, DWORD dwReg, DWORD64 dwAddr, PSYSCALL syscall)
{
    if (dwReg < 0 || dwReg > 3)
        return FALSE;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ntPrepare(syscall->NtGetContextThread.dwSyscall, syscall->NtGetContextThread.pJmpAddr);
    NTSTATUS status = SPOOF(ntCall, hThread, &ctx);

    if (status != 0)
        return FALSE;

    switch (dwReg)
    {
    case 0:
        ctx.Dr0 = dwAddr;
        ctx.Dr7 |= (1 << 0);
        ctx.Dr7 &= ~(1 << 16);
        ctx.Dr7 &= ~(1 << 17);
        break;

    case 1:
        ctx.Dr1 = dwAddr;
        ctx.Dr7 |= (1 << 2);
        ctx.Dr7 &= ~(1 << 20);
        ctx.Dr7 &= ~(1 << 21);
        break;

    case 2:
        ctx.Dr2 = dwAddr;
        ctx.Dr7 |= (1 << 4);
        ctx.Dr7 &= ~(1 << 24);
        ctx.Dr7 &= ~(1 << 25);
        break;

    case 3:
        ctx.Dr3 = dwAddr;
        ctx.Dr7 |= (1 << 6);
        ctx.Dr7 &= ~(1 << 29);
        ctx.Dr7 &= ~(1 << 28);
        break;

    default:
        return FALSE;
    }

    ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;

    ntPrepare(syscall->NtSetContextThread.dwSyscall, syscall->NtSetContextThread.pJmpAddr);
    status = SPOOF(ntCall, hThread, &ctx);

    if (status != 0)
        return FALSE;

    return TRUE;
}

// INDIRECT SYSCALL + SPOOF - OK
BOOL RemoveHWBP(HANDLE hThread, DWORD dwReg, PSYSCALL syscall)
{
    if (dwReg < 0 || dwReg > 3)
        return FALSE;

    CONTEXT ctx = { 0 };
    NTSTATUS status = 0;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ntPrepare(syscall->NtGetContextThread.dwSyscall, syscall->NtGetContextThread.pJmpAddr);
    status = SPOOF(ntCall, hThread, &ctx);

    if (status != 0)
        return FALSE;
    /*
    if (!GetThreadContext(hThread, &ctx))
        return FALSE;*/

    switch (dwReg)
    {
    case 0:
        ctx.Dr0 = 0;
        break;

    case 1:
        ctx.Dr1 = 0;
        break;

    case 2:
        ctx.Dr2 = 0;
        break;

    case 3:
        ctx.Dr3 = 0;
        break;

    default:
        return FALSE;
    }

    ctx.ContextFlags |= CONTEXT_DEBUG_REGISTERS;

    ntPrepare(syscall->NtSetContextThread.dwSyscall, syscall->NtSetContextThread.pJmpAddr);
    status = SPOOF(ntCall, hThread, &ctx);

    if (status != 0)
        return FALSE;

    return TRUE;
}
