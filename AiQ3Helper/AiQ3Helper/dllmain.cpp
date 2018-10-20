// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

HMODULE _gModuleBase;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			_gModuleBase = hModule;
			DbgPrintW(L"DllMain Entry.....");

			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD WINAPI LoopThread(IN LPVOID lparameter)
{
	do 
	{
		DbgPrintW(L"LoopThread zzz.....");
		Sleep(1000);

	} while (TRUE);

	return 0;
}

extern "C" VOID AiQ3Helper001()
{
	DbgPrintW(L"AiQ3Helper001 Entry.....");
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LoopThread, NULL, 0, NULL);
	if (hThread)
	{
		CloseHandle(hThread);
	}
}