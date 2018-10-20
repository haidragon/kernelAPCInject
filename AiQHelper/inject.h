#ifndef _INJECT_H
#define _INJECT_H

#include "headers.h"

typedef struct _SHELLCODE_INJECT_APC
{
	BYTE      ShellCodeApc[0x1000];
	WCHAR     szDllFullPath[MAX_PATH];
	CHAR      szProcedureName[MAX_PATH];            //防止出现类粉碎名称导致的长度过长
	ULONG_PTR LdrLoadDllFunc;
	ULONG_PTR LdrGetProcedureAddressFunc;

}ShellCodeInjectApc, *PShellCodeInjectApc;

////////////////////////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS (NTAPI* LDRLOADDLL)(IN PWSTR SearchPath OPTIONAL,
	IN PULONG DllCharacteristics OPTIONAL,
	IN PUNICODE_STRING DllName,
	OUT PVOID *BaseAddress);

typedef NTSTATUS (NTAPI* LDRGETPROCEDUREADDRESS)(IN PVOID BaseAddress,
	IN PANSI_STRING Name,
	IN ULONG Ordinal,
	OUT PVOID *ProcedureAddress);
////////////////////////////////////////////////////////////////////////////////////////////////

VOID InjectDllByApcS1KernelRoutine (
	__in struct _KAPC *Apc,
	__deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,
	__deref_inout_opt PVOID *NormalContext,
	__deref_inout_opt PVOID *SystemArgument1,
	__deref_inout_opt PVOID *SystemArgument2
	);

VOID InjectDllByApcS1NormalRoutine (
	__in_opt PVOID NormalContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
	);

NTSTATUS GetProcessFirstEThread(HANDLE ProcessId, PETHREAD* pEThread);
NTSTATUS InjectDllIndirectByUserApc(HANDLE ProcessId);
NTSTATUS InjectDllByApc_Step1(HANDLE ProcessId);

BOOL InjectDllUserMode(PShellCodeInjectApc BaseData);
VOID _nopfunc_userapc_end();

#endif