#ifndef _PUBLIC_H
#define _PUBLIC_H

#include "headers.h"


#define PROCESS_QUERY_INFORMATION (0x0400)
#define SEC_IMAGE 0x1000000

///////////////////////////////////////////////////////////////////////////////////

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY32
{
	ULONG 	Reserved[2];
	PVOID  	Base;
	ULONG  	Size;
	ULONG  	Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  ModuleNameOffset;
	CHAR  	ImageName[256];

} SYSTEM_MODULE_INFORMATION_ENTRY32, *PSYSTEM_MODULE_INFORMATION_ENTRY32;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY64
{
	ULONG 	Reserved[4];
	PVOID  	Base;
	ULONG  	Size;
	ULONG  	Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  ModuleNameOffset;
	CHAR  	ImageName[256];

} SYSTEM_MODULE_INFORMATION_ENTRY64, *PSYSTEM_MODULE_INFORMATION_ENTRY64;

typedef struct _SYSTEM_MODULE_INFORMATION32 // Information Class 11
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY32 Module[1];

} SYSTEM_MODULE_INFORMATION32, *PSYSTEM_MODULE_INFORMATION32;

typedef struct _SYSTEM_MODULE_INFORMATION64 // Information Class 11
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY64 Module[1];

} SYSTEM_MODULE_INFORMATION64, *PSYSTEM_MODULE_INFORMATION64;

#ifdef _WIN64
typedef SYSTEM_MODULE_INFORMATION_ENTRY64      	SYSTEM_MODULE_INFORMATION_ENTRY;
typedef PSYSTEM_MODULE_INFORMATION_ENTRY64    	PSYSTEM_MODULE_INFORMATION_ENTRY;
typedef SYSTEM_MODULE_INFORMATION64             SYSTEM_MODULE_INFORMATION;
typedef PSYSTEM_MODULE_INFORMATION64            PSYSTEM_MODULE_INFORMATION;
#else
typedef SYSTEM_MODULE_INFORMATION_ENTRY32      	SYSTEM_MODULE_INFORMATION_ENTRY;
typedef PSYSTEM_MODULE_INFORMATION_ENTRY32     	PSYSTEM_MODULE_INFORMATION_ENTRY;
typedef SYSTEM_MODULE_INFORMATION32            	SYSTEM_MODULE_INFORMATION;
typedef PSYSTEM_MODULE_INFORMATION32           	PSYSTEM_MODULE_INFORMATION;
#endif

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32 {
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	ULONG Mutant;                      // INITIAL_PEB structure is also updated.

	ULONG ImageBaseAddress;
	ULONG Ldr;
}PEB32,*PPEB32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY32 HashLinks;
		struct {
			ULONG SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			ULONG LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
}RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
}PEB,*PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
#if DEVL
	,MemoryWorkingSetInformation
#endif
	,MemoryMappedFilenameInformation
	,MemoryRegionInformation
	,MemoryWorkingSetExInformation

} MEMORY_INFORMATION_CLASS;

typedef struct _IMAGE_NAME_INFO{
	UNICODE_STRING Name;
	CHAR Buffer[1];
}IMAGE_NAME_INFO,*PIMAGE_NAME_INFO;

NTSYSAPI
	PIMAGE_NT_HEADERS
	NTAPI
	RtlImageNtHeader(
	PVOID Base
	);

NTSYSAPI
	PPEB
	NTAPI
	PsGetProcessPeb(
	IN PEPROCESS Process
	);

NTSYSAPI
	UCHAR*
	NTAPI
	PsGetProcessImageFileName(
	IN PEPROCESS Process
	);

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTSYSAPI
	VOID
	NTAPI
	KeInitializeApc (
	OUT PRKAPC Apc,
	IN PRKTHREAD Thread,
	IN KAPC_ENVIRONMENT Environment,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
	IN PKNORMAL_ROUTINE NormalRoutine OPTIONAL,
	IN KPROCESSOR_MODE ApcMode OPTIONAL,
	IN PVOID NormalContext OPTIONAL
	);

NTSYSAPI
	BOOLEAN
	NTAPI
	KeInsertQueueApc (
	IN PRKAPC Apc,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN KPRIORITY Increment
	);

NTSYSAPI
	NTSTATUS
	NTAPI
	ZwQuerySystemInformation (
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

//////////////////////////////////////////////////////////////////////////////////////

NTSTATUS GlobalInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryString);
NTSTATUS GlobalUnInit(PDRIVER_OBJECT DriverObject);

VOID CreateProcessNotifyRoutine(
	__in HANDLE ParentId,
	__in HANDLE ProcessId,
	__in BOOLEAN Create
	);
VOID LoadImageNotifyRoutinue(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo
	);

PPEB GetProcessPeb(IN PEPROCESS Process);
NTSTATUS 
	NTAPI
	GetProcessImageNameByProcess(IN PEPROCESS Process,
	OUT LPWSTR lpszImageName,
	IN PULONG Length
	);


PVOID GetExportFuncAddress(PVOID pImageBase,LPSTR lpszFunName);
BOOLEAN GetProcessModuleInfo(PPEB Peb, LPWSTR lpszModuleName, PVOID *pImageBase, PSIZE_T pSize);

NTSTATUS GetKernelModuleBase(LPCSTR ImageName, PVOID* pImageBaseAddr, PULONG pImageSize);
NTSTATUS ConvertWCharToChar(WCHAR* lpwzBuffer, CHAR* lpszBuffer, DWORD dwOutCchLength);
WCHAR* GetFileNameByFullPath(WCHAR* lpszFullImagePath);

////////////////////////////////////////////////////////////////////////////////////////
//**********************************自定义结构体***************************************//
typedef struct _PROCINFO
{
	LIST_ENTRY ActiveListEntry;
	HANDLE     ProcessId;
	CHAR       lpszProcessImageName[MAX_PATH];
}ProcInfo, *PProcInfo;
///////////////////////////////////////////////////////////////////////////////////////

PVOID g_pKernelbase;
DWORD g_dwKernelSize;

PVOID g_pNtdllbase;
DWORD g_dwNtdllSize;

DWORD g_dwOsMajorVer;
DWORD g_dwOsMinorVer;
DWORD g_dwOsBuildNumber;

BOOLEAN    g_bInitProcessNotify;
BOOLEAN    g_bInitLoadImageNotify;
ERESOURCE  g_XProcessResource;
LIST_ENTRY g_XProcessList;

#define IS_WINDOWS8_OR_LATER()   ((g_dwOsMajorVer == 6 && g_dwOsMinorVer >= 2) || g_dwOsMajorVer > 6)
#define IS_WINDOWS7_OR_BEFORE()  ((g_dwOsMajorVer == 6 && g_dwOsMinorVer == 1) || g_dwOsMajorVer < 6)
#define IS_WINDOWSXP_OR_BEFORE()  (g_dwOsMajorVer == 5 && g_dwOsMinorVer <= 2)

#endif