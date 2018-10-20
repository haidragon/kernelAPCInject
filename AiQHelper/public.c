#include "public.h"
#include "inject.h"

NTSTATUS GlobalInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryString)
{
	NTSTATUS Status          = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES oa;

	g_pKernelbase            = 0;
	g_dwKernelSize           = 0;
	g_pNtdllbase             = 0;
	g_dwNtdllSize            = 0;
	g_bInitProcessNotify     = FALSE;
	g_bInitLoadImageNotify   = FALSE;

	PsGetVersion(&g_dwOsMajorVer, &g_dwOsMinorVer, &g_dwOsBuildNumber, NULL);
	Status = GetKernelModuleBase(NULL, &g_pKernelbase, &g_dwKernelSize);
	if (!NT_SUCCESS(Status)){
		return Status;
	}

	// Win8之前可行，Win8之后需要在进程空间PEB查找
	if (IS_WINDOWS7_OR_BEFORE())
	{
		Status = GetKernelModuleBase("ntdll.dll", &g_pNtdllbase, &g_dwNtdllSize);
		if (!NT_SUCCESS(Status)){
			return Status;
		}
	}
 
 	Status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, FALSE);
	if (NT_SUCCESS(Status)) 
	{
		if (IS_WINDOWSXP_OR_BEFORE())
		{
			ExInitializeResourceLite(&g_XProcessResource);
			InitializeListHead(&g_XProcessList);

			Status = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutinue);
			if (NT_SUCCESS(Status)) {
				g_bInitLoadImageNotify = TRUE;
			}
		}
		g_bInitProcessNotify = TRUE;
	}

	return Status;
}

NTSTATUS GlobalUnInit(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS    Status    = STATUS_SUCCESS;
	PProcInfo    pProcInfo = NULL;
	PLIST_ENTRY ListPtr, ListHeader;


	if (g_bInitProcessNotify) {
 		Status = PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	}

	///////////////////////////////////////////////////////////////////////////
	//************************卸载XP下的LoadImage回调*************************//
	///////////////////////////////////////////////////////////////////////////

	if (IS_WINDOWSXP_OR_BEFORE())
	{
		KeEnterCriticalRegion();
		if (ExAcquireResourceSharedLite(&g_XProcessResource, TRUE))
		{
			while (!IsListEmpty(&g_XProcessList))
			{
				ListPtr = RemoveTailList(&g_XProcessList);
				pProcInfo = CONTAINING_RECORD(ListPtr, ProcInfo, ActiveListEntry);
				ExFreePool(pProcInfo);
			}

			ExReleaseResource(&g_XProcessResource);
			ExDeleteResourceLite(&g_XProcessResource);
		}
		KeLeaveCriticalRegion();

		if (g_bInitLoadImageNotify) {
			Status = PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutinue);
		}
	}

	return Status;
}

VOID LoadImageNotifyRoutinue(
	__in PUNICODE_STRING FullImageName,
	__in HANDLE ProcessId,                // pid into which image is being mapped
	__in PIMAGE_INFO ImageInfo
	)
{
	NTSTATUS    Status                      = STATUS_SUCCESS;
	PProcInfo   pProcInfo                   = NULL;
	PLIST_ENTRY ListPtr                     = NULL;
	BOOLEAN     bInject                     = FALSE;
	CHAR        lpszFullImageName[MAX_PATH] = { 0 };

	if (ProcessId != 0)
	{
		//  XP下加载exe时的调用堆栈：

		// 	b1c88c08 80644526 nt!PsCallImageNotifyRoutines+0x36
		// 	b1c88d0c 805d0e6b nt!DbgkCreateThread+0xa2
		// 	b1c88d50 805470de nt!PspUserThreadStartup+0x9d
		// 	00000000 00000000 nt!KiThreadStartup+0x16

		if (FullImageName) {

			// 1. 在进程List中查找当前进程是否存在
			KeEnterCriticalRegion();
			if (ExAcquireResourceSharedLite(&g_XProcessResource, TRUE))
			{
				ListPtr = g_XProcessList.Flink;
				for ( ; ListPtr != &g_XProcessList; ListPtr = ListPtr->Flink )
				{
					pProcInfo = CONTAINING_RECORD(ListPtr, ProcInfo, ActiveListEntry);
					if (pProcInfo->ProcessId == ProcessId) {

						Status = ConvertWCharToChar(GetFileNameByFullPath(FullImageName->Buffer), 
							lpszFullImageName, MAX_PATH);

						DbgPrint("[LoadImageNotifyRoutinue] ProcessId:%d, MapImageName:%wZ, pProcInfo->lpszProcessImageName:%s", 
							FullImageName, pProcInfo->lpszProcessImageName);

						if (NT_SUCCESS(Status) && !_stricmp(lpszFullImageName, pProcInfo->lpszProcessImageName)) {
							bInject = TRUE;
						}

						RemoveEntryList(ListPtr);
						ExFreePool(pProcInfo);
						break;
					}
				}
				ExAcquireResourceSharedLite(&g_XProcessResource, FALSE);
			}
			KeLeaveCriticalRegion();

			if (bInject)
			{
				InjectDllByApc_Step1(ProcessId);
			}
		}
	}
}

VOID CreateProcessNotifyRoutine(
	__in HANDLE ParentId,
	__in HANDLE ProcessId,
	__in BOOLEAN Create
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS EProcess = NULL;
	ULONG ulLength = MAX_PATH;
	UCHAR* szImageName = NULL;
	PKAPC Apc = NULL;

	if (Create == FALSE)
		return;

	Status = PsLookupProcessByProcessId(ProcessId, &EProcess);
	if (!NT_SUCCESS(Status) || !EProcess)
		return;

	do
	{

		szImageName = PsGetProcessImageFileName(EProcess);
		if (NULL == szImageName)
			break;

		DbgPrint("[CreateProcessNotifyRoutine] szImageName: %s", szImageName);
		if (_stricmp((char*)szImageName, "qq.exe") == 0 ||
			_stricmp((char*)szImageName, "iexplore.exe") == 0 ||
			_stricmp((char*)szImageName, "360se.exe") == 0) 
		{
			
			/* 
			 * 注：当前线程为父进程创建子进程的那个线程，当前子进程的初始化线程还没有得到执行机会，等待他的执行机会
			 * XP以及XP之前，在进程/线程回调中使用PsLookupThreadByThreadId不会成功，得等到PspCreateThread执行完
			 * 成之后，线程体GrantAccess被初始化才能成功
			 */
			if (IS_WINDOWSXP_OR_BEFORE())
			{
				KeEnterCriticalRegion();
				if (ExAcquireResourceSharedLite(&g_XProcessResource, TRUE))
				{
					PProcInfo Info = (PProcInfo)ExAllocatePoolWithTag(PagedPool, sizeof(ProcInfo), 'idba');
					if (Info) {

						memset(Info, 0, sizeof(ProcInfo));
						Info->ProcessId = ProcessId;
						strncpy(Info->lpszProcessImageName, (char*)szImageName, strlen((char*)szImageName));
						InsertTailList(&g_XProcessList, &Info->ActiveListEntry);
					}
					ExReleaseResource(&g_XProcessResource);
				}
				KeLeaveCriticalRegion();
			}
			else
			{
				// XP下调用进程回调时机在PspCreateThread，这个时候Dll加载的UserApc系统APC还未被插入
				// 这个时候插会导致加载时机非常靠前，很可能crash；
				// 为了防止XP之后的平台也出现这种情况，都不在进程回调插入UserMode的APC

				Status = InjectDllByApc_Step1(ProcessId);
				//Status = InjectDllIndirectByUserApc(ProcessId);
			}
		}

	} while (FALSE);

	ObDereferenceObject(EProcess);
}

PPEB GetProcessPeb(PEPROCESS Process)
{
	PPEB Peb = PsGetProcessPeb(Process);
	if ((ULONG_PTR)Peb > MmUserProbeAddress)
	{
		Peb = NULL;
	}
	return Peb;
}

/*
 * 注: 调用该函数获取别的进程模块导出函数一定要切空间！！！
 */
PVOID GetExportFuncAddress(PVOID pImageBase, LPSTR lpszFunName)
{
	PIMAGE_NT_HEADERS       pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportTable;
	DWORD*                  pAddressesArray;
	DWORD*                  pNamesArray;
	WORD*                   pOrdinalsArray;
	DWORD                   dwFuncIndex;
	ULONG                   i;
	CHAR*                   szFunName;
	ULONG_PTR               FunAddress = 0;

	__try
	{
		pNtHeaders = RtlImageNtHeader(pImageBase);
		if (pNtHeaders && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) 
		{

			pExportTable =(IMAGE_EXPORT_DIRECTORY *)((ULONG_PTR)pImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			pAddressesArray = (DWORD* )((ULONG_PTR)pImageBase + pExportTable->AddressOfFunctions);
			pNamesArray     = (DWORD* )((ULONG_PTR)pImageBase + pExportTable->AddressOfNames);
			pOrdinalsArray  = (WORD* )((ULONG_PTR)pImageBase + pExportTable->AddressOfNameOrdinals);

			for(i = 0; i < pExportTable->NumberOfNames; i++){
				szFunName = (LPSTR)((ULONG_PTR)pImageBase + pNamesArray[i]);
				dwFuncIndex = pOrdinalsArray[i]; 
				if (_stricmp(szFunName, lpszFunName) == 0) {
					FunAddress = (ULONG_PTR)((ULONG_PTR)pImageBase + pAddressesArray[dwFuncIndex]);	
					break;
				}
			}
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		FunAddress = 0;
	}

	return (PVOID)FunAddress;
}

/*
 * 注: ImageName传入NULL获取当前nt模块信息
 */
NTSTATUS GetKernelModuleBase(LPCSTR ImageName, PVOID* pImageBaseAddr, PULONG pImageSize)
{
	NTSTATUS         					ntStatus = STATUS_UNSUCCESSFUL;
	PVOID            					pBuffer	= NULL;
	ULONG            					ulNeed = sizeof(SYSTEM_MODULE_INFORMATION) + 30 * sizeof(SYSTEM_MODULE_INFORMATION_ENTRY);
	ULONG			 					ulIndex = 0;
	PSYSTEM_MODULE_INFORMATION   		pSysModInfo = NULL;
	PSYSTEM_MODULE_INFORMATION_ENTRY	pModEntry = NULL;

	pBuffer = ExAllocatePoolWithTag(PagedPool, ulNeed, 'gkmb');	
	if (pBuffer == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeed, &ulNeed);
	if( ntStatus == STATUS_INFO_LENGTH_MISMATCH )
	{
		ExFreePool(pBuffer);

		pBuffer = ExAllocatePoolWithTag(PagedPool, ulNeed, 'kgmb');	
		if( pBuffer == NULL ) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ntStatus = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeed, &ulNeed);
		if (ntStatus != STATUS_SUCCESS ) {
			ExFreePool(pBuffer);
			return ntStatus;
		}
	}
	else if( ntStatus != STATUS_SUCCESS )
	{
		ExFreePool(pBuffer);	
		return ntStatus;
	}

	pSysModInfo 	= (PSYSTEM_MODULE_INFORMATION)pBuffer;
	pModEntry 	    = pSysModInfo->Module;

	if (ImageName == NULL) {
		if (pImageBaseAddr) {
			*pImageBaseAddr = pModEntry[0].Base;
		}	
		if (pImageSize) {
			*pImageSize = pModEntry[0].Size;
		}

		ntStatus = STATUS_SUCCESS;
		DbgPrint("[GetKernelModuleBase] nt name:%s", pModEntry[0].ImageName + pModEntry[0].ModuleNameOffset);
	}
	else
	{
		for( ulIndex = 0; ulIndex < pSysModInfo->Count; ulIndex ++ ) 
		{
			if( _stricmp(pModEntry[ulIndex].ImageName + pModEntry[ulIndex].ModuleNameOffset, ImageName) == 0 )
			{
				if (pImageBaseAddr)
					*pImageBaseAddr = pModEntry[ulIndex].Base;	

				if (pImageSize)
					*pImageSize = pModEntry[ulIndex].Size;

				ntStatus = STATUS_SUCCESS;
				break;
			}
		}
	}

	ExFreePool(pBuffer);
	return ntStatus;
}

BOOLEAN GetProcessModuleInfo(PPEB Peb, LPWSTR lpszModuleName, PVOID *pImageBase, PSIZE_T pSize)
{
	BOOLEAN bRet=FALSE;
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY ListHead,ListPtr;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	ULONG Length;

	Length = wcslen(lpszModuleName) * sizeof(WCHAR);

	do 
	{
		if (NULL == Peb)
			break;

		__try
		{

			Ldr = Peb->Ldr;
			if (!Ldr || !Ldr->Initialized)
				break;

			if (IsListEmpty(&Ldr->InLoadOrderModuleList))
				break;

			ListPtr = ListHead = Ldr->InLoadOrderModuleList.Flink;

			do 
			{
				pLdrDataEntry = CONTAINING_RECORD(ListPtr,LDR_DATA_TABLE_ENTRY,InLoadOrderLinks);
				if (Length == pLdrDataEntry->BaseDllName.Length &&
					pLdrDataEntry->BaseDllName.Buffer) 
				{
					if (!_wcsnicmp(pLdrDataEntry->BaseDllName.Buffer, lpszModuleName, Length / sizeof(WCHAR)))
					{															
						*pImageBase = pLdrDataEntry->DllBase;
						if (pSize)
							*pSize = pLdrDataEntry->SizeOfImage;
						
						bRet = TRUE;
						break;													
					}
				}
				ListPtr = ListPtr->Flink;

			} while (ListPtr->Flink != ListHead);

		}
		__except(EXCEPTION_EXECUTE_HANDLER) 
		{
		}

	} while (FALSE);

	return bRet;
}

NTSTATUS ConvertWCharToChar(WCHAR* lpwzBuffer, CHAR* lpszBuffer, DWORD dwOutCchLength)
{
	
	ANSI_STRING    ansiOutString;
	UNICODE_STRING uniInString;
	NTSTATUS       Status       = STATUS_SUCCESS;
	WCHAR*         wzPtr        = lpwzBuffer;

	while(*wzPtr) wzPtr++;
	uniInString.Length = (USHORT)((wzPtr - lpwzBuffer) * sizeof(WCHAR));
	uniInString.MaximumLength = uniInString.Length + 2;
	uniInString.Buffer = lpwzBuffer;

	Status = RtlUnicodeStringToAnsiString(&ansiOutString, &uniInString, TRUE);
	if (NT_SUCCESS(Status)) {
		
		
		// 传入这么多字节的Buffer，不够没办法只能拷这么多
		memcpy(lpszBuffer, ansiOutString.Buffer, dwOutCchLength);
		RtlFreeAnsiString(&ansiOutString);
	}

	return Status;
}

WCHAR* GetFileNameByFullPath(WCHAR* lpszFullImagePath)
{
	LPWSTR lpPos     = lpszFullImagePath;
	if (wcsstr(lpPos, L"\\"))
	{
		lpPos += wcslen(lpszFullImagePath) - 1;
		while(*lpPos != L'\\' && lpPos > lpszFullImagePath){
			lpPos--;
		}
		lpPos += 1;
	}
	return lpPos;
}