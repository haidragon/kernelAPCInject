/***************************************************************************************
* AUTHOR : FaEry
* DATE   : 2017-3-4
* MODULE : AiQHelper.C
*
****************************************************************************************
* Copyright (C) 2010 FaEry.
****************************************************************************************/

#include "AiQHelper.h"
#include "public.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	DbgPrint("[AiQHelper] DriverEntry pDriverObj:%x", pDriverObj);

	pDriverObj->DriverUnload = DriverUnload;
	GlobalInit(pDriverObj, pRegistryString);
	
	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	DbgPrint("[AiQHelper] DriverUnload pDriverObj:%x", pDriverObj);
	GlobalUnInit(pDriverObj);
}