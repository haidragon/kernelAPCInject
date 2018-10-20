#ifndef CXX_AIQHELPER_H
#define CXX_AIQHELPER_H

#include "headers.h"

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);


#endif
