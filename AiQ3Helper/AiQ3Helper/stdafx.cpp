// stdafx.cpp : 只包括标准包含文件的源文件
// AiQ3Helper.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"

// TODO: 在 STDAFX.H 中
// 引用任何所需的附加头文件，而不是在此文件中引用

void _DbgPrintW(const WCHAR* pszFormat, ...) 
{ 
	va_list args;
	ULONG ulIndex = 0;
	WCHAR szDebugInfo[MAX_PATH] = {0};
	va_start(args, pszFormat);

	HRESULT hr = StringCchCopyW(szDebugInfo, MAX_PATH, L"[AiQ3Helper]");
	if (FAILED(hr)){
		return;
	}
	ulIndex = wcslen(L"[AiQ3Helper]");
	hr = StringCchVPrintfW(szDebugInfo + ulIndex, MAX_PATH - ulIndex, pszFormat, args);
	if (FAILED(hr)){
		return;
	}

	OutputDebugStringW(szDebugInfo);
	va_end(args);
}

void _DbgPrintA(const char* pszFormat, ...) 
{ 
	va_list args;
	ULONG ulIndex = 0;
	char szDebugInfo[MAX_PATH] = {0};
	va_start(args, pszFormat);

	HRESULT hr = StringCchCopyA(szDebugInfo, MAX_PATH, "[AiQ3Helper]");
	if (FAILED(hr)){
		return;
	}

	ulIndex = wcslen(L"[AiQ3Helper]");
	hr = StringCchVPrintfA(szDebugInfo + ulIndex, MAX_PATH - ulIndex, pszFormat, args);
	if (FAILED(hr)){
		return;
	}

	OutputDebugStringA(szDebugInfo);
	va_end(args);
}