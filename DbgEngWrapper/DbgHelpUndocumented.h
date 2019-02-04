#pragma once

#include <windows.h>
#include <DbgHelp.h>

struct IDiaSession;

BOOL IMAGEAPI
SymGetDiaSession(
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _Out_ ::IDiaSession** session
);


void IMAGEAPI
SymFreeDiaString(
    _In_ unsigned short* String
);
