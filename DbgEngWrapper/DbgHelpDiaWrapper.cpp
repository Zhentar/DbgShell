#include "stdafx.h"

#include "DbgHelpUndocumented.h"
#include "DbgHelpDiaWrapper.h"
#pragma comment(lib, "dbghelp")

namespace DbgEngWrapper
{

bool WDbgHelpDia::GetDiaSession([In]IntPtr hProcess, [In]ULONG64 BaseAddress, [Out] WDbgHelpDia^% dia)
{
    ::IDiaSession* session = nullptr;
    BOOL result = SymGetDiaSession((HANDLE)hProcess, BaseAddress, &session);
    if (session)
    {
        dia = gcnew WDbgHelpDia(session);
    }
    return result != 0;
};

int WDbgHelpDia::SearchSymbols(String^ searchMask, SymTag tag, DiaSearchOptions diaSearchOptions, SymbolCallback^ resultCallback)
{
    IDiaSymbol* globalScope = nullptr;

    HRESULT hr = m_diaSession->get_globalScope(&globalScope);

    if (!hr && globalScope)
    {
        marshal_context mc;
        IDiaEnumSymbols* enumSymbols = nullptr;
        hr = m_diaSession->findChildrenEx(globalScope, 
                                          static_cast<enum SymTagEnum>(tag), 
                                          mc.marshal_as<const wchar_t*>(searchMask), 
                                          static_cast<enum NameSearchOptions>(diaSearchOptions), 
                                          &enumSymbols);
        if (!hr && enumSymbols)
        {
            ULONG fetchedSymbols = 0;
            IDiaSymbol* childSymbol = nullptr;
            while ((hr = enumSymbols->Next(1, &childSymbol, &fetchedSymbols)) == 0 && fetchedSymbols)
            {
                wchar_t* nameUnmanaged = nullptr;
                DWORD64 address = 0;
                childSymbol->get_undecoratedName(&nameUnmanaged);
                childSymbol->get_virtualAddress(&address);
                String^ name = gcnew String(nameUnmanaged);
                resultCallback(name, address);
                childSymbol->Release();
                SymFreeDiaString((unsigned short*)nameUnmanaged);
            }


            enumSymbols->Release();
        }
        globalScope->Release();
    }
    return hr;
}


int WDbgHelpDia::SearchSymbols(DotNet::Globbing::Glob^ searchMask, SymTag tag, DiaSearchOptions diaSearchOptions, SymbolCallback^ resultCallback)
{
    IDiaSymbol* globalScope = nullptr;

    HRESULT hr = m_diaSession->get_globalScope(&globalScope);

    if (!hr && globalScope)
    {
        marshal_context mc;
        IDiaEnumSymbols* enumSymbols = nullptr;
        hr = m_diaSession->findChildrenEx(globalScope,
            static_cast<enum SymTagEnum>(tag),
            nullptr,
            static_cast<enum NameSearchOptions>(diaSearchOptions),
            &enumSymbols);
        if (!hr && enumSymbols)
        {
            ULONG fetchedSymbols = 0;
            IDiaSymbol* childSymbol = nullptr;
            while ((hr = enumSymbols->Next(1, &childSymbol, &fetchedSymbols)) == 0 && fetchedSymbols)
            {
                DWORD64 address = 0;
                bool isMangledSearch = (diaSearchOptions & DiaSearchOptions::UndecoratedName) != DiaSearchOptions::UndecoratedName;

                String^ name = nullptr; 
                if (isMangledSearch)
                {
                    wchar_t* nameUnmanaged = nullptr;
                    childSymbol->get_name(&nameUnmanaged);
                    name = gcnew String(nameUnmanaged);
                    SymFreeDiaString((unsigned short*)nameUnmanaged);
                }
                else
                {
                    wchar_t* nameUnmanaged = nullptr;
                    childSymbol->get_undecoratedNameEx(0x1000, &nameUnmanaged);
                    name = gcnew String(nameUnmanaged);
                    SymFreeDiaString((unsigned short*)nameUnmanaged);
                }
                
                if (searchMask->IsMatch(name))
                {
                    if (isMangledSearch)
                    {
                        wchar_t* nameUnmanaged = nullptr;
                        childSymbol->get_undecoratedNameEx(0x1000, &nameUnmanaged);
                        name = gcnew String(nameUnmanaged);
                        SymFreeDiaString((unsigned short*)nameUnmanaged);
                    }
                    childSymbol->get_virtualAddress(&address);
                    resultCallback(name, address);
                }
                childSymbol->Release();
            }


            enumSymbols->Release();
        }
        globalScope->Release();
    }
    return hr;
}

}