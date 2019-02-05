#include "stdafx.h"

#include "DbgHelpUndocumented.h"
#include <diacreate.h>
#include "DbgHelpDiaWrapper.h"
#pragma comment(lib, "advapi32")
#pragma comment(lib, "diaguids")
#pragma comment(lib, "dbghelp")


namespace DbgEngWrapper
{

bool WDbgHelpDia::GetDiaSession([In]IntPtr hProcess, [In]ULONG64 BaseAddress, [Out] WDbgHelpDia^% dia)
{
    ::IDiaSession* session = nullptr;
    BOOL result = SymGetDiaSession((HANDLE)hProcess, BaseAddress, &session);
    if (session)
    {
        dia = gcnew WDbgHelpDia(session, (void(*)(BSTR))&SymFreeDiaString);
    }
    return result != 0;
};

HRESULT WDbgHelpDia::CreateDiaSession(String^ pdbFilename, ULONG64 BaseAddress, [Out] WDbgHelpDia^% dia)
{
    marshal_context mc;
    IDiaDataSource  *diaDataSource = nullptr;
    IDiaSession  *diaSession = nullptr;
    int hr = ::NoRegCoCreate(L"msdia140.dll", __uuidof(DiaSource), __uuidof(IDiaDataSource),(void **)&diaDataSource);
    if (hr == 0 && diaDataSource != nullptr)
    {
        hr = diaDataSource->loadDataFromPdb(mc.marshal_as<const wchar_t*>(pdbFilename));
        if (hr == 0)
        {
            hr = diaDataSource->openSession(&diaSession);
            if (hr == 0 && diaSession != nullptr)
            {
                diaSession->put_loadAddress(BaseAddress);
                dia = gcnew WDbgHelpDia(diaSession, &SysFreeString);
            }
        }
    }
    return hr;
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
                BSTR nameUnmanaged = nullptr;
                DWORD64 address = 0;
                childSymbol->get_undecoratedNameEx(0x1000, &nameUnmanaged);
                childSymbol->get_virtualAddress(&address);
                String^ name = gcnew String(nameUnmanaged);
                resultCallback(name, address);
                childSymbol->Release();
                freeString(nameUnmanaged);
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
                    BSTR nameUnmanaged = nullptr;
                    childSymbol->get_name(&nameUnmanaged);
                    name = gcnew String(nameUnmanaged);
                    freeString(nameUnmanaged);
                }
                else
                {
                    BSTR nameUnmanaged = nullptr;
                    childSymbol->get_undecoratedNameEx(0x1000, &nameUnmanaged);
                    name = gcnew String(nameUnmanaged);
                    freeString(nameUnmanaged);
                }
                
                if (searchMask->IsMatch(name))
                {
                    if (isMangledSearch)
                    {
                        BSTR nameUnmanaged = nullptr;
                        childSymbol->get_undecoratedNameEx(0x1000, &nameUnmanaged);
                        name = gcnew String(nameUnmanaged);
                        freeString(nameUnmanaged);
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