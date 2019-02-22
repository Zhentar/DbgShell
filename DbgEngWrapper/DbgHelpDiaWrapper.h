#pragma once
#include <windows.h>
#include <Dia2.h>
#include <vcclr.h>
#include <msclr\marshal.h>

using namespace System;
using namespace System::Text;
using namespace System::Runtime::InteropServices;
using namespace msclr::interop;
using namespace Microsoft::Diagnostics::Runtime::Interop;
using namespace System::Diagnostics::Tracing;

namespace DbgEngWrapper
{
    [Flags]
    public enum class DiaSearchOptions
    {
        None = 0,
        CaseSensitive = nsfCaseSensitive,
        CaseInsensitive = nsfCaseInsensitive,
        FNameExt = nsfFNameExt,
        RegularExpression = nsfRegularExpression,
        UndecoratedName = nsfUndecoratedName,
    };

    public ref class WDbgHelpDia
    {
    private:
        ::IDiaSession* m_diaSession;
        void (*freeString)(BSTR);

        WDbgHelpDia(::IDiaSession* pSession, void(*freeStringFunction)(BSTR))
        {
            if (!pSession)
                throw gcnew ArgumentNullException("pNative");

            freeString = freeStringFunction;
            m_diaSession = pSession;
        }

    public:

        ~WDbgHelpDia()
        {
            // This calls the finalizer to perform native cleanup tasks, and also causes
            // CLR finalization to be suppressed.
            this->!WDbgHelpDia();
        }

        !WDbgHelpDia()
        {
            if (m_diaSession)
            {
                m_diaSession->Release();
                m_diaSession = nullptr;
            }
        }

        static bool GetDiaSession([In]IntPtr hProcess, [In]ULONG64 BaseAddress, [Out] WDbgHelpDia^% dia);
        static HRESULT CreateDiaSession(String^ pdbFilename, ULONG64 BaseAddress, bool useLocalAlloc, [Out] WDbgHelpDia^% dia);

        delegate void SymbolCallback(String^ name, UInt64 address);

        int SearchSymbols(String^ searchMask, SymTag tag, DiaSearchOptions diaSearchOptions, SymbolCallback^ resultCallback);

        int SearchSymbols(DotNet::Globbing::Glob^ searchMask, SymTag tag, DiaSearchOptions diaSearchOptions, SymbolCallback^ resultCallback);
    };

}