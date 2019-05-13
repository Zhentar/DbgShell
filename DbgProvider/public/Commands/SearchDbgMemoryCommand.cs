using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CSharp.RuntimeBinder;
using Microsoft.Diagnostics.Runtime.Interop;

namespace MS.Dbg.Commands
{
    [Cmdlet(VerbsCommon.Search, "DbgMemory")]
    [OutputType(typeof(DbgMemory))]
    public class SearchDbgMemoryCommand : DbgBaseCommand
    {
        //Problem: want to pipeline things like Get-DbgSymbol in. But Powershell can't figure out which ulong to match to which parameter.
        //so just grab the address directly.
        //Still need to consider how to handle DbgMemory (where the address is unlikely to be what you are searching for), and searching
        //for the values in static symbols
        public class AggressiveAddressTransformationAttribute : AddressTransformationAttribute
        {
            public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
            {
                try
                {
                    dynamic input = inputData;
                    if (input.Address is ulong address)
                    {
                        return address;
                    }
                }
                catch (RuntimeBinderException) { } //There's probably a better way to do this
                catch( PropertyNotFoundException ) { }

                return base.Transform(engineIntrinsics, inputData);
            }
        }

        public enum SearchSize
        {
            Default,
            DWord,
            QWord
        }

        [Flags]
        public enum MemType
        {
            Default = 0,
            Private = 1,
            Image = 2,
            Mapped = 4,
            All = Private | Image | Mapped
        }

        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        [AggressiveAddressTransformation] //Not necessarily an address, but it is often enough that the semantics are useful
        public ulong SearchValue { get; set; }

        [Parameter(Mandatory = false)]
        [AddressTransformation]
        public ulong SearchMask { get; set; }

        [Parameter(Mandatory = false, Position = 1)]
        public SearchSize SearchType { get; set; }

        [Parameter(Mandatory = false)]
        [AddressTransformation]
        public ulong StartAddress { get; set; }

        [Parameter(Mandatory = false)]
        [RangeTransformation]
        public ulong EndAddress { get; set; }

        [Parameter( Mandatory = false )]
        public SwitchParameter IncludeReadOnly { get; set; }

        [Parameter( Mandatory = false )]
        public SwitchParameter ExcludeExectuable { get; set; }

        [ Parameter( Mandatory = false ) ]
        public MemType MemoryType { get; set; } = MemType.All;

        protected override void ProcessRecord()
        {
            base.ProcessRecord();


            foreach (var result in Debugger.StreamFromDbgEngThread<DbgMemory>(CancelTS.Token, DoSearch))
            {
                WriteObject(result);
            }
            
        }

        private const PAGE WRITABLE = PAGE.READWRITE | PAGE.WRITECOPY | PAGE.EXECUTE_READWRITE | PAGE.EXECUTE_WRITECOPY;

        private void DoSearch(CancellationToken ct, Action<DbgMemory> yield)
        {
            var targetPointerType = Debugger.TargetIs32Bit ? SearchSize.DWord : SearchSize.QWord;
            var searchType = SearchType == SearchSize.Default ? targetPointerType : SearchType;

            var searchMask = SearchMask;
            if(searchMask == 0) { searchMask = ulong.MaxValue; }
            var searchValue = SearchValue & searchMask;

            var startAddress = StartAddress & 0xFFFF_FFFF_FFFF_FFFC;
            if (searchType == SearchSize.QWord)
            {
                startAddress = startAddress & 0xFFFF_FFFF_FFFF_FFF8;
            }
            var endAddress = EndAddress > StartAddress ? EndAddress : ulong.MaxValue;

            var startPage = startAddress & 0xFFFF_FFFF_FFFF_F000;
            var curPage = startPage;

            Span<byte> bytes = stackalloc byte[4096];
            while (curPage < endAddress && Debugger.TryQueryVirtual(curPage, out var info) == 0 && !ct.IsCancellationRequested)
            {
                var regionEnd = Math.Min( endAddress,  info.BaseAddress + info.RegionSize);
                curPage = regionEnd;
                if( !IncludeReadOnly && (info.Protect & WRITABLE) == 0 )
                {
                    continue;
                }

                if ((info.State & MEM.COMMIT) != 0 && CheckMemType(info.Type, MemoryType))
                {
                    for (var page = info.BaseAddress; page < regionEnd; page += 4096)
                    {
                        if (Debugger.TryReadVirtualDirect(page, bytes))
                        {
                            //TODO: skip leading portion of first page and trailing portion of last page as needed
                            if (searchType == SearchSize.DWord)
                            {
                                SearchPage<uint, UintIntegralTypeHelper>(yield, bytes, searchMask, searchValue, page);
                            }
                            else
                            {
                                SearchPage<ulong, UlongIntegralTypeHelper>(yield, bytes, searchMask, searchValue, page);
                            }
                        }
                    }
                }
            }
        }

        private static bool CheckMemType( MEM actualType, MemType flags )
        {
            switch( actualType )
            {
                case MEM.PRIVATE:
                    return (flags & MemType.Private) != 0;
                case MEM.IMAGE:
                    return (flags & MemType.Image) != 0;
                case MEM.MAPPED:
                    return (flags & MemType.Mapped) != 0;
                default:
                    if( flags == MemType.All ) { return true; }
                    throw new InvalidOperationException( "Unknown/Bogus Memory Type!" );
            }
        }

        private unsafe void SearchPage<T, THelper>(Action<DbgMemory> yield, Span<byte> bytes, ulong searchMask, ulong searchValue, ulong page) where T : unmanaged where THelper : struct, IIntegralTypeHelper<T>
        {
            THelper helper = default;
            T value = helper.ConvertUlong(searchValue);
            T mask = helper.ConvertUlong(searchMask);
            var dwords = MemoryMarshal.Cast<byte, T>(bytes);
            for (int i = 0; i < dwords.Length; i++)
            {
                if (helper.AreEqual(helper.BitwiseAnd(dwords[i], mask), value))
                {
                    int byteIdx = i * sizeof(T);
                    ulong address = page + (ulong) byteIdx;
                    var valueBytes = bytes.Slice(byteIdx, sizeof(T)).ToArray();
                    var result = new DbgMemory( address, valueBytes, Debugger ) { DefaultDisplayFormat = helper.DisplayFormat };
                    yield(result);
                }
            }
        }
    }

    internal struct UlongIntegralTypeHelper : IIntegralTypeHelper<ulong>
    {
        public ulong BitwiseAnd(ulong lhs, ulong rhs) => lhs & rhs;
        public ulong ConvertUlong(ulong value) => value;
        public bool AreEqual(ulong lhs, ulong rhs) => lhs == rhs;
        public DbgMemoryDisplayFormat DisplayFormat => DbgMemoryDisplayFormat.QWords;
    }

    internal struct UintIntegralTypeHelper : IIntegralTypeHelper<uint>
    {
        public uint BitwiseAnd(uint lhs, uint rhs) => lhs & rhs;
        public uint ConvertUlong(ulong value) => (uint) value;
        public bool AreEqual(uint lhs, uint rhs) => lhs == rhs;
        public DbgMemoryDisplayFormat DisplayFormat => DbgMemoryDisplayFormat.DWords;
    }

    internal interface IIntegralTypeHelper<T> where T: unmanaged
    {
        T BitwiseAnd(T lhs, T rhs);
        T ConvertUlong(ulong value);
        bool AreEqual(T lhs, T rhs);
        DbgMemoryDisplayFormat DisplayFormat { get; }
    }
}
