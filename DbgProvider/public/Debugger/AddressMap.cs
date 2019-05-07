using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Runtime.Interop;

namespace MS.Dbg
{
    public interface IMemoryRegion : ISupportColor
    {
        Address BaseAddress { get; }
        ulong Size { get; }
        IEnumerable<IMemoryRegion> SubRegions { get; }
    }
    
    public interface IRegionProvider
    {
        IEnumerable<IMemoryRegion> IdentifyRegions( DbgEngDebugger debugger );
    }

    public class AddressMap
    {
        private static readonly List<IRegionProvider> sm_regionProviders = new List<IRegionProvider>();

        static AddressMap()
        {
            RegisterRegionProvider( new ModuleRegionProvider() );
        }
        
        public static void RegisterRegionProvider(IRegionProvider provider)
        {
            sm_regionProviders.Add( provider );
        }

        public static AddressMap BuildAddressMap( DbgEngDebugger debugger )
        {
            var result = new AddressMap();
            var addrList = result.m_addresses;

            foreach(var provider in sm_regionProviders)
            {
                foreach( var region in provider.IdentifyRegions( debugger ) )
                {
                    addrList.Add( region );
                }
            }

            int addressesIdx = 0;
            ulong address = 0;
            while( debugger.TryQueryVirtual( address, out var info ) == 0 )
            {
                if( (info.State & MEM.FREE) != 0 )
                {
                    address += info.RegionSize;
                }
                else
                {
                    while( addressesIdx < addrList.Count && addrList[addressesIdx].BaseAddress < info.BaseAddress)
                    {
                        addressesIdx++;
                    }
                    var region = new VirtualAllocRegion( info, debugger );
                    address += region.Size;
                    if( !(addressesIdx < addrList.Count && addrList[ addressesIdx ].BaseAddress == region.BaseAddress &&
                          addrList[ addressesIdx ].Size == region.Size) )
                    {
                        addrList.Add( region );
                    }
                }
            }

            return result;
        }

        private class MemoryRegionComparer : IComparer<IMemoryRegion>
        {
            public int Compare( IMemoryRegion x, IMemoryRegion y )
            {
                if( x is null )
                {
                    return y is null ? 0 : 1;
                }
                if( y is null ) { return -1;}
                return x.BaseAddress.CompareTo( y.BaseAddress );
            }
        }

        private static readonly MemoryRegionComparer sm_comparer = new MemoryRegionComparer();

        private readonly SortedList<IMemoryRegion> m_addresses = new SortedList<IMemoryRegion>( sm_comparer );
    }


    public class VirtualAllocRegion : IMemoryRegion
    {

        public VirtualAllocRegion( MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger )
        {
            Type = info.Type;
            var is32bit = debugger.TargetIs32Bit;
            BaseAddress = new Address( info.AllocationBase, is32bit );

            var subRegions = new List< VirtualAllocSubRegion >();

            ulong currAddress = info.AllocationBase;
            do
            {
                currAddress += info.RegionSize;
                subRegions.Add( new VirtualAllocSubRegion( info, is32bit ) );
            } while( debugger.TryQueryVirtual( currAddress, out info ) == 0 && info.AllocationBase == BaseAddress );

            Size = currAddress - BaseAddress;
            m_subRegions = subRegions;
        }

        private readonly IReadOnlyList<VirtualAllocSubRegion> m_subRegions;

        public Address BaseAddress { get; }

        public ulong Size { get; }

        public MEM Type { get; }

        public IEnumerable< IMemoryRegion > SubRegions => m_subRegions;

        public ColorString ToColorString()
        {
            var cs = new ColorString( "VirtualAlloc " );
            cs.Append( BaseAddress.ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( " - " );
            cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( $"  MEM_{Type}  " );
            cs.Append( new ColorString( ConsoleColor.DarkGray, "<unknown>" ) );
            return cs;
        }

        public class VirtualAllocSubRegion : IMemoryRegion
        {
            public VirtualAllocSubRegion( MEMORY_BASIC_INFORMATION64 info, bool is32bit )
            {
                BaseAddress = new Address( info.BaseAddress, is32bit );
                Size = info.RegionSize;
                State = info.State;
                Protect = info.Protect;
            }

            public Address BaseAddress { get; }

            public ulong Size { get; }

            public MEM State { get; }

            public PAGE Protect { get; }

            public IEnumerable<IMemoryRegion> SubRegions => Enumerable.Empty<IMemoryRegion>();

            public ColorString ToColorString()
            {
                var cs = new ColorString( "VirtualAlloc " );
                cs.Append( BaseAddress.ToColorString( ConsoleColor.DarkYellow ) );
                cs.Append( " - " );
                cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
                cs.Append( $"  MEM_{State} PAGE_{State}  " );
                cs.Append( new ColorString( ConsoleColor.DarkGray, "<unknown>" ) );
                return cs;
            }
        }
    }
}
