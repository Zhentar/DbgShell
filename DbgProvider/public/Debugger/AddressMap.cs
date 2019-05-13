using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Runtime.Interop;
using MS.Dbg.AddressRegionProviders;

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
            RegisterRegionProvider( new NativeHeapRegionProvider() );
        }

        public static void RegisterRegionProvider( IRegionProvider provider )
        {
            sm_regionProviders.Add( provider );
        }

        private static AddressMap sm_cachedAddressMap;
        private static bool sm_initDone;

        private static void DumpAddressMapAtSlightestProvocation()
        {
            sm_cachedAddressMap = null;
        }

        public static AddressMap GetAddressMap( DbgEngDebugger debugger )
        {
            if( !sm_initDone )
            {
                debugger.SymbolStateChanged += ( _, __ ) => DumpAddressMapAtSlightestProvocation();
                debugger.DebuggeeStateChanged += ( _, __ ) => DumpAddressMapAtSlightestProvocation();
                sm_initDone = true;
            }

            return sm_cachedAddressMap ?? (sm_cachedAddressMap = debugger.ExecuteOnDbgEngThread( () => BuildAddressMap( debugger )));
        }

        private static AddressMap BuildAddressMap( DbgEngDebugger debugger )
        {

            var result = new AddressMap();
            var addrList = result.m_addresses;

            foreach( var provider in sm_regionProviders )
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
                    while( addressesIdx < addrList.Count && (addrList[ addressesIdx ].BaseAddress + addrList[ addressesIdx ].Size) < info.BaseAddress )
                    {
                        addressesIdx++;
                    }
                    var region = new VirtualAllocRegion( info, debugger );
                    address += region.Size;
                    if( !(addressesIdx < addrList.Count 
                          && addrList[ addressesIdx ].BaseAddress <= region.BaseAddress
                          && addrList[ addressesIdx ].BaseAddress + addrList[ addressesIdx ].Size >= region.BaseAddress + region.Size))
                    {
                        addrList.Add( region );
                    }
                }

                //dbgeng seems to be susceptible to wigging out somewhere north of the 4GB line in 32-bit mode with Wow64 processes
                if( debugger.TargetIs32Bit && address > uint.MaxValue )
                {
                    break;
                }
            }

            return result;
        }

        public static MemoryRegionStack GetMemoryRegionsForAddress( DbgEngDebugger debugger, ulong address )
        {
            var results = new List<IMemoryRegion>();
            var map = GetAddressMap( debugger );

            foreach( var region in map.Regions )
            {
                if( region.BaseAddress <= address && region.BaseAddress + region.Size > address )
                {
                    var currRegion = region;
                    do
                    {
                        IMemoryRegion nextRegion = null;
                        results.Add( currRegion );
                        foreach( var subRegion in currRegion.SubRegions )
                        {
                            if( subRegion.BaseAddress <= address && subRegion.BaseAddress + subRegion.Size > address )
                            {
                                nextRegion = subRegion;
                                break;
                            }
                        }
                        currRegion = nextRegion;
                    } while( currRegion != null );
                }
            }


            return new MemoryRegionStack( results );
        }

        public IEnumerable<IMemoryRegion> Regions => m_addresses;

        private readonly MemoryRegionList m_addresses = new MemoryRegionList();
    }

    internal class MemoryRegionList : SortedList<IMemoryRegion>
    {
        private static readonly MemoryRegionComparer sm_comparer = new MemoryRegionComparer();

        public MemoryRegionList() : base( sm_comparer )
        {
        }

        public MemoryRegionList( IEnumerable<IMemoryRegion> values ) : this()
        {
            foreach( var val in values )
            {
                Add( val );
            }
        }


        private class MemoryRegionComparer : IComparer<IMemoryRegion>
        {
            public int Compare( IMemoryRegion x, IMemoryRegion y )
            {
                if( x is null )
                {
                    return y is null ? 0 : 1;
                }
                if( y is null ) { return -1; }
                return x.BaseAddress.CompareTo( y.BaseAddress );
            }
        }
    }

    [DebuggerDisplay( "{BaseAddress} + {Size} (Leaf)" )]
    internal class LeafRegion : IMemoryRegion
    {
        public LeafRegion( Address baseAddress, ulong size, ColorString description )
        {
            m_description = description;
            BaseAddress = baseAddress;
            Size = size;
        }

        public ColorString ToColorString()
        {
            var cs = BaseAddress.ToColorString( ConsoleColor.DarkYellow );
            cs.Append( " - " );
            cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( " " );
            cs.Append( m_description );
            return cs;
        }

        private readonly ColorString m_description;
        public Address BaseAddress { get; }
        public ulong Size { get; }
        public IEnumerable<IMemoryRegion> SubRegions { get { yield break; } }
    }

    public class MemoryRegionStack : ISupportColor, IEquatable<MemoryRegionStack>, IReadOnlyList<IMemoryRegion>
    {
        private readonly IReadOnlyList<IMemoryRegion> m_regions;

        public MemoryRegionStack( IReadOnlyList<IMemoryRegion> regions ) => m_regions = regions;

        public ColorString ToColorString() => ToColorString( false );
 
        public ColorString ToColorString(bool allLevels)
        {
            if( !allLevels )
            {
                return m_regions[ m_regions.Count - 1 ].ToColorString();
            }
            var cs = new ColorString();
            
            foreach( var region in m_regions )
            {
                if( cs.Length > 0 ) { cs.Append( "\n" ); }
                cs.Append( region.ToColorString() );
            }
            return cs;
        }

        public bool Equals( MemoryRegionStack other )
        {
            if( other?.m_regions.Count != this.m_regions.Count ) { return false; }
            for( int i = 0; i < m_regions.Count; i++ )
            {
                if( m_regions[ i ].BaseAddress != other.m_regions[ i ].BaseAddress
                    || m_regions[ i ].Size != other.m_regions[ i ].Size )
                {
                    return false;
                }
            }
            return true;
        }

        public IEnumerator< IMemoryRegion > GetEnumerator() => m_regions.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable) m_regions).GetEnumerator();

        public int Count => m_regions.Count;

        public IMemoryRegion this[ int index ] => m_regions[ index ];
    }

    [DebuggerDisplay( "{BaseAddress} + {Size} ({m_subRegions.Count})" )]
    internal abstract class MemoryRegionBase : IMemoryRegion
    {
        protected MemoryRegionBase( ulong baseAddress, ulong size, DbgEngDebugger debugger )
        {
            BaseAddress = new Address( baseAddress, debugger.TargetIs32Bit );
            Size = size;
            Debugger = debugger;
        }

        public ColorString ToColorString()
        {
            var cs = BaseAddress.ToColorString( ConsoleColor.DarkYellow );
            cs.Append( " - " );
            cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( " " );
            cs.Append( Description );
            return cs;
        }

        protected abstract ColorString Description { get; }

        public Address BaseAddress { get; }

        public ulong Size { get; }

        protected readonly DbgEngDebugger Debugger;

        public IEnumerable<IMemoryRegion> SubRegions => m_subRegions ?? (m_subRegions = new MemoryRegionList( GetSubRegions( Debugger ) ));

        private SortedList<IMemoryRegion> m_subRegions;

        protected abstract IEnumerable<IMemoryRegion> GetSubRegions( DbgEngDebugger debugger );
    }


    public class VirtualAllocRegion : IMemoryRegion
    {
        private static readonly ColorString Unknown = new ColorString( ConsoleColor.DarkGray, "<unknown>" );
        private static readonly ColorString Mapped = new ColorString( ConsoleColor.DarkMagenta, "<MAPPED>" );

        public VirtualAllocRegion( MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger )
        {
            Type = info.Type;
            var is32bit = debugger.TargetIs32Bit;
            BaseAddress = new Address( info.AllocationBase, is32bit );

            var subRegions = new List<VirtualAllocSubRegion>();

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

        public IEnumerable<IMemoryRegion> SubRegions => m_subRegions;

        public ColorString ToColorString()
        {
            var cs = BaseAddress.ToColorString( ConsoleColor.DarkYellow );
            cs.Append( " - " );
            cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( $" MEM_{Type} " );
            cs.Append( Type == MEM.MAPPED ? Mapped : Unknown );
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
                cs.Append( $" PAGE_{State}" );
                cs.Append( new ColorString( ConsoleColor.DarkGray, "<unknown>" ) );
                return cs;
            }
        }
    }
}
