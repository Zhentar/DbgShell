using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Diagnostics.Runtime.Interop;
using MS.Dbg.AddressRegionProviders;

namespace MS.Dbg
{
    [ DebuggerDisplay( "{BaseAddress} + {Size}" ) ]
    public abstract class MemoryRegionBase : IEquatable< MemoryRegionBase >, ISupportColor
    {
        protected MemoryRegionBase( ulong baseAddress, ulong size, DbgEngDebugger debugger )
            : this( baseAddress, size, debugger.TargetIs32Bit )
        {
        }

        protected MemoryRegionBase( ulong baseAddress, ulong size, bool is32bit )
            : this( new Address( baseAddress, is32bit ), size )
        {
        }

        protected MemoryRegionBase( Address baseAddress, ulong size )
        {
            BaseAddress = baseAddress;
            Size = size;
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

        public abstract ColorString Description { get; }

        public Address BaseAddress { get; }

        public ulong Size { get; }

        public abstract IEnumerable< MemoryRegionBase > SubRegions { get; }

        public bool Equals( MemoryRegionBase other )
        {
            if( ReferenceEquals( null, other ) )
            {
                return false;
            }
            if( ReferenceEquals( this, other ) )
            {
                return true;
            }
            return BaseAddress.Equals( other.BaseAddress ) && Size == other.Size;
        }

        public override bool Equals( object obj ) => ReferenceEquals( this, obj ) || obj is MemoryRegionBase other && Equals( other );

        public override int GetHashCode() => (BaseAddress.GetHashCode() * 397) ^ Size.GetHashCode();
    }

    public interface IRegionProvider
    {
        IEnumerable< MemoryRegionBase > IdentifyRegions( DbgEngDebugger debugger );
    }

    public class AddressMap
    {
        private static readonly List< IRegionProvider > sm_regionProviders = new List< IRegionProvider >();

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

            return sm_cachedAddressMap ?? (sm_cachedAddressMap = debugger.ExecuteOnDbgEngThread( () => BuildAddressMap( debugger ) ));
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
                    while( addressesIdx < addrList.Count && (addrList[ addressesIdx ].BaseAddress + addrList[ addressesIdx ].Size) <= info.BaseAddress )
                    {
                        addressesIdx++;
                    }
                    var region = new VirtualAllocRegion( info, debugger );
                    address += region.Size;

                    if( !(addressesIdx < addrList.Count
                          && addrList[ addressesIdx ].BaseAddress <= region.BaseAddress
                          && addrList[ addressesIdx ].BaseAddress + addrList[ addressesIdx ].Size >= region.BaseAddress + region.Size) )
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
            var results = new List< MemoryRegionBase >();
            var map = GetAddressMap( debugger );

            foreach( var region in map.Regions )
            {
                if( region.BaseAddress <= address && region.BaseAddress + region.Size > address )
                {
                    var currRegion = region;
                    do
                    {
                        MemoryRegionBase nextRegion = null;
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

        public IEnumerable< MemoryRegionBase > Regions => m_addresses;

        private readonly MemoryRegionList m_addresses = new MemoryRegionList();
    }

    internal class MemoryRegionList : SortedList< MemoryRegionBase >
    {
        private static readonly MemoryRegionComparer sm_comparer = new MemoryRegionComparer();

        public MemoryRegionList() : base( sm_comparer )
        {
        }

        public MemoryRegionList( IEnumerable< MemoryRegionBase > values ) : this()
        {
            foreach( var val in values )
            {
                Add( val );
            }
        }


        private class MemoryRegionComparer : IComparer< MemoryRegionBase >
        {
            public int Compare( MemoryRegionBase x, MemoryRegionBase y )
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

    [ DebuggerDisplay( "{BaseAddress} + {Size} (Leaf)" ) ]
    public class LeafRegion : MemoryRegionBase
    {
        public LeafRegion( Address baseAddress, ulong size, ColorString description )
            : base( baseAddress, size )
        {
            Description = description;
        }

        public override ColorString Description { get; }
        public override IEnumerable< MemoryRegionBase > SubRegions { get { yield break; } }
    }

    public class MemoryRegionStack : ISupportColor, IEquatable< MemoryRegionStack >, IReadOnlyList< MemoryRegionBase >
    {
        private readonly IReadOnlyList< MemoryRegionBase > m_regions;

        public MemoryRegionStack( IReadOnlyList< MemoryRegionBase > regions ) => m_regions = regions;

        public ColorString ToColorString() => ToColorString( false );

        public ColorString ToColorString( bool allLevels )
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
            if( other?.m_regions.Count != m_regions.Count ) { return false; }
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

        public IEnumerator< MemoryRegionBase > GetEnumerator() => m_regions.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => ((IEnumerable) m_regions).GetEnumerator();

        public int Count => m_regions.Count;

        public MemoryRegionBase this[ int index ] => m_regions[ index ];
    }

    [ DebuggerDisplay( "{BaseAddress} + {Size} ({m_subRegions.Count})" ) ]
    public abstract class ChildCachingMemoryRegion : MemoryRegionBase
    {
        protected ChildCachingMemoryRegion( ulong baseAddress, ulong size, DbgEngDebugger debugger )
            : base( baseAddress, size, debugger )
        {
            m_debugger = debugger;
        }

        protected readonly DbgEngDebugger m_debugger;
        private SortedList< MemoryRegionBase > m_subRegions;

        public override IEnumerable< MemoryRegionBase > SubRegions => m_subRegions ?? (m_subRegions = new MemoryRegionList( GetSubRegions( m_debugger ) ));
        protected abstract IEnumerable< MemoryRegionBase > GetSubRegions( DbgEngDebugger debugger );
    }


    public class VirtualAllocRegion : MemoryRegionBase
    {
        private static readonly ColorString Unknown = new ColorString( ConsoleColor.DarkGray, "<unknown>" );
        private static readonly ColorString Mapped = new ColorString( ConsoleColor.DarkMagenta, "<MAPPED>" );

        internal VirtualAllocRegion( MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger )
            : this( info, debugger, GetInfoDetails( info, debugger ) )
        {
        }

        private VirtualAllocRegion( MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger, (ulong size, List< VirtualAllocSubRegion > subRegions) details )
            : base( info.BaseAddress, details.size, debugger )
        {
            Type = info.Type;
            SubRegions = details.subRegions;
        }


        private static (ulong size, List< VirtualAllocSubRegion > subRegions) GetInfoDetails( MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger )
        {
            var is32bit = debugger.TargetIs32Bit;
            var baseAddress = info.AllocationBase;

            var subRegions = new List< VirtualAllocSubRegion >();

            ulong currAddress = info.AllocationBase;
            do
            {
                currAddress += info.RegionSize;
                subRegions.Add( new VirtualAllocSubRegion( info, is32bit ) );
            } while( debugger.TryQueryVirtual( currAddress, out info ) == 0 && info.AllocationBase == baseAddress );

            return (currAddress - baseAddress, subRegions);
        }

        public override IEnumerable< MemoryRegionBase > SubRegions { get; }

        public MEM Type { get; }
        public override ColorString Description => new ColorString( $"MEM_{Type} " ).Append( Type == MEM.MAPPED ? Mapped : Unknown );
    }

    public class VirtualAllocSubRegion : LeafRegion
    {
        internal VirtualAllocSubRegion( MEMORY_BASIC_INFORMATION64 info, bool is32bit )
            : base( new Address( info.BaseAddress, is32bit ), info.RegionSize,
                    new ColorString( $" PAGE_{info.Protect} " ).AppendPushPopFg( ConsoleColor.DarkGray, "<unknown>" ) )
        {
            State = info.State;
            Protect = info.Protect;
        }

        public MEM State { get; }
        public PAGE Protect { get; }
    }
}