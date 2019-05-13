﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Threading;

namespace MS.Dbg.AddressRegionProviders
{
    internal class NativeHeapRegionProvider : IRegionProvider
    {
        public IEnumerable<IMemoryRegion> IdentifyRegions( DbgEngDebugger debugger )
        {
            var dataSections = debugger.Modules.Select( m => (m, m.GetSectionHeaders().FirstOrDefault( h => h.Name == ".data" )) ).ToList();
            var types = new HeapTypeCache( debugger );
            foreach( var heapBase in AllHeaps( debugger ) )
            {
                foreach( var segment in RegionsForHeap( heapBase, debugger, types, dataSections ) )
                {
                    yield return segment;
                }
            }
        }

        private static IEnumerable<ulong> AllHeaps( DbgEngDebugger debugger )
        {
            dynamic teb = debugger.GetCurrentThreadTebEffective( CancellationToken.None ).Value;
            dynamic peb = teb.ProcessEnvironmentBlock.DbgGetPointee();
            uint numberOfHeaps = peb.NumberOfHeaps.ToUint32( null );
            return debugger.ReadMemPointers( (ulong) peb.ProcessHeaps.DbgGetPointer(), numberOfHeaps );
        }

        private static IEnumerable<IMemoryRegion> RegionsForHeap( ulong heapBase, DbgEngDebugger debugger, HeapTypeCache types, List<(DbgModuleInfo mod, IMAGE_SECTION_HEADER dataHdr)> dataSections )
        {
            var heap = GetHeap( heapBase, debugger );
            var segmentList = (ulong) heap.SegmentList.DbgGetOperativeSymbol().Address;
            ulong encoding = heap.Encoding.AgregateCode.ToUint64( null );

            var possibleSymbols = new List< string >();
            bool is32bit = debugger.TargetIs32Bit;

            //TODO: single search pass for all heaps, more DRY code, generally engoodify
            Span<byte> buffer = stackalloc byte[ 4096 ];
            foreach( (DbgModuleInfo module, IMAGE_SECTION_HEADER dataHdr) in dataSections )
            {

                for( uint offset = 0; offset < dataHdr.VirtualSize; offset+= 4096 )
                {
                    var currentPage = module.BaseAddress + dataHdr.VirtualAddress + offset;
                    if( debugger.TryReadVirtualDirect( currentPage, buffer ) )
                    {
                        if( is32bit )
                        {
                            var searchSpan = MemoryMarshal.Cast< byte, uint >( buffer );
                            for( int i = 0; i < searchSpan.Length; i++ )
                            {
                                if( searchSpan[ i ] == heapBase )
                                {
                                    if(debugger.TryGetNameByOffset( currentPage + (uint) (i * sizeof( uint )),out var name, out var displacement ) )
                                    {
                                        if( displacement == 0 )
                                        {
                                            possibleSymbols.Add( name );
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            var searchSpan = MemoryMarshal.Cast<byte, ulong>( buffer );
                            for( int i = 0; i < searchSpan.Length; i++ )
                            {
                                if( searchSpan[ i ] == heapBase )
                                {
                                    if( debugger.TryGetNameByOffset( currentPage + (uint) (i * sizeof( ulong )), out var name, out var displacement ) )
                                    {
                                        if( displacement == 0 )
                                        {
                                            possibleSymbols.Add( name );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            var heapName = possibleSymbols.Count == 1 ? new ColorString( ConsoleColor.Magenta, possibleSymbols[ 0 ] ) : null;


            foreach( var segment in debugger.EnumerateLIST_ENTRY( segmentList, types.HeapSegment, "SegmentListEntry" ) )
            {
                yield return new NativeHeapSegmentRegion( heapBase, heapName, segment.WrappingPSObject, encoding, types, debugger);
            }
            ulong virtAllocHead = heap.VirtualAllocdBlocks.DbgGetOperativeSymbol().Address;
            var commitSizeOffset = is32bit ? 0x10u : 0x20u;
            foreach( var heapBlock in debugger.EnumerateLIST_ENTRY_raw( virtAllocHead, 0 ) )
            {
                var size = debugger.ReadMemAs_UInt32(heapBlock + commitSizeOffset);
                yield return new LeafRegion( new Address( heapBlock, debugger ), size, "Heap VirtualAllocBlock" );
            }
        }

        private static dynamic GetHeap( ulong heapBase, DbgEngDebugger debugger )
        {
            return debugger._CreateNtdllSymbolForAddress( heapBase,
                                                          "_HEAP",
                                                          $"Heap {heapBase:X}",
                                                          CancellationToken.None ).Value;
        }

    }

    internal class HeapTypeCache
    {
        //TODO: symbol cookie invalid errors?
        public HeapTypeCache( DbgEngDebugger debugger )
        {
            var ntdll = debugger.GetNtdllModuleEffective();
            HeapSegment = (DbgUdtTypeInfo) debugger.GetModuleTypeByName( ntdll, "_HEAP_SEGMENT" );
            UcrDescriptor = (DbgUdtTypeInfo) debugger.GetModuleTypeByName( ntdll, "_HEAP_UCR_DESCRIPTOR" );
            UserDataHeader = (DbgUdtTypeInfo) debugger.GetModuleTypeByName( ntdll, "_HEAP_USERDATA_HEADER" );
            foreach( var sym in debugger.FindSymbol_Enum( ntdll.Name + "!RtlpLFHKey" ) )
            {
                LfhKey = debugger.ReadMemAs<uint>( sym.Address );
            }
        }

        public readonly DbgUdtTypeInfo HeapSegment;
        public readonly DbgUdtTypeInfo UcrDescriptor;
        public readonly DbgUdtTypeInfo UserDataHeader;
        public readonly uint LfhKey;
    }



    internal abstract class HeapRegionBase : MemoryRegionBase
    {
        protected readonly ColorString m_heapName;
        protected HeapRegionBase( ulong heapBase, ColorString heapName, ulong baseAddress, ulong size, HeapTypeCache typeCache, DbgEngDebugger debugger )
        : base(baseAddress, size, debugger)
        {
            TypeCache = typeCache;
            HeapBase = new Address( heapBase, debugger.TargetIs32Bit);
            m_heapName = heapName ?? HeapBase.ToColorString();
        }
        
        public Address HeapBase { get; }

        protected HeapTypeCache TypeCache { get; }

        protected override ColorString Description => new ColorString( "Heap " ).Append( m_heapName );

        [ StructLayout( LayoutKind.Explicit )]
        internal struct _HEAP_ENTRY
        {
            [FieldOffset( 0 )] public ulong  AgregateCode; //[sic]
            [FieldOffset( 0 )] public ushort Size;
            [FieldOffset( 2 )] public byte   Flags;
            [FieldOffset( 3 )] public byte   SmallTagIndex;
            [FieldOffset( 4 )] public ushort PreviousSize;
            [FieldOffset( 6 )] public byte   LFHFlags;
            [FieldOffset( 7 )] public byte   UnusedBytes;
        }
    }

    internal class NativeHeapSegmentRegion : HeapRegionBase
    {

        private readonly dynamic m_heapSegment;
        private readonly ulong m_heapEncoding;

        public NativeHeapSegmentRegion( ulong heapBase, 
                                        ColorString heapName, 
                                        PSObject heapSegment, 
                                        ulong heapEncoding, 
                                        HeapTypeCache typeCache,
                                        DbgEngDebugger debugger ) 
            : base( heapBase, heapName, SegmentBase( heapSegment ), SegmentSize( heapSegment ), typeCache, debugger )
        {
            m_heapSegment = heapSegment;
            m_heapEncoding = heapEncoding;
        }

        private static ulong SegmentBase( dynamic segment )
        {
            return (ulong) segment.BaseAddress.DbgGetPointer();
        }

        private static ulong SegmentSize( dynamic segment )
        {
            ulong baseAddress = (ulong) segment.BaseAddress.DbgGetPointer();
            ulong endAddress = (ulong) segment.LastValidEntry.DbgGetPointer();
            return endAddress - baseAddress;
        }


        protected override ColorString Description => base.Description.Append( " Segment" );

        protected override IEnumerable<IMemoryRegion> GetSubRegions( DbgEngDebugger debugger )
        {
            return debugger.StreamFromDbgEngThread<IMemoryRegion>( default, ( ct, yield ) =>
                {
                    ulong heapHeaderOffset = m_heapSegment.Entry.DbgGetOperativeSymbol().Type.Members[ "AgregateCode" ].Offset;
                    dynamic segment = debugger.GetValueForAddressAndType( BaseAddress, TypeCache.HeapSegment );
                    DbgSymbol ucrListHeadSymbol = segment.UCRSegmentList.DbgGetOperativeSymbol();
                    var ucrListHead = ucrListHeadSymbol.Address;
                    var ucrEntries = new HashSet<ulong>( debugger.EnumerateLIST_ENTRY_raw( ucrListHead, (int) ucrListHeadSymbol.Type.Size ) );


                    ulong entryAddr = m_heapSegment.FirstEntry.DbgGetPointer() + heapHeaderOffset;
                    while( debugger.TryReadMemAs_integer( entryAddr, 8, false, out var entryValue ) )
                    {
                        if( ucrEntries.Contains( entryAddr + 8 ) )
                        {
                            dynamic ucrDescriptor = debugger.GetValueForAddressAndType( entryAddr + 8, TypeCache.UcrDescriptor );
                            var ucrSize = ucrDescriptor.Size.ToUint64( null );
                            if( ucrSize == 0 ) { break; }
                            entryAddr = ucrDescriptor.Address + ucrSize + heapHeaderOffset;
                            continue; //TODO: yield UCR region
                        }
                        _HEAP_ENTRY entry = new _HEAP_ENTRY { AgregateCode = entryValue ^ m_heapEncoding };
                        ulong nextAddr = entryAddr + entry.Size * 8u;
                        yield(new HeapEntryRegion( HeapBase, m_heapName, entry, entryAddr, TypeCache, Debugger ));
                        entryAddr = nextAddr + heapHeaderOffset;
                    }
                } );
        }
    }

    internal class HeapEntryRegion : HeapRegionBase
    {
        private static readonly ColorString Header         = new ColorString( ConsoleColor.Gray, " Entry Header " );
        private static readonly ColorString HeaderFree     = Header.AppendPushPopFgBg( ConsoleColor.Black, ConsoleColor.Gray, "(free)" );
        private static readonly ColorString HeaderInternal = Header.AppendPushPopFgBg( ConsoleColor.Black, ConsoleColor.Gray, "(internal)" );

        private static readonly ColorString LfhHeader      = new ColorString( ConsoleColor.Gray, " LFH Entry Header " );
        private static readonly ColorString LfhHeaderFree  = LfhHeader.AppendPushPopFgBg( ConsoleColor.Black, ConsoleColor.Gray, "(free)" );

        public HeapEntryRegion( ulong heapBase, ColorString heapName, _HEAP_ENTRY entry, ulong baseAddress, HeapTypeCache typeCache, DbgEngDebugger debugger ) 
            : base(heapBase, heapName, baseAddress, entry.Size * 8u, typeCache, debugger)
        {
            m_entry = entry;
        }

        private readonly _HEAP_ENTRY m_entry;
        protected override ColorString Description => base.Description.Append( $" Entry ({m_entry.Size * 8u - Math.Max( 8u, m_entry.UnusedBytes ):X,White})" );
        protected override IEnumerable< IMemoryRegion > GetSubRegions( DbgEngDebugger debugger )
        {
            bool free = (m_entry.Flags & 0x1) == 0;
            bool @internal = (m_entry.Flags & 0x8) != 0;
            var actualSize = m_entry.Size * 8u - Math.Max( 8u, m_entry.UnusedBytes ); //I don't understand why unused is less than 8 sometimes
            var entryBodyAddr = BaseAddress + 8;
            var desc = free ? HeaderFree : @internal ? HeaderInternal : Header;
            yield return new LeafRegion( BaseAddress, 8, base.Description.Append(desc) );

            if( @internal )
            {
                var userdataHeaderType = TypeCache.UserDataHeader;
                dynamic userDataHeader = debugger.GetValueForAddressAndType( entryBodyAddr, userdataHeaderType );
                if( userDataHeader.Signature == 0xF0E0D0C0 )
                {
                    dynamic subSegment = userDataHeader.SubSegment;
                    uint blockSize = subSegment.BlockSize * 8u;
                    uint blockCount = subSegment.BlockCount + 0u;

                    ulong entriesStart = entryBodyAddr;
                    if( userdataHeaderType.Members.HasItemNamed( "EncodedOffsets" ) )
                    {
                        uint encodedOffsets = userDataHeader.EncodedOffsets.StrideAndOffset + 0u;
                        encodedOffsets ^= (uint) subSegment.UserBlocks.DbgGetPointer();
                        encodedOffsets ^= TypeCache.LfhKey;
                        entriesStart += (ushort) encodedOffsets;
                    }
                    else
                    {
                        entriesStart += userdataHeaderType.Size;
                    }

                    yield return new LeafRegion( new Address( entryBodyAddr, BaseAddress.Is32Bit ), entriesStart - entryBodyAddr, base.Description.Append( " LFH Block Header" ));

                    var endAddr = entriesStart + blockCount * blockSize;
                    for( var entryAddr = entriesStart; entryAddr < endAddr; entryAddr += blockSize )
                    {
                        var unused = debugger.ReadMemAs<byte>( entryAddr + 7 ) & 0x3Fu;
                        if( unused == 0 )
                        {
                            free = true;
                        }

                        if( unused < 8 )
                        {
                            unused = 8;
                        }
                        yield return new LeafRegion( new Address( entryAddr , BaseAddress.Is32Bit ), 8, base.Description.Append( free ? LfhHeaderFree : LfhHeader ));
                        actualSize = blockSize - unused;
                        yield return new LeafRegion( new Address( entryAddr + 8, BaseAddress.Is32Bit ), actualSize, base.Description.Append( $" LFH Entry Body ({actualSize:X,White})" ) );
                    }
                }
                else
                {
                    yield return new LeafRegion( new Address( entryBodyAddr, BaseAddress.Is32Bit ), actualSize, base.Description.Append( " Internal Data" ) );
                }
            }
            else
            {
                yield return new LeafRegion( new Address(entryBodyAddr, BaseAddress.Is32Bit), actualSize, base.Description.Append( $" Entry Body ({actualSize:X,White})"));
            }
        }
    }
    
}
