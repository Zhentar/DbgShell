using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Diagnostics.Runtime.Interop;

namespace MS.Dbg
{
    public class DbgVirtualAllocBlock : ISupportColor, IEquatable<DbgVirtualAllocBlock>
    {
        public static IEnumerable<DbgVirtualAllocBlock> AllBlocks(DbgEngDebugger debugger)
        {
            ulong address = 0;
            while (debugger.TryQueryVirtual(address, out var info) == 0)
            {
                if (info.State.HasFlag(MEM.FREE))
                {
                    address += info.RegionSize;
                }
                else
                {
                    var block = new DbgVirtualAllocBlock(address, debugger);
                    address = block.BaseAddress + block.BlockSize;
                    yield return block;
                }
            }
        }

        public ulong BaseAddress { get; }

        public ulong BlockSize { get; }

        public ulong CommitSize { get; }

        public MEM Type { get; }

        //TODO: dirty. Fix once done prototyping.
        public DbgVirtualAllocBlock(ulong addr) : this(addr, DbgProvider.GetDebugger(""))
        { }

        public DbgVirtualAllocBlock(ulong addr, DbgEngDebugger debugger) : this(debugger.QueryVirtual(addr), debugger)
        { }

        public DbgVirtualAllocBlock(MEMORY_BASIC_INFORMATION64 info, DbgEngDebugger debugger)
        {
            Type = info.Type; //I am under the impression that an alloc block can only be one type
            var commitSize = 0ul;
            ulong currAddress = BaseAddress = info.AllocationBase;
            while (debugger.TryQueryVirtual(currAddress, out info) == 0 && info.AllocationBase == BaseAddress)
            {
                currAddress += info.RegionSize;
                if (info.State.HasFlag(MEM.COMMIT))
                {
                    commitSize += info.RegionSize;
                }
            }

            BlockSize = currAddress - BaseAddress;
            CommitSize = commitSize;
            Debugger = debugger;
        }

        protected readonly DbgEngDebugger Debugger;

        public ColorString Description => MemoryGroup.Name;


        public DbgMemoryGroup MemoryGroup
        {
            get
            {
                switch (Type)
                {
                    case MEM.IMAGE:
                        if (!m_ModuleCache.TryGetValue(this.BaseAddress, out var memoryGroup))
                        {
                            memoryGroup = (m_ModuleCache[BaseAddress] = new DbgMemoryGroup(GetModuleName(BaseAddress), BaseAddress));
                        }
                        return memoryGroup;
                    case MEM.PRIVATE:
                        var lookup = GetHeapMap(Debugger);
                        if (lookup.TryGetValue(this.BaseAddress, out var heapGroup))
                        {
                            return heapGroup;
                        }
                        goto default;
                    case MEM.MAPPED:
                        return mappedGroup;
                    default:
                        return unknownGroup;
                }

                ColorString GetModuleName(ulong address)
                {
                    try
                    {
                        var module = Debugger.GetModuleByAddress(address);
                        return new ColorString(ConsoleColor.Cyan, module.Name);
                    }
                    catch (DbgEngException)
                    {
                        return new ColorString(ConsoleColor.Gray, $"<module {address:X}>");
                    }
                }

            }
        }

        private static readonly DbgMemoryGroup unknownGroup = new DbgMemoryGroup(new ColorString(ConsoleColor.DarkGray, "<unknown>"), 0);
        private static readonly DbgMemoryGroup mappedGroup = new DbgMemoryGroup(new ColorString(ConsoleColor.DarkMagenta, "<MAPPED>"), 0);
        //TODO: some might consider calling this a "cache" somewhat disingenuous, given the complete absence of any invalidation mechanism 
        private static Dictionary<ulong, DbgMemoryGroup> m_HeapCache;
        private static Dictionary<ulong, DbgMemoryGroup> m_ModuleCache = new Dictionary<ulong, DbgMemoryGroup>();

        private static Dictionary<ulong, DbgMemoryGroup> GetHeapMap(DbgEngDebugger debugger)
        {
            if (m_HeapCache != null)
            {
                return m_HeapCache;
            }

            m_HeapCache = new Dictionary<ulong, DbgMemoryGroup>();
            foreach (var heapBase in AllHeaps(debugger))
            {
                var group = DbgMemoryGroup.FromHeapBase(heapBase, debugger);

                foreach (var segment in BlocksForHeap(heapBase, debugger))
                {
                    m_HeapCache[segment.BaseAddress] = group;
                }
            }

            return m_HeapCache;
        }

        public static IEnumerable<ulong> AllHeaps(DbgEngDebugger debugger)
        {
            dynamic teb = debugger.GetCurrentThreadTebNative( CancellationToken.None ).Value;
            dynamic peb = teb.ProcessEnvironmentBlock.DbgGetPointee();
            uint numberOfHeaps = peb.NumberOfHeaps.ToUint32(null);
            return debugger.ReadMemPointers((ulong)peb.ProcessHeaps.DbgGetPointer(), numberOfHeaps);
        }


        public static IEnumerable<DbgVirtualAllocBlock> BlocksForHeap(ulong heapBase, DbgEngDebugger debugger)
        {
            var heap = GetHeap(heapBase, debugger);
            var segmenttype = GetHeapSegmentType(debugger);
            var segmentList = (ulong)heap.SegmentList.DbgGetOperativeSymbol().Address;

            foreach (dynamic segment in debugger.EnumerateLIST_ENTRY( segmentList, segmenttype, "SegmentListEntry" ))
            {
                ulong baseAddress = (ulong)segment.WrappingPSObject.BaseAddress.DbgGetPointer();
                yield return new DbgVirtualAllocBlock(baseAddress, debugger);
            }

            foreach (var heapBlock in debugger.EnumerateLIST_ENTRY_raw(heap.VirtualAllocdBlocks.DbgGetOperativeSymbol().Address, 0))
            {
                yield return new DbgVirtualAllocBlock(heapBlock, debugger);
            }
        }

        internal static DbgUdtTypeInfo GetHeapSegmentType(DbgEngDebugger debugger) => GetTypeNamed(debugger, "_HEAP_SEGMENT");

        internal static DbgUdtTypeInfo GetTypeNamed(DbgEngDebugger debugger, string name)
        {
            return (DbgUdtTypeInfo)debugger.GetModuleTypeByName( debugger.GetNtdllModuleNative(), name );
        }

        internal static dynamic GetHeap(ulong heapBase, DbgEngDebugger debugger)
        {
            return debugger._CreateNtdllSymbolForAddress( false, 
                                                          heapBase, 
                                                          "_HEAP", 
                                                          $"Heap {heapBase:X}", 
                                                          CancellationToken.None ).Value;
        }

        public virtual ColorString ToColorString()
        {
            var cs = new ColorString("VirtualAlloc ");
            cs.Append(DbgProvider.FormatAddress(BaseAddress, Debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            cs.Append(" - ");
            cs.Append(DbgProvider.FormatAddress(BaseAddress + BlockSize, Debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            cs.Append($"  MEM_{Type}  ");
            cs.Append(Description);
            return cs;
        }

        public override bool Equals(object obj)
        {
            return obj is DbgVirtualAllocBlock other && Equals(other);
        }

        public bool Equals(DbgVirtualAllocBlock other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return BaseAddress == other.BaseAddress && BlockSize == other.BlockSize;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode =  BaseAddress.GetHashCode();
                hashCode = (hashCode * 397) ^ BlockSize.GetHashCode();
                return hashCode;
            }
        }

        public static DbgVirtualAllocBlock GetBlockForAddr(ulong address)
        {
            var debugger = DbgProvider.GetDebugger("");
            var info = debugger.QueryVirtual(address);

            if (GetHeapMap(debugger).TryGetValue(info.AllocationBase, out var heapGroup))
            {
                return DbgSpecificSubpieceOfAVirtualAllocBlock.GetSubpieceForHeap(address, info.AllocationBase, heapGroup.BaseAddress, debugger);
            }

            return new DbgVirtualAllocBlock(info, debugger);
        }
    }

    //TODO: get better at naming things
    public class DbgSpecificSubpieceOfAVirtualAllocBlock : DbgVirtualAllocBlock
    {
        [StructLayout(LayoutKind.Explicit)]
        internal struct _HEAP_ENTRY
        {
            [FieldOffset(0)]public ulong AgregateCode;
            [FieldOffset(0)]public ushort Size;
            [FieldOffset(2)]public byte Flags;
            [FieldOffset(3)]public byte SmallTagIndex;
            [FieldOffset(4)]public ushort PreviousSize;
            [FieldOffset(6)]public byte LFHFlags;
            [FieldOffset(7)]public byte UnusedBytes;
        }

        public static DbgSpecificSubpieceOfAVirtualAllocBlock GetSubpieceForHeap(ulong addr, ulong segmentBase, ulong heapBase, DbgEngDebugger debugger)
        {
            return debugger.ExecuteOnDbgEngThread(() =>
            {
                var heap = GetHeap(heapBase, debugger);
                ulong encoding = heap.Encoding.AgregateCode.ToUint64(null); //[sic]
                var segmenttype = GetHeapSegmentType(debugger);
                dynamic segment = debugger.GetValueForAddressAndType(segmentBase, segmenttype);
                DbgSymbol ucrListHeadSymbol = segment.UCRSegmentList.DbgGetOperativeSymbol();
                var ucrListHead = ucrListHeadSymbol.Address;
                var ucrType = GetTypeNamed(debugger, "_HEAP_UCR_DESCRIPTOR");

                ulong heapHeaderOffset = heap.Encoding.DbgGetOperativeSymbol().Type.Members["AgregateCode"].Offset;
                var ucrEntries = new HashSet<ulong>(debugger.EnumerateLIST_ENTRY_raw(ucrListHead, (int)ucrListHeadSymbol.Type.Size));


                ulong entryAddr = segment.FirstEntry.DbgGetPointer() + heapHeaderOffset;
                while (debugger.TryReadMemAs_integer(entryAddr , 8, false, out var entryValue))
                {
                    if (ucrEntries.Contains(entryAddr + 8))
                    {
                        dynamic ucrDescriptor = debugger.GetValueForAddressAndType(entryAddr + 8, ucrType);
                        var ucrSize = ucrDescriptor.Size;
                        if(ucrSize == 0) { break; }
                        entryAddr = ucrDescriptor.Address + ucrSize + heapHeaderOffset;
                        continue;
                    }
                    _HEAP_ENTRY entry = new _HEAP_ENTRY {AgregateCode = entryValue ^ encoding};
                    ulong nextAddr = entryAddr + entry.Size * 8u;
                    if (addr < nextAddr)
                    {
                        bool free = (entry.Flags & 0x1) == 0;
                        var actualSize = entry.Size * 8u - Math.Max(8u, entry.UnusedBytes); //I don't understand why unused is less than 8 sometimes
                        return new DbgSpecificSubpieceOfAVirtualAllocBlock(entryAddr + 8, free, actualSize);
                    }

                    entryAddr = nextAddr + heapHeaderOffset;
                }

                throw new InvalidOperationException("Address not within heap segment or heap segment corrupt");
            });
        }

        public DbgSpecificSubpieceOfAVirtualAllocBlock(ulong addr, bool free, ulong size) : base(addr)
        {
            Address = addr;
            IsFree = free;
            PieceSize = size;
        }
        

        public bool IsFree { get; }
        public ulong Address { get; }
        public ulong PieceSize { get; }

        public override ColorString ToColorString()
        {
            var cs = base.ToColorString();
            cs.AppendLine();
            cs.Append("Heap entry body ");
            cs.Append(DbgProvider.FormatAddress(Address, Debugger.TargetIs32Bit, true, true, ConsoleColor.DarkCyan));
            cs.Append($" size 0x{PieceSize:X,DarkGreen}");
            if (IsFree)
            {
                cs.AppendPushPopFgBg(ConsoleColor.Black, ConsoleColor.Gray, "Free");
            }
            else
            {
                cs.AppendPushPopFg(ConsoleColor.Gray, "Busy");
            }

            return cs;
        }

        public override bool Equals(object obj)
        {
            return obj is DbgSpecificSubpieceOfAVirtualAllocBlock other && Equals(other);
        }

        protected bool Equals(DbgSpecificSubpieceOfAVirtualAllocBlock other)
        {
            return base.Equals(other) && IsFree == other.IsFree && Address == other.Address && PieceSize == other.PieceSize;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = base.GetHashCode();
                hashCode = (hashCode * 397) ^ IsFree.GetHashCode();
                hashCode = (hashCode * 397) ^ Address.GetHashCode();
                hashCode = (hashCode * 397) ^ PieceSize.GetHashCode();
                return hashCode;
            }
        }
    }

    public class DbgMemoryGroup : ISupportColor
    {
        public static DbgMemoryGroup FromHeapBase(ulong heapBase, DbgEngDebugger debugger)
        {
            ColorString name =
                new ColorString("Heap ").Append(DbgProvider.FormatAddress(heapBase, debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            return new DbgMemoryGroup(name, heapBase);
        }

        public DbgMemoryGroup(ColorString name, ulong baseAddress)
        {
            Name = name;
            BaseAddress = baseAddress;
        }

        public ColorString Name { get; }

        public ulong BaseAddress { get; }

        //public IReadOnlyList<DbgVirtualAllocBlock> AllocBlocks { get; }
        public ColorString ToColorString() => Name;
    }
}
