using System;
using System.Collections.Generic;
using System.Linq;
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

        public DbgVirtualAllocBlock(ulong addr, DbgEngDebugger debugger)
        {
            var info = debugger.QueryVirtual(addr);
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

        private readonly DbgEngDebugger Debugger;

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
                            memoryGroup = (m_ModuleCache[BaseAddress] = new DbgMemoryGroup(GetModuleName(BaseAddress)));
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
                        return new ColorString(ConsoleColor.Cyan, Debugger.GetModuleByAddress(address).Name);
                    }
                    catch (DbgEngException)
                    {
                        return new ColorString(ConsoleColor.Gray, $"<module {address:X}>");
                    }
                }

            }
        }

        private static readonly DbgMemoryGroup unknownGroup = new DbgMemoryGroup(new ColorString(ConsoleColor.DarkGray, "<unknown>"));
        private static readonly DbgMemoryGroup mappedGroup = new DbgMemoryGroup(new ColorString(ConsoleColor.DarkMagenta, "<MAPPED>"));
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
            dynamic peb = DbgPseudoRegisterInfo.GetDbgPsedoRegisterInfo(debugger, "$peb").Value;
            uint numberOfHeaps = peb.NumberOfHeaps.ToUint32(null);
            return debugger.ReadMemPointers((ulong)peb.ProcessHeaps.DbgGetPointer(), numberOfHeaps);
        }


        public static IEnumerable<DbgVirtualAllocBlock> BlocksForHeap(ulong heapBase, DbgEngDebugger debugger)
        {
            var si = DbgHelp.EnumTypesByName(debugger.DebuggerInterface,
                                                0,
                                                "ntdll!_HEAP",
                                                System.Threading.CancellationToken.None).FirstOrDefault();
            var segmentsi = DbgHelp.EnumTypesByName(debugger.DebuggerInterface,
                0,
                "ntdll!_HEAP_SEGMENT",
                System.Threading.CancellationToken.None).FirstOrDefault();
            if (null == si)
            {
                throw new DbgProviderException("Can't find type ntdll!_HEAP. No symbols?",
                    "NoHeapType",
                    System.Management.Automation.ErrorCategory.ObjectNotFound);
            }
            if (null == segmentsi)
            {
                throw new DbgProviderException("Can't find type ntdll!_HEAP_SEGMENT. No symbols?",
                    "NoHeapType",
                    System.Management.Automation.ErrorCategory.ObjectNotFound);
            }
            var type = DbgTypeInfo.GetNamedTypeInfo(debugger,
                si.ModBase,
                si.TypeIndex,
                si.Tag,
                debugger.GetCurrentTarget());
            var segmenttype = (DbgUdtTypeInfo)DbgTypeInfo.GetNamedTypeInfo(debugger,
                segmentsi.ModBase,
                segmentsi.TypeIndex,
                segmentsi.Tag,
                debugger.GetCurrentTarget());
            dynamic heap = new DbgSimpleSymbol(debugger,
                                                "Heap",
                                                type,
                                                heapBase).Value;
            foreach (dynamic segment in debugger.EnumerateLIST_ENTRY(heap.SegmentList, segmenttype, "SegmentListEntry"))
            {
                uint baseAddress = (uint)segment.BaseAddress.DbgGetPointer();
                yield return new DbgVirtualAllocBlock(baseAddress, debugger);
            }

            foreach (var heapBlock in debugger.EnumerateLIST_ENTRY_raw(heap.VirtualAllocdBlocks.DbgGetOperativeSymbol().Address, 0))
            {
                yield return new DbgVirtualAllocBlock(heapBlock, debugger);
            }
        }

        public ColorString ToColorString()
        {
            var cs = new ColorString("VirtualAlloc ");
            cs.Append(DbgProvider.FormatAddress(BaseAddress, Debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            cs.Append(" - ");
            cs.Append(DbgProvider.FormatAddress(BaseAddress + BlockSize, Debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            cs.Append("  MEM_" + Type + "  ");
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
    }

    public class DbgMemoryGroup : ISupportColor
    {
        public static DbgMemoryGroup FromHeapBase(ulong heapBase, DbgEngDebugger debugger)
        {
            ColorString name =
                new ColorString("Heap ").Append(DbgProvider.FormatAddress(heapBase, debugger.TargetIs32Bit, true, true, ConsoleColor.DarkYellow));
            return new DbgMemoryGroup(name);
        }

        public DbgMemoryGroup(ColorString name)
        {
            Name = name;
        }

        public ColorString Name { get; }

        //public IReadOnlyList<DbgVirtualAllocBlock> AllocBlocks { get; }
        public ColorString ToColorString() => Name;
    }
}
