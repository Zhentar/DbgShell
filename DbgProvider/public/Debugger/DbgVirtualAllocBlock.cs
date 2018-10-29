﻿using System.Collections.Generic;
using System.Linq;
using Microsoft.Diagnostics.Runtime.Interop;

namespace MS.Dbg
{
    public class DbgVirtualAllocBlock
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

        public string Description
        {
            get
            {
                switch (Type)
                {
                    case MEM.IMAGE:
                        try
                        {
                            return Debugger.GetModuleByAddress(BaseAddress).Name;
                        }
                        catch (DbgEngException)
                        {
                            return "<unknown>";
                        }
                    case MEM.PRIVATE:
                        var lookup = GetHeapMap(Debugger);
                        if (lookup.TryGetValue(this.BaseAddress, out var heapBase))
                        {
                            return $"Heap {heapBase:X8}";
                        }
                        goto default;
                    case MEM.MAPPED:
                    default:
                        return "";
                }
            }
        }


        //TODO: some might consider calling this a "cache" somewhat disingenuous, given the complete absence of any invalidation mechanism 
        private static Dictionary<ulong, ulong> m_HeapCache;

        private static Dictionary<ulong, ulong> GetHeapMap(DbgEngDebugger debugger)
        {
            if (m_HeapCache != null)
            {
                return m_HeapCache;
            }

            m_HeapCache = new Dictionary<ulong, ulong>();
            foreach (var heapBase in AllHeaps(debugger))
            {
                foreach (var segment in BlocksForHeap(heapBase, debugger))
                {
                    m_HeapCache[segment.BaseAddress] = heapBase;
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
    }
}
