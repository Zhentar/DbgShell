using System;
using System.Collections.Generic;

namespace MS.Dbg.AddressRegionProviders
{
    class ClrRegionProvider : IRegionProvider
    {
        public IEnumerable<MemoryRegionBase> IdentifyRegions( DbgEngDebugger debugger )
        {
            foreach( var runtime in debugger.GetCurrentTarget().ClrRuntimes )
            {
                //foreach( var segment in runtime.GetHeap().Segments)
                //{
                //    var startAddr = new Address( Util.RoundDownToVirtualAllocGranularity( segment.Start ), debugger );
                //    yield return new LeafRegion( startAddr , segment.ReservedEnd - startAddr, new ColorString( ConsoleColor.Yellow, "CLR Heap" ) );
                //}
                foreach( var region in runtime.EnumerateMemoryRegions())
                {
                    var start = region.Address;
                    var size = region.Size;
                    if(region.Type == Microsoft.Diagnostics.Runtime.ClrMemoryRegionType.GCSegment)
                    {
                        start = Util.RoundDownToVirtualAllocGranularity( start ); //The first page of each heap segment doesn't get reported
                        size += region.Address - start;
                    }
                    yield return new LeafRegion( new Address( start, debugger ), size, new ColorString( ConsoleColor.Yellow, "CLR " + region.Type ) );
                }
            }
        }
    }
}
