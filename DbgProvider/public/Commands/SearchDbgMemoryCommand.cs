using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace MS.Dbg.Commands
{
    [Cmdlet(VerbsCommon.Search, "DbgMemory")]
    [OutputType(typeof(SearchDbgMemoryCommand.SearchResult))]
    public class SearchDbgMemoryCommand : DbgBaseCommand
    {
        public class SearchResult
        {
            public ulong Address { get; set; }
        }

        [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true)]
        [AddressTransformation] //Not necessarily an address, but it is often enough that the semantics are useful
        public ulong SearchValue { get; set; }

        [Parameter(Mandatory = false, Position = 1)]
        public uint SearchValueLengthInBytes { get; set; }

        [Parameter(Mandatory = false)]
        public uint SearchResultAlignment { get; set; }

        [Parameter(Mandatory = false)]
        [AddressTransformation]
        public ulong FromAddress { get; set; }

        [Parameter(Mandatory = false)]
        [RangeTransformation]
        public ulong? SearchRangeInBytes { get; set; }

        [Parameter(Mandatory = false)]
        public bool WritableOnly { get; set; }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            var endAddress = (FromAddress + SearchRangeInBytes) ?? ulong.MaxValue;

            var targetPointerSize = Debugger.TargetIs32Bit ? 4u : 8u;

            var searchLength = SearchValueLengthInBytes == 0 ? targetPointerSize : SearchValueLengthInBytes;
            var searchAlignment = SearchResultAlignment == 0 ? Math.Min(targetPointerSize, searchLength) : SearchResultAlignment;
            var searchForBytes = BitConverter.GetBytes(SearchValue).Take((int)searchLength).ToArray();

            var curAddress = FromAddress;
            while (Debugger.SearchMemory(curAddress, endAddress, searchForBytes, WritableOnly, out var resultAddr))
            {
                curAddress = resultAddr + searchLength;
                if (resultAddr % searchAlignment == FromAddress % searchAlignment)
                {
                    WriteObject(new SearchResult {Address = resultAddr});
                }
            }
        }
    }
}
