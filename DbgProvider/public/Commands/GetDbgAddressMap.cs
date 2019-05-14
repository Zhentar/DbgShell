using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;

namespace MS.Dbg.Commands
{
    [Cmdlet( VerbsCommon.Get, "DbgAddressMap" )]
    [OutputType( typeof( MemoryRegionBase ) )]
    public class GetDbgAddressMap : DbgBaseCommand
    {
        [Parameter( Mandatory = false,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true )]
        [AddressTransformation]
        public ulong Address { get; set; }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            var map = AddressMap.GetAddressMap( Debugger );
            if( Address != 0 )
            {
                foreach( var region in AddressMap.GetMemoryRegionsForAddress( Debugger, Address ) )
                {
                    WriteObject( region );
                }
            }
            else
            {
                foreach( var region in map.Regions )
                {
                    WriteObject( region );
                }
            }
        }
    }
}
