using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Runtime.Interop;

namespace MS.Dbg.Commands
{
	[Cmdlet(VerbsCommon.Get, "DbgVirtualAllocBlock")]
	[OutputType(typeof(DbgVirtualAllocBlock))]
	public class GetDbgVirtualAllocBlockCommand : DbgBaseCommand
	{
		[Parameter(Mandatory = false,
			Position = 0,
			ValueFromPipeline = true,
			ValueFromPipelineByPropertyName = true)]
		[AddressTransformation]
		public ulong Address { get; set; }

		protected override void ProcessRecord()
		{
			base.ProcessRecord();

			if (Address != 0)
			{
				WriteObject(new DbgVirtualAllocBlock(Address, Debugger));
			}
			else
			{
				foreach (var block in DbgVirtualAllocBlock.AllBlocks(Debugger))
				{
					WriteObject(block);
				}
			}
		}
	}
}
