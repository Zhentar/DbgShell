using System;
using System.Collections.Generic;
using Microsoft.Diagnostics.Runtime;

namespace MS.Dbg
{
    class ModuleRegionProvider : IRegionProvider
    {
        public IEnumerable<IMemoryRegion> IdentifyRegions( DbgEngDebugger debugger )
        {
            var is32bit = debugger.TargetIs32Bit;
            foreach(var module in debugger.Modules)
            {
                //Skip Wow64 ntdll from 32-bit mode
                if( is32bit && module.BaseAddress > uint.MaxValue)
                {
                    break;
                }
                yield return new NativeModuleRegion( module );
            }

            foreach(var runtime in debugger.GetCurrentTarget().ClrRuntimes)
            {
                foreach(var clrModule in runtime.Modules)
                {
                    if(clrModule.ImageBase > 0)
                    {
                        yield return new ClrModuleRegion( clrModule, is32bit );
                    }
                }
            }
        }
    }

    public abstract class ModuleRegion : IMemoryRegion
    {
        protected ModuleRegion(Address baseAddr, ulong size)
        {
            BaseAddress = baseAddr;
            Size = size;
        }
        
        public Address BaseAddress { get; }
        public ulong Size { get; }
        public abstract string ModuleName { get; }

        public abstract IEnumerable< IMemoryRegion > SubRegions { get; }
        

        public ColorString ToColorString()
        {
            var cs = BaseAddress.ToColorString( ConsoleColor.DarkYellow );
            cs.Append( " - " );
            cs.Append( (BaseAddress + Size).ToColorString( ConsoleColor.DarkYellow ) );
            cs.Append( " " );
            cs.Append( new ColorString( ConsoleColor.Cyan, ModuleName ) );
            return cs;
        }
    }

    internal class NativeModuleRegion : ModuleRegion
    {
        public NativeModuleRegion(DbgModuleInfo moduleInfo) : base(new Address(moduleInfo.BaseAddress, moduleInfo.Debugger.TargetIs32Bit), moduleInfo.Size )
        {
            m_moduleInfo = moduleInfo;
        }

        private readonly DbgModuleInfo m_moduleInfo;

        public override string ModuleName => m_moduleInfo.Name;

        public override IEnumerable<IMemoryRegion> SubRegions
        {
            get
            {
                foreach( var section in m_moduleInfo.GetSectionHeaders() )
                {
                    yield return new LeafRegion( BaseAddress + section.VirtualAddress, section.VirtualSize, ModuleName + " " + section.Name );
                }
            }
        }
        
    }

    internal class ClrModuleRegion : ModuleRegion
    {
        public ClrModuleRegion( ClrModule moduleInfo, bool is32bit ) : base( new Address( moduleInfo.ImageBase, is32bit ), moduleInfo.Size )
        {
            m_moduleInfo = moduleInfo;
        }

        private readonly ClrModule m_moduleInfo;

        public override string ModuleName => m_moduleInfo.Name;

        public override IEnumerable<IMemoryRegion> SubRegions
        {
            get
            {
                yield break;
                //TODO: yield return PE sections??
            }
        }
    }
}
