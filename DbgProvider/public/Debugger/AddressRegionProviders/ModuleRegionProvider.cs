﻿using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Diagnostics.Runtime;

namespace MS.Dbg.AddressRegionProviders
{
    class ModuleRegionProvider : IRegionProvider
    {
        public IEnumerable< MemoryRegionBase > IdentifyRegions( DbgEngDebugger debugger )
        {
            var NativeModules = new HashSet<string>();
            var is32bit = debugger.TargetIs32Bit;
            foreach( var module in debugger.Modules )
            {
                //Skip Wow64 ntdll from 32-bit mode
                if( is32bit && module.BaseAddress > uint.MaxValue )
                {
                    break;
                }
                yield return new NativeModuleRegion( module );
                NativeModules.Add( module.Name );
            }

            foreach( var runtime in debugger.GetCurrentTarget().ClrRuntimes )
            {
                foreach( var clrModule in runtime.Modules )
                {
                    if( clrModule.ImageBase > 0 )
                    {
                        var region = new ClrModuleRegion( clrModule, is32bit );
                        if( !NativeModules.Contains( region.ModuleName ) &&
                            !NativeModules.Contains( region.ModuleName.Replace('.','_') + "_ni"))
                        {
                            yield return region;
                        }
                    }
                }
            }
        }
    }

    public abstract class ModuleRegion : MemoryRegionBase
    {
        protected ModuleRegion( Address baseAddr, ulong size )
            : base( baseAddr, size )
        {
        }

        public abstract string ModuleName { get; }
        public override ColorString Description => new ColorString( ConsoleColor.White, ModuleName );
    }

    internal class NativeModuleRegion : ModuleRegion
    {
        public NativeModuleRegion( DbgModuleInfo moduleInfo ) : base( new Address( moduleInfo.BaseAddress, moduleInfo.Debugger.TargetIs32Bit ),
                                                                      moduleInfo.Size )
        {
            m_moduleInfo = moduleInfo;
        }

        private readonly DbgModuleInfo m_moduleInfo;

        public override string ModuleName => m_moduleInfo.Name;

        public override IEnumerable< MemoryRegionBase > SubRegions
        {
            get
            {
                foreach( var section in m_moduleInfo.GetSectionHeaders() )
                {
                    yield return new LeafRegion( BaseAddress + section.VirtualAddress, section.VirtualSize,
                                                 new ColorString( ConsoleColor.Cyan, ModuleName ).Append( " " + section.Name ) );
                }
            }
        }
    }

    internal class ClrModuleRegion : ModuleRegion
    {
        public ClrModuleRegion( ClrModule moduleInfo, bool is32bit )
            : base( new Address( moduleInfo.ImageBase, is32bit ), moduleInfo.Size )
        {
            m_moduleInfo = moduleInfo;
        }

        private readonly ClrModule m_moduleInfo;

        public override string ModuleName => Path.GetFileNameWithoutExtension( m_moduleInfo.AssemblyName );

        public override IEnumerable< MemoryRegionBase > SubRegions
        {
            get
            {
                yield break;
                //TODO: yield return PE sections??
            }
        }
    }
}