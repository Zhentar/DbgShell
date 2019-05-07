using System;
using System.Runtime.InteropServices;
using System.Text;

namespace MS.Dbg
{
    [StructLayout( LayoutKind.Sequential )]
    public struct IMAGE_SECTION_HEADER
    {
        public string Name
        {
            get
            {
                //On the one hand, the temporary array allocation kills me.
                //On the other hand going unsafe + pinning to avoid an 8 byte array allocation kills me more.
                var nameBytes = new byte[ 8 ];
                MemoryMarshal.Write( nameBytes, ref NameBytes );
                if( nameBytes[ 7 ] == 0 )
                {
                    return Encoding.ASCII.GetString( nameBytes, 0, Array.IndexOf( nameBytes, (byte) 0 ) );
                }
                return Encoding.ASCII.GetString( nameBytes );
            }
        }

        private ulong NameBytes;
        public readonly uint VirtualSize;
        public readonly uint VirtualAddress;
        public readonly uint SizeOfRawData;
        public readonly uint PointerToRawData;
        public readonly uint PointerToRelocations;
        public readonly uint PointerToLinenumbers;
        public readonly ushort NumberOfRelocations;
        public readonly ushort NumberOfLinenumbers;
        public readonly uint Characteristics;
    }
}
