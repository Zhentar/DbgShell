using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MS.Dbg
{ 
    public readonly struct Address : ISupportColor, IComparable<Address>, IEquatable<Address>
    {
        private const ulong FlagBitmask = 0x7000_0000_0000_0000;

        public Address(ulong address, DbgEngDebugger debugger) : this(address, debugger.TargetIs32Bit)
        { }

        public Address(ulong address, bool is32Bit)
        {
            m_addressAndBitnessFlag = is32Bit ? address : (address | FlagBitmask);
        }

        readonly ulong m_addressAndBitnessFlag;

        public ulong Value => (ulong)((((long)m_addressAndBitnessFlag) << 1) >> 1);

        public bool Is32Bit => (m_addressAndBitnessFlag & FlagBitmask) == 0;

        public ColorString ToColorString() => DbgProvider.FormatAddress( Value, Is32Bit, true, true );

        public ColorString ToColorString( ConsoleColor color ) => DbgProvider.FormatAddress( Value, Is32Bit, true, true, color );


        //Operators & interfaces

        public int CompareTo( Address other ) => Value.CompareTo( other.Value );

        public bool Equals( Address other ) => Value.Equals( other.Value );


        public static Address operator +( Address lhs, ulong rhs ) => new Address( lhs.Value + rhs, lhs.Is32Bit );

        //While this is technically a lossy conversion, the loss is purely formatting so implicit it is for convenience.
        public static implicit operator ulong(Address a) => a.Value;
    }
}
