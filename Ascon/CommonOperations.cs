using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class CommonOperations
    {
        public static ulong RightRotate64Bits(ulong x, int rotationCount)
        {
            return (ulong)(x << (64 - rotationCount) ^ (x >> rotationCount));
        }
        public static string PrintState(ulong[] state)
        {
            string strState = "";
            for (int i = 0; i < state.Length; i++)
                strState += string.Format("0x{0:X}", state[i])+"\n";
            return strState;
        }

        public static ulong GetFirstNBits(ulong data, int n)
        {
            ulong mask = 0x0;

            for (int i = 0; i < n; i++)
            {
                mask >>= 1;
                mask ^= 0x8000000000000000L;
            }
            ulong value= data & mask;
            return value;
        }

        public static ulong GetLastNBits(ulong data, int n)
        {
            ulong mask = 0x0;

            for (int i = 0; i < n; i++)
            {
                mask <<= 1;
                mask ^= 0x1L;
            }
            return data & mask;
        }
    }
}
