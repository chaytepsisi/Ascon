using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    internal class CommonOperations
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
    }
}
