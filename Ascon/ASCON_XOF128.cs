using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class ASCON_XOF128
    {
        public ulong[] GenerateOutput(ulong[] message, int messageLength, int outputLength)
        {
            ulong[] state = new ulong[5];//320bit state
            ulong[] zeroKey = new ulong[2] { 0x0, 0x0 };
            ulong[] zeroNonce = new ulong[2] { 0x0, 0x0 };

            message = AsconOperations.Pad(message, messageLength);
            AsconOperations.Initialization(state, zeroKey, AsconConstants.XOF_IV, zeroNonce);
            AsconOperations.AbsorbMessage(state, message);

            int outputBlockSize = (int)Math.Ceiling(outputLength / 64.0);
            ulong[] xofOutput = new ulong[outputBlockSize];
            xofOutput[0] = state[0];
            for (int i = 1; i < outputBlockSize; i++)// 256/64 = 4 output blocks for 256bit hash
            {
                AsconOperations.Permutation(state, 0, AsconConstants.NumberOfRounds_Pa);
                xofOutput[i] = state[0];
            }
            return xofOutput;
        }
    }
}
