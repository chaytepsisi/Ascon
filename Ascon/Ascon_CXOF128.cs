using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class Ascon_CXOF128
    {
        public ulong[] GenerateOutput(ulong[] message, int messageLength, ulong[] customizationString, int outputLength)
        {
            ulong[] state = new ulong[5];//320bit state
            ulong[] zeroKey = new ulong[2] { 0x0, 0x0 };
            ulong[] zeroNonce = new ulong[2] { 0x0, 0x0 };

            customizationString = AsconOperations.Pad(customizationString, (int)customizationString[0]);
            message = AsconOperations.Pad(message, messageLength);
            message = customizationString.Concat(message).ToArray();

            AsconOperations.Initialization(state, zeroKey, AsconConstants.CXOF_IV, zeroNonce);
            AsconOperations.AbsorbMessage(state, message);

            int outputBlockSize = (int)Math.Ceiling(outputLength / 64.0);
            ulong[] cxofOutput = new ulong[outputBlockSize];
            cxofOutput[0] = state[0];
            for (int i = 1; i < outputBlockSize; i++)// 256/64 = 4 output blocks for 256bit hash
            {
                AsconOperations.Permutation(state, 0, AsconConstants.NumberOfRounds_Pa);
                cxofOutput[i] = state[0];
            }
            return cxofOutput;
        }
    }
}
