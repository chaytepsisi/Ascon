using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class Ascon_Hash256
    {
        public ulong[] GenerateAsconHash(ulong[] message, int messageLength)
        {
            ulong[] state = new ulong[5];//320bit state
            ulong[] zeroKey = new ulong[2] { 0x0, 0x0 };
            ulong[] zeroNonce = new ulong[2] { 0x0, 0x0 };

            message = AsconOperations.Pad(message, messageLength);
            AsconOperations.Initialization(state, zeroKey, AsconConstants.HASH_IV, zeroNonce);
            AsconOperations.AbsorbMessage(state, message);

            ulong[] hashValue = new ulong[4];
            hashValue[0] = state[0];
            for (int i = 1; i < 4; i++)// 256/64 = 4 output blocks for 256bit hash
            {
                AsconOperations.Permutation(state, 0, AsconConstants.NumberOfRounds_Pa);
                hashValue[i] = state[0];
            }
            return hashValue;
        }
    }
}
