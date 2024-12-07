using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class Ascon_AEAD128
    {
        int dataLength;
        ulong[] ProcessMessage(ulong[] state, ulong[] message)
        {
            ulong[] cText = new ulong[message.Length];
            int j = 0;
            for (; j < (message.Length+1)/2-1; j += 1)
            {
                state[0] ^= message[2 * j];
                state[1] ^= message[2 * j + 1];
                cText[2 * j] = state[0];
                cText[2 * j + 1] = state[1];
                if(j!=message.Length-2)
                    for (int i = 0; i < AsconConstants.NumberOfRounds_Pb; i++)
                        AsconOperations.Permutation(state, i, AsconConstants.NumberOfRounds_Pb);
            }
            if (dataLength % 128 == 0) {
                state[0] ^= message[2 * j];
                state[1] ^= message[2 * j + 1];
                cText[2 * j] =  state[0];
                cText[2 * j + 1] = state[1];
                state[1] ^= 0x1UL << (dataLength % 64 - 1);
            }
            else
            {
                if(dataLength % 128 > 64)
                {
                    state[0] ^= message[2 * j];
                    state[1] ^= CommonOperations.GetFirstNBits(message[2 * j + 1], dataLength % 64);
                    cText[2 * j] = state[0];
                    cText[2 * j + 1] = CommonOperations.GetFirstNBits(state[1], dataLength % 64);
                    state[1] ^= 0x1UL << (dataLength % 64 - 1);
                }
                else
                {
                    state[0] ^= CommonOperations.GetFirstNBits(message[2 * j], dataLength % 64);
                    cText[2 * j] = CommonOperations.GetFirstNBits(state[0], dataLength % 64);
                    cText[2 * j + 1] = 0;
                    if (dataLength % 128 != 64)
                        state[0] ^= 0x1UL << (dataLength % 64 - 1);
                    else state[1] ^= 0x1UL << 63;
                }
            }
            return cText;
        }
        private ulong[] ProcessCipherText(ulong[] state, ulong[] cipherText)
        {
            ulong[] pText = new ulong[cipherText.Length];
            int j = 0;
            for (; j< cipherText.Length/2-1; j += 1)
            {
                pText[2 * j] = state[0]^cipherText[2 * j];
                pText[2 * j+1] = state[1] ^ cipherText[2 * j + 1];
                state[0]=cipherText[2 * j];
                state[1]=cipherText[2 * j + 1];
            
                for (int i = 0; i < AsconConstants.NumberOfRounds_Pb; i++)
                        AsconOperations.Permutation(state, i, AsconConstants.NumberOfRounds_Pb);
            }
           
            if(dataLength%128==0)
            {
                pText[2 * j] = state[0] ^ cipherText[2 * j];
                pText[2 * j + 1] = state[1] ^ cipherText[2 * j + 1];
                state[0] = cipherText[2 * j];
                state[1] = cipherText[2 * j + 1];
            }
            else
            {
                int lastCtextBlockLength = dataLength % 128;
                if (lastCtextBlockLength == 64)
                {
                    pText[2 * j] = state[0] ^ cipherText[2 * j];
                    pText[2 * j + 1] = 0x0L;
                    state[0] = cipherText[2 * j];
                    state[1] ^= 0x8000000000000000L;
                }
                else if (lastCtextBlockLength > 64)
                {
                    int lastBlockSize = dataLength % 64;
                    pText[2 * j] = state[0] ^ cipherText[2 * j];
                    state[0] = cipherText[2 * j];
                    
                    pText[2 * j + 1] = CommonOperations.GetFirstNBits(state[1] ^ cipherText[2 * j + 1], lastBlockSize);
                    state[1] = cipherText[2 * j + 1] ^ CommonOperations.GetLastNBits(state[1],64-lastBlockSize) ^ (0x1UL << (lastBlockSize-1));
                }
                else
                {
                    pText[2 * j] = CommonOperations.GetFirstNBits(state[0] ^ cipherText[2 * j], lastCtextBlockLength);
                    state[0] = cipherText[2 * j + 1] ^ CommonOperations.GetLastNBits(state[0], 64 - lastCtextBlockLength) ^ (0x1UL << (63 - lastCtextBlockLength));
                    pText[2 * j + 1] = 0x0L;

                }
            }
            return pText;
        }

        public (ulong[], ulong[]) Encrypt(ulong[] message, int messageLength, ulong[] key, ulong[] nonce, ulong[] associatedData = null, int associatedDataLength = 0)
        {
            ulong[] state = new ulong[5];
            dataLength=messageLength;
            message=AsconOperations.Pad(message, messageLength);
            AsconOperations.Initialization(state, key, AsconConstants.IV, nonce);
            if (associatedDataLength > 0)
            {
                AsconOperations.Pad(associatedData, associatedDataLength);
                AsconOperations.ProcessAuthanticatedData(state, associatedData);
            }
            var cipherText = ProcessMessage(state, message);
            var tag = AsconOperations.FinalizationAndTagGeneration(state, key);
            return (cipherText, tag);
        }

        public (ulong[], ulong[]) Decrypt(ulong[] cipherText, int cipherTextLength, ulong[] key, ulong[] nonce, ulong[] tag, ulong[] associatedData = null, int associatedDataLength = 0)
        {
            ulong[] state = new ulong[5];
            dataLength = cipherTextLength;
            AsconOperations.Initialization(state, key, AsconConstants.IV, nonce);
            if (associatedDataLength > 0)
            {
                AsconOperations.Pad(associatedData, associatedDataLength);
                AsconOperations.ProcessAuthanticatedData(state, associatedData);
            }
            
            var plainText = ProcessCipherText(state, cipherText);
            var producedTag = AsconOperations.FinalizationAndTagGeneration(state, key);
            return (plainText, producedTag);
        }
    }
}
