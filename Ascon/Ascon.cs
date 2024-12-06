using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    public class Ascon
    {

        void P_AddConstantLayer(ulong[] state, int i, int numberOfRounds)
        {
            state[2] ^= AsconConstants.RoundConstants[16 - numberOfRounds + i];
        }
        void P_SubstutitionLayer(ulong[] state)
        {
            state[0] ^= state[4];
            state[2] ^= state[1];
            state[4] ^= state[3];

            ulong[] tempState = new ulong[state.Length];
            for (int i = 0; i < tempState.Length; i++)
                tempState[i] = state[i];

            tempState[0] = (tempState[0] ^ 1) & state[1];
            tempState[1] = (tempState[1] ^ 1) & state[2];
            tempState[2] = (tempState[2] ^ 1) & state[3];
            tempState[3] = (tempState[3] ^ 1) & state[4];
            tempState[4] = (tempState[4] ^ 1) & state[0];

            //Order of the operations are important
            //Do NOT reorder the following lines
            state[1] ^= tempState[2] ^ state[0];
            state[3] ^= tempState[4] ^ state[2];
            state[0] ^= tempState[1] ^ state[4];
            state[2] ^= tempState[3] ^ 1;
            state[4] ^= tempState[0];
            //Alternative_P_SubstutionLayer(state);
        }
        void Alternative_P_SubstutionLayer(ulong[] state)
        {
            int[] sBox = new int[] { 0x4, 0xb, 0x1f, 0x14, 0x1a, 0x15, 0x9, 0x2, 0x1b, 0x5, 0x8, 0x12, 0x1d, 0x3, 0x6, 0x1c, 0x1e, 0x13, 0x7, 0xe, 0x0, 0xd, 0x11, 0x18, 0x10, 0xc, 0x1, 0x19, 0x16, 0xa, 0xf, 0x17 };

            ulong[] tempState = new ulong[state.Length];

            for (int i = 0; i < 64; i++)
            {
                int input = 0x0;
                for (int j = 0; j < state.Length; j++)
                {
                    input <<= 1;
                    input ^= (int)((state[j] >> (63 - i)) & 0x1);
                }
                int output = sBox[input];

                for (int j = 0; j < tempState.Length; j++)
                {
                    tempState[j] ^= (ulong)(input & 0x1);
                    output >>= 1;
                }
            }
        }
        void P_LinearLayer(ulong[] state)
        {
            state[0] ^= CommonOperations.RightRotate64Bits(state[0], 19) ^ CommonOperations.RightRotate64Bits(state[0], 28);
            state[1] ^= CommonOperations.RightRotate64Bits(state[1], 61) ^ CommonOperations.RightRotate64Bits(state[1], 39);
            state[2] ^= CommonOperations.RightRotate64Bits(state[2], 1) ^ CommonOperations.RightRotate64Bits(state[2], 6);
            state[3] ^= CommonOperations.RightRotate64Bits(state[3], 10) ^ CommonOperations.RightRotate64Bits(state[3], 17);
            state[4] ^= CommonOperations.RightRotate64Bits(state[4], 7) ^ CommonOperations.RightRotate64Bits(state[4], 41);
        }
        void Permutation(ulong[] state, int i, int totalNumberOfRounds)
        {
            P_AddConstantLayer(state, i, totalNumberOfRounds);
            P_SubstutitionLayer(state);
            P_LinearLayer(state);
        }

        void Pad(ulong[] data, int dataLength)
        {
            if (dataLength % 128 == 0)
                return;
            else
            {
                int paddingLength = 128-(dataLength % 128);
                if(paddingLength==64)
                {
                    ulong newLastBlock = 0x8000000000000000L;
                    data=data.Append(newLastBlock).ToArray();
                }
                else if (paddingLength > 64)
                {
                    int tempPaddingLength = 64-(dataLength % 64);
                    ulong paddedBlock = data[data.Length - 1] >> tempPaddingLength;
                    paddedBlock <<= 1;
                    paddedBlock ^= 0x1;
                    paddedBlock <<= (tempPaddingLength - 1);
                    data[data.Length - 1] = paddedBlock;

                    ulong newLastBlock = 0x0L;
                    data = data.Append(newLastBlock).ToArray();
                }
                else
                {
                    ulong paddedBlock = data[data.Length - 1] >> paddingLength;
                    paddedBlock <<= 1;
                    paddedBlock ^= 0x1;
                    paddedBlock <<= (paddingLength - 1);
                    data[data.Length - 1] = paddedBlock;
                }
            }
        }

        void Initialization(ulong[] state, ulong[] key, ulong IV, ulong[] nonce)
        {
            state[0] = IV;
            state[1] = key[0];
            state[2] = key[1];
            state[3] = nonce[0];
            state[4] = nonce[1];

            for (int i = 0; i < AsconConstants.NumberOfRounds_Pa; i++)
            {
                Permutation(state, i, AsconConstants.NumberOfRounds_Pa);
            }
            state[3] ^= key[0];
            state[4] ^= key[1];
        }

        void ProcessAuthanticatedData(ulong[] state, ulong[] assocData)
        {
            for (int j = 0; j < assocData.Length; j += 2)
            {
                state[0] ^= assocData[j];
                state[1] ^= assocData[j + 1];
                for (int i = 0; i < AsconConstants.NumberOfRounds_Pb; i++)
                    Permutation(state, i, AsconConstants.NumberOfRounds_Pb);
            }
            state[4] ^= 0x1L;
        }

        ulong[] ProcessMessage(ulong[] state, ulong[] message)
        {
            ulong[] cText = new ulong[message.Length];
            for (int j = 0; j < message.Length; j += 2)
            {
                state[0] ^= message[2 * j];
                state[1] ^= message[2 * j + 1];
                cText[2 * j] = state[0];
                cText[2 * j + 1] = state[1];

                for (int i = 0; i < AsconConstants.NumberOfRounds_Pb; i++)
                    Permutation(state, i, AsconConstants.NumberOfRounds_Pb);
            }
            return cText;
        }

        ulong[]  FinalizationAndTagGeneration(ulong[] state, ulong[] key)
        {
            //XOR the Key to the state as S=S ^ (0..00|K|000..00) 
            state[2] ^= key[0];
            state[3] ^= key[1];

            for (int i = 0; i < AsconConstants.NumberOfRounds_Pa; i++)
                Permutation(state, i, AsconConstants.NumberOfRounds_Pa);

            state[3] ^= key[0];
            state[4] ^= key[1];

            return new ulong[] { state[3], state[4] };
        }

        public (ulong[], ulong[]) Encrypt(ulong[] message, int messageLength, ulong[] key, ulong[] nonce, ulong[] associatedData = null, int associatedDataLength=0)
        {
            ulong[] state = new ulong[] { 0x0L, 0x0L, 0x0L, 0x0L, 0x0L };
            Pad(message, messageLength);
            Initialization(state, key, AsconConstants.IV, nonce);
            if (associatedDataLength > 0)
            {
                Pad(associatedData, associatedDataLength);
                ProcessAuthanticatedData(state, associatedData);
            }
            var cipherText = ProcessMessage(state, message);
            var tag = FinalizationAndTagGeneration(state, key);
            Console.WriteLine("\n");
            Console.WriteLine(CommonOperations.PrintState(state));
            return (cipherText,tag);
        }
    }
}
