using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Ascon
{
    internal class AsconConstants
    {
        public const ulong IV_Ascon128 = 0x80400c0600000000;
        public const ulong IV_Ascon128a = 0x80800c0800000000;
        public const ulong IV_Ascon80pq = 0x00000000a0400c06;

        public const int NumberOfRounds_pa= 12;
        public const int NumberOfRounds_pb_Ascon128 = 8;//6 in the original submission
        public const int NumberOfRounds_pb_Ascon128a = 8;

        public const int KeySize= 128;
        public const int KeySize_Ascon80pq = 160;

        public const int NonceSize = 128;
        public const int TagSize = 128;

        public const ulong DataBlockSize_Ascon128 = 64;
        public const ulong DataBlockSize_Ascon128a = 64;
        public const ulong DataBlockSize_Ascon80pq = 128;

        public static ulong[] RoundConstants = new ulong[]{0x000000000000003cL, 0x000000000000002dL, 0x000000000000001eL, 0x000000000000000fL, 0x00000000000000f0L, 0x00000000000000e1L, 0x00000000000000d2L, 0x00000000000000c3L, 0x00000000000000b4L, 0x00000000000000a5L, 0x0000000000000096L, 0x0000000000000087L, 0x0000000000000078L, 0x0000000000000069L, 0x000000000000005aL, 0x000000000000004bL };

    }
}
