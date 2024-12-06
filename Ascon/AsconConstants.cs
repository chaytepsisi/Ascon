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
        public const ulong IV = 0x00001000808c0001;

        public const int NumberOfRounds_Pa= 12;
        public const int NumberOfRounds_Pb = 8;

        public const int KeySize= 128;
        public const int NonceSize = 128;
        public const int TagSize = 128;

        public const ulong DataBlockSize = 64;


        public static ulong[] RoundConstants = new ulong[]{0x000000000000003cL, 0x000000000000002dL, 0x000000000000001eL, 0x000000000000000fL, 0x00000000000000f0L, 0x00000000000000e1L, 0x00000000000000d2L, 0x00000000000000c3L, 0x00000000000000b4L, 0x00000000000000a5L, 0x0000000000000096L, 0x0000000000000087L, 0x0000000000000078L, 0x0000000000000069L, 0x000000000000005aL, 0x000000000000004bL };

    }
}
