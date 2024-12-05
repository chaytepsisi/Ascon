using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AsconTest_Console
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Ascon.Ascon ascon=new Ascon.Ascon();
            // Encrypt(ulong[] message, int messageLength, ulong[] key, ulong[] nonce, ulong[] associatedData = null, ulong IV = 0x0L)
            ascon.Encrypt(new ulong[] { 0xFFFFFFFFFFFFFFFF, 0xF000000000000000 },129, new ulong[] { 0x0, 0x0 }, new ulong[] { 0x0, 0x0 }, new ulong[] {0x0,0x1 });
        }
    }
}
