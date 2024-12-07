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
            Ascon.Ascon_AEAD128 ascon=new Ascon.Ascon_AEAD128();
            ulong[] Message = new ulong[] { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x10ABCDEFFEDCBA01, 0x0ABCDE0000000000 };
            ulong[] Key=new ulong[] { 0x0, 0x0 };
            ulong[] Nonce = new ulong[] { 0x0, 0x0 };
            ulong[] AssocData = new ulong[] { 0x0, 0x1 };

            var result =ascon.Encrypt(Message, 344, Key,Nonce , AssocData,128);

            Console.WriteLine("Padded Plaintext:\n");
            Console.WriteLine(Ascon.CommonOperations.PrintState( Message));

            var ciphertext = result.Item1;
            var tag=result.Item2;

            Console.WriteLine("Ciphertext:\n");
            Console.WriteLine(Ascon.CommonOperations.PrintState(ciphertext));

            Console.WriteLine("\nTag:\n");
            Console.WriteLine(Ascon.CommonOperations.PrintState(tag));

            var decResult= ascon.Decrypt(ciphertext, 344, Key, Nonce, tag, AssocData, 128);
            if(CheckTag(decResult.Item2,tag))
                Console.WriteLine("Verified...");
            else Console.WriteLine("Tag Mismatch");

            Console.WriteLine(Ascon.CommonOperations.PrintState(decResult.Item1));
        }

        static bool CheckTag(ulong[] incomingTag, ulong[] calculatedTag)
        {
            if(incomingTag.Length != calculatedTag.Length)
                return false;
            for (int i = 0; i < incomingTag.Length; i++)
            {
                if(incomingTag[i] != calculatedTag[i])
                    return false;
            }
            return true;
        }
    }
}
