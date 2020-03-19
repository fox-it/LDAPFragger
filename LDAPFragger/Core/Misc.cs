using System;
using System.IO;
using System.Linq;
using System.Text;

namespace LDAPFragger.Core
{
    class Misc
    {

        //public string ConvertByteArrayToHex

        /// <summary>
        /// Chops string into multiple pieces by given size
        /// </summary>
        /// <param name="value"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string[] Chop(string value, int length)
        {
            int strLength = value.Length;
            int strCount = (strLength + length - 1) / length;
            string[] result = new string[strCount];
            for (int i = 0; i < strCount; ++i)
            {
                result[i] = value.Substring(i * length, Math.Min(length, strLength));
                strLength -= length;
            }
            return result;
        }

        /// <summary>
        /// Generates a random alphanumeric string 
        /// </summary>
        /// <returns></returns>
        public static string GenerateId(int length = 4)
        {
            var lCase = "abcdefghijklmnopqrstuvwxyz";
            var uCase = lCase.ToUpper();
            var digit = "0123456789";
            char[] chars = string.Join("", lCase, uCase, digit).ToCharArray();

            var result = new StringBuilder();

            Random rnd = new Random();            
            for(int i = 0; i < length; i++)
            {
                int index = rnd.Next(0, chars.Length - 1);
                result.Append(chars[index]);
            }
            
            return result.ToString();            
        }

         /// <summary>
        /// Encodes bytearray to base64
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static string Base64Encode(byte[] Data)
        {
            return Convert.ToBase64String(Data);
        }

        /// <summary>
        /// Encodes string to base64
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static string Base64Encode(string Data)
        {
            var blob = Encoding.ASCII.GetBytes(Data);
            return Base64Encode(blob);
        }

        /// <summary>
        /// Decodes base64 string to bytearray
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static byte[] Base64Decode(string Data)
        {
            return Convert.FromBase64String(Data);
        }

        /// <summary>
        /// Writes a generic message to the console
        /// </summary>
        /// <param name="msg"></param>
        public static void WriteGood(string msg)
        {            
            if (Program.Verbose)
                Console.WriteLine("[+] {0}", msg);
        }

        /// <summary>
        /// Writes an error message to the console
        /// </summary>
        /// <param name="msg"></param>
        public static void WriteBad(string msg)
        {
            if (Program.Verbose)
                Console.WriteLine("[-] {0}", msg);
        }

        /// <summary>
        /// Used to update the same line with new data
        /// </summary>
        /// <param name="msg"></param>
        public static void WriteUpdate(string msg)
        {
            if (Program.Verbose)
                Console.Write("\r[*] {0}   ", msg);            
        }

        /// <summary>
        /// Returns whether OS is x64 of x86
        /// </summary>
        /// <returns></returns>
        public static bool Is64BitOS()
        {
            return Environment.Is64BitOperatingSystem;
        }


        /// <summary>
        /// Saves bytearray to a file
        /// https://stackoverflow.com/questions/6397235/write-bytes-to-file
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        public static bool ByteArrayToFile(string fileName, byte[] byteArray)
        {
            try
            {

                // Delete file if it exists
                if (File.Exists(fileName))
                    File.Delete(fileName);

                using (var fs = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(byteArray, 0, byteArray.Length);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception caught in process: {0}", ex);
                return false;
            }
        }

        /// <summary>
        /// Converts integer to little endian
        /// </summary>
        /// <param name="data">integer to convert</param>
        /// <returns></returns>
        public static byte[] convertToLE(int data)
        {
            byte[] bytes = BitConverter.GetBytes(data);
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }

            return bytes;
        }

        /// <summary>
        /// Converts LE to BE
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] convertToBE(byte[] data)
        {
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(data);
            }
            
            return data;
        }

        /// <summary>
        /// Concats byte arrays
        /// </summary>
        /// <param name="arrays"></param>
        /// <returns></returns>
        public static byte[] Combine(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        /// <summary>
        /// Returns a string representation of a byte array
        /// </summary>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        public static string PrintBytes(byte[] byteArray)
        {
            var sb = new StringBuilder("struct.unpack('<I',");
            for (var i = 0; i < byteArray.Length; i++)
            {
                var b = byteArray[i];
                int iByte = Int32.Parse(b.ToString());

                if (iByte < 10)
                    sb.Append(@"\x0" + iByte.ToString());
                else
                    sb.Append(@"\x" + iByte.ToString());

                if (i < byteArray.Length - 1)
                {
                    //sb.Append(", ");
                }
            }
            sb.Append("')[0]");
            return sb.ToString();
        }


    }
}
