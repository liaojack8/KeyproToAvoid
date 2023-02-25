namespace KeyproToAvoid
{
    using Microsoft.Win32;
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    public class AuroraRegistry
    {
        private static byte[] key = Encoding.ASCII.GetBytes("Aurora");
        private static byte[] IV = Encoding.ASCII.GetBytes("AuroraLicenses");

        public static string GetRegistry(string skey)
        {
            try
            {
                return Registry.LocalMachine.OpenSubKey("SOFTWARE").OpenSubKey("AURORA").GetValue(skey).ToString();
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string RC2Decrypt(string txtToDecrypt)
        {
            byte[] buffer = Convert.FromBase64String(txtToDecrypt);
            using (RC2CryptoServiceProvider provider = new RC2CryptoServiceProvider())
            {
                ICryptoTransform transform = provider.CreateDecryptor(key, IV);
                MemoryStream stream = new MemoryStream();
                using (CryptoStream stream2 = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    stream2.Write(buffer, 0, buffer.Length);
                    stream2.FlushFinalBlock();
                    stream2.Close();
                }
                string str = Encoding.UTF8.GetString(stream.ToArray());
                stream.Close();
                return str;
            }
        }

        public static string RC2Encrypt(string txtToEncrypt)
        {
            new UnicodeEncoding();
            byte[] bytes = Encoding.UTF8.GetBytes(txtToEncrypt);
            using (RC2CryptoServiceProvider provider = new RC2CryptoServiceProvider())
            {
                ICryptoTransform transform = provider.CreateEncryptor(key, IV);
                MemoryStream stream = new MemoryStream();
                using (CryptoStream stream2 = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    stream2.Write(bytes, 0, bytes.Length);
                    stream2.FlushFinalBlock();
                    stream2.Close();
                }
                string str = Convert.ToBase64String(stream.ToArray());
                stream.Close();
                return str;
            }
        }

        public static void SetRegistry(string skey, string sValue)
        {
            RegistryKey key = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
            key.CreateSubKey("AURORA");
            key.OpenSubKey("AURORA", true).SetValue(skey, sValue);
        }
    }
}

