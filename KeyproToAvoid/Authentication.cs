namespace KeyproToAvoid
{
    using EncryptTripleDes;
    using System;
    using System.Management;
    using System.Security.Cryptography;
    using System.Text;

    public class Authentication
    {
        public static byte[] AuthenticationByDevice(byte[] cipherText)
        {
            MD5CryptoServiceProvider provider = new MD5CryptoServiceProvider();
            ManagementObjectCollection instances = new ManagementClass("Win32_ComputerSystemProduct").GetInstances();
            ManagementObjectCollection moc = new ManagementClass("Win32_Processor").GetInstances();
            foreach (ManagementObject obj2 in instances)
            {
                try
                {
                    byte[] buffer = null;
                    string sUUID = obj2["UUID"].ToString().Replace("-", "").Trim();
                    buffer = CPUProcessor(moc, provider, "UniqueId", sUUID, cipherText);
                    if (buffer != null)
                    {
                        return buffer;
                    }
                    buffer = CPUProcessor(moc, provider, "ProcessorId", sUUID, cipherText);
                    if (buffer != null)
                    {
                        return buffer;
                    }
                    buffer = CPUProcessor(moc, provider, "Name", sUUID, cipherText);
                    if (buffer != null)
                    {
                        return buffer;
                    }
                    buffer = CPUProcessor(moc, provider, "Manufacturer", sUUID, cipherText);
                    if (buffer != null)
                    {
                        return buffer;
                    }
                    buffer = CPUProcessor(moc, provider, "MaxClockSpeed", sUUID, cipherText);
                    if (buffer != null)
                    {
                        return buffer;
                    }
                }
                catch
                {
                }
            }
            return null;
        }

        public static bool CheckRegDate(string skey, ref string sDateTime)
        {
            string registry = AuroraRegistry.GetRegistry(skey);
            if (registry == string.Empty)
            {
                return false;
            }
            string s = AuroraRegistry.RC2Decrypt(registry);
            DateTime now = DateTime.Now;
            DateTime time2 = DateTime.ParseExact(s, "yyyyMMdd", null);
            sDateTime = time2.ToShortDateString();
            if (DateTime.Compare(time2, now) > 0)
            {
                return false;
            }
            return true;
        }

        public static bool CheckReleaseDate(byte[] PBLOCK, ref string sDateTime)
        {
            if (PBLOCK.Length >= 14)
            {
                StringBuilder builder = new StringBuilder();
                for (int i = 10; i < 14; i++)
                {
                    builder.AppendFormat("{0:X2}", PBLOCK[i]);
                }
                DateTime now = DateTime.Now;
                DateTime time2 = DateTime.ParseExact(builder.ToString(), "yyyyMMdd", null);
                sDateTime = time2.ToShortDateString();
                if (DateTime.Compare(time2, now) > 0)
                {
                    return false;
                }
            }
            return true;
        }

        public static bool CheckRunTime(string skey)
        {
            string registry = AuroraRegistry.GetRegistry(skey);
            if (registry == string.Empty)
            {
                return false;
            }
            string s = AuroraRegistry.RC2Decrypt(registry);
            int num = 0;
            try
            {
                num = int.Parse(s);
            }
            catch
            {
            }
            return (num > 0);
        }

        public static bool CheckTryDate(byte[] PBLOCK, ref string sDateTime)
        {
            if (PBLOCK.Length >= 10)
            {
                StringBuilder builder = new StringBuilder();
                for (int i = 6; i < 10; i++)
                {
                    builder.AppendFormat("{0:X2}", PBLOCK[i]);
                }
                DateTime now = DateTime.Now;
                DateTime time2 = DateTime.ParseExact(builder.ToString(), "yyyyMMdd", null);
                sDateTime = time2.ToShortDateString();
                if (DateTime.Compare(now, time2) > 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static byte[] CPUProcessor(ManagementObjectCollection moc, MD5CryptoServiceProvider MD5, string wmiProperty, string sUUID, byte[] cipherText)
        {
            foreach (ManagementObject obj2 in moc)
            {
                try
                {
                    string str = obj2[wmiProperty].ToString();
                    byte[] bkey = MD5.ComputeHash(Encoding.ASCII.GetBytes(str + sUUID));
                    byte[] buffer2 = DecryptBytes(cipherText, bkey);
                    if (buffer2 != null)
                    {
                        return buffer2;
                    }
                }
                catch
                {
                }
            }
            return null;
        }

        private static byte[] DecryptBytes(byte[] cipherText, byte[] bkey)
        {
            try
            {
                EncryptionAlgorithm tripleDes = EncryptionAlgorithm.TripleDes;
                byte[] bytesKey = bkey;
                byte[] bytes = Encoding.ASCII.GetBytes("27475277");
                Decryptor decryptor = new Decryptor(tripleDes) {
                    IV = bytes
                };
                return decryptor.Decrypt(cipherText, bytesKey);
            }
            catch
            {
                return null;
            }
        }

        public static byte[] HexToBytes(string str)
        {
            try
            {
                byte[] buffer = new byte[str.Length / 2];
                if (buffer.Length == 0)
                {
                    return null;
                }
                for (int i = 0; i < (str.Length / 2); i++)
                {
                    int num2 = Convert.ToInt32(str.Substring(i * 2, 2), 0x10);
                    buffer[i] = (byte) num2;
                }
                return buffer;
            }
            catch
            {
                return null;
            }
        }
    }
}

