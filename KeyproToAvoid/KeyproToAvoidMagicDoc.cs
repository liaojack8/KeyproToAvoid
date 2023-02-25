namespace KeyproToAvoid
{
    using System;

    public class KeyproToAvoidMagicDoc
    {
        public static void CheckRunDate()
        {
            string str = string.Empty;
            int num = 0;
            try
            {
                num = int.Parse(AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("MagicDocValidDate")));
                str = AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("MagicDocCheckDate"));
            }
            catch
            {
            }
            string txtToEncrypt = DateTime.Now.ToString("yyyyMMdd");
            if (txtToEncrypt != str)
            {
                AuroraRegistry.SetRegistry("MagicDocCheckDate", AuroraRegistry.RC2Encrypt(txtToEncrypt));
                int num2 = --num;
                AuroraRegistry.SetRegistry("MagicDocValidDate", AuroraRegistry.RC2Encrypt(num2.ToString()));
            }
        }

        public static int GetVersion(ref string sDateTime)
        {
            byte[] cipherText = Authentication.HexToBytes(AuroraRegistry.GetRegistry("MagicDocLicence").Replace("-", ""));
            if (cipherText == null)
            {
                return -2;
            }
            byte[] pBLOCK = Authentication.AuthenticationByDevice(cipherText);
            if (pBLOCK == null)
            {
                return -3;
            }
            if (pBLOCK.Length >= 10)
            {
                if (!Authentication.CheckRegDate("MagicDocRegDate", ref sDateTime))
                {
                    return -8;
                }
                if (!Authentication.CheckTryDate(pBLOCK, ref sDateTime))
                {
                    return -9;
                }
                if (!Authentication.CheckRunTime("MagicDocValidDate"))
                {
                    return -7;
                }
            }
            return Convert.ToInt32(pBLOCK[1]);
        }
    }
}

