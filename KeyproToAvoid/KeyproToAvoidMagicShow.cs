namespace KeyproToAvoid
{
    using System;

    public class KeyproToAvoidMagicShow
    {
        public static void CheckRunDate()
        {
            string str = string.Empty;
            int num = 0;
            try
            {
                num = int.Parse(AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("MagicShowValidDate")));
                str = AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("MagicShowCheckDate"));
            }
            catch
            {
            }
            string txtToEncrypt = DateTime.Now.ToString("yyyyMMdd");
            if (txtToEncrypt != str)
            {
                AuroraRegistry.SetRegistry("MagicShowCheckDate", AuroraRegistry.RC2Encrypt(txtToEncrypt));
                int num2 = --num;
                AuroraRegistry.SetRegistry("MagicShowValidDate", AuroraRegistry.RC2Encrypt(num2.ToString()));
            }
        }

        public static bool GetKeyproSP(ref byte[] baSP, ref string sDateTime, ref int ErrorCode)
        {
            byte[] cipherText = Authentication.HexToBytes(AuroraRegistry.GetRegistry("MagicShowLicence").Replace("-", ""));
            if (cipherText == null)
            {
                ErrorCode = -2;
                return false;
            }
            byte[] pBLOCK = Authentication.AuthenticationByDevice(cipherText);
            if (pBLOCK != null)
            {
                baSP = pBLOCK;
                if (pBLOCK.Length >= 10)
                {
                    if (!Authentication.CheckRegDate("MagicShowRegDate", ref sDateTime))
                    {
                        ErrorCode = -8;
                        return false;
                    }
                    if (!Authentication.CheckTryDate(pBLOCK, ref sDateTime))
                    {
                        ErrorCode = -9;
                        return false;
                    }
                    if (!Authentication.CheckRunTime("MagicShowValidDate"))
                    {
                        ErrorCode = -7;
                        return false;
                    }
                }
                return true;
            }
            ErrorCode = -3;
            return false;
        }
    }
}

