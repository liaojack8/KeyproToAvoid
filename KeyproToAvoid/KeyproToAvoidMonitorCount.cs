namespace KeyproToAvoid
{
    using System;

    public class KeyproToAvoidMonitorCount
    {
        public static void CheckRunDate()
        {
            string str = string.Empty;
            int num = 0;
            try
            {
                num = int.Parse(AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("SmartMonitorValidDate")));
                str = AuroraRegistry.RC2Decrypt(AuroraRegistry.GetRegistry("SmartMonitorCheckDate"));
            }
            catch
            {
            }
            string txtToEncrypt = DateTime.Now.ToString("yyyyMMdd");
            if (txtToEncrypt != str)
            {
                AuroraRegistry.SetRegistry("SmartMonitorCheckDate", AuroraRegistry.RC2Encrypt(txtToEncrypt));
                int num2 = --num;
                AuroraRegistry.SetRegistry("SmartMonitorValidDate", AuroraRegistry.RC2Encrypt(num2.ToString()));
            }
        }

        public static int GetMfpMaxMonitorCount(ref string sDateTime)
        {
            byte[] cipherText = Authentication.HexToBytes(AuroraRegistry.GetRegistry("SmartMonitorLicence").Replace("-", ""));
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
                if (!Authentication.CheckRegDate("SmartMonitorRegDate", ref sDateTime))
                {
                    return -8;
                }
                if (!Authentication.CheckTryDate(pBLOCK, ref sDateTime))
                {
                    return -9;
                }
                if (!Authentication.CheckRunTime("SmartMonitorValidDate"))
                {
                    return -7;
                }
            }
            return Convert.ToInt32(pBLOCK[1]);
        }

        public static int GetOcrMaxMonitorCount(ref string sDateTime)
        {
            byte[] cipherText = Authentication.HexToBytes(AuroraRegistry.GetRegistry("SmartMonitorLicence").Replace("-", ""));
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
                if (!Authentication.CheckRegDate("SmartMonitorRegDate", ref sDateTime))
                {
                    return -8;
                }
                if (!Authentication.CheckTryDate(pBLOCK, ref sDateTime))
                {
                    return -9;
                }
                if (!Authentication.CheckRunTime("SmartMonitorValidDate"))
                {
                    return -7;
                }
            }
            return Convert.ToInt32(pBLOCK[2]);
        }
    }
}

