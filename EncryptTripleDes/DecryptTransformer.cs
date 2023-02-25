namespace EncryptTripleDes
{
    using System;
    using System.Security.Cryptography;

    internal class DecryptTransformer
    {
        private EncryptionAlgorithm algorithmID;
        private byte[] initVec;

        internal DecryptTransformer(EncryptionAlgorithm deCryptId)
        {
            this.algorithmID = deCryptId;
        }

        internal ICryptoTransform GetCryptoServiceProvider(byte[] bytesKey)
        {
            switch (this.algorithmID)
            {
                case EncryptionAlgorithm.Des:
                {
                    DES des = new DESCryptoServiceProvider {
                        Mode = CipherMode.CBC,
                        Key = bytesKey,
                        IV = this.initVec
                    };
                    return des.CreateDecryptor();
                }
                case EncryptionAlgorithm.Rc2:
                {
                    RC2 rc = new RC2CryptoServiceProvider {
                        Mode = CipherMode.CBC
                    };
                    return rc.CreateDecryptor(bytesKey, this.initVec);
                }
                case EncryptionAlgorithm.Rijndael:
                {
                    Rijndael rijndael = new RijndaelManaged {
                        Mode = CipherMode.CBC
                    };
                    return rijndael.CreateDecryptor(bytesKey, this.initVec);
                }
                case EncryptionAlgorithm.TripleDes:
                {
                    TripleDES edes = new TripleDESCryptoServiceProvider {
                        Mode = CipherMode.CBC
                    };
                    return edes.CreateDecryptor(bytesKey, this.initVec);
                }
            }
            throw new CryptographicException("Algorithm ID '" + this.algorithmID + "' not supported.");
        }

        internal byte[] IV
        {
            set => 
                (this.initVec = value);
        }
    }
}

