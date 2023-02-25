namespace EncryptTripleDes
{
    using System;
    using System.Security.Cryptography;

    internal class EncryptTransformer
    {
        private EncryptionAlgorithm algorithmID;
        private byte[] initVec;
        private byte[] encKey;

        internal EncryptTransformer(EncryptionAlgorithm algId)
        {
            this.algorithmID = algId;
        }

        internal ICryptoTransform GetCryptoServiceProvider(byte[] bytesKey)
        {
            DES des;
            switch (this.algorithmID)
            {
                case EncryptionAlgorithm.Des:
                    des = new DESCryptoServiceProvider {
                        Mode = CipherMode.CBC
                    };
                    if (bytesKey != null)
                    {
                        des.Key = bytesKey;
                        this.encKey = des.Key;
                        break;
                    }
                    this.encKey = des.Key;
                    break;

                case EncryptionAlgorithm.Rc2:
                {
                    RC2 rc = new RC2CryptoServiceProvider {
                        Mode = CipherMode.CBC
                    };
                    if (bytesKey != null)
                    {
                        rc.Key = bytesKey;
                        this.encKey = rc.Key;
                    }
                    else
                    {
                        this.encKey = rc.Key;
                    }
                    if (this.initVec == null)
                    {
                        this.initVec = rc.IV;
                    }
                    else
                    {
                        rc.IV = this.initVec;
                    }
                    return rc.CreateEncryptor();
                }
                case EncryptionAlgorithm.Rijndael:
                {
                    Rijndael rijndael = new RijndaelManaged {
                        Mode = CipherMode.CBC
                    };
                    if (bytesKey != null)
                    {
                        rijndael.Key = bytesKey;
                        this.encKey = rijndael.Key;
                    }
                    else
                    {
                        this.encKey = rijndael.Key;
                    }
                    if (this.initVec == null)
                    {
                        this.initVec = rijndael.IV;
                    }
                    else
                    {
                        rijndael.IV = this.initVec;
                    }
                    return rijndael.CreateEncryptor();
                }
                case EncryptionAlgorithm.TripleDes:
                {
                    TripleDES edes = new TripleDESCryptoServiceProvider {
                        Mode = CipherMode.CBC
                    };
                    if (bytesKey != null)
                    {
                        edes.Key = bytesKey;
                        this.encKey = edes.Key;
                    }
                    else
                    {
                        this.encKey = edes.Key;
                    }
                    if (this.initVec == null)
                    {
                        this.initVec = edes.IV;
                    }
                    else
                    {
                        edes.IV = this.initVec;
                    }
                    return edes.CreateEncryptor();
                }
                default:
                    throw new CryptographicException("Algorithm ID '" + this.algorithmID + "' not supported.");
            }
            if (this.initVec == null)
            {
                this.initVec = des.IV;
            }
            else
            {
                des.IV = this.initVec;
            }
            return des.CreateEncryptor();
        }

        internal byte[] IV
        {
            get => 
                this.initVec;
            set => 
                (this.initVec = value);
        }

        internal byte[] Key =>
            this.encKey;
    }
}

