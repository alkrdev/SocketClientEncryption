using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace SecureKeyExchange
{
    public class DiffieHellman : IDisposable
    {
        private Aes aes = null;
        private ECDiffieHellmanCng diffieHellman = null;

        private byte[] publicKey;
        public byte[] PublicKey
        {
            get
            {
                return publicKey;
            }
            set { publicKey = value; }
        }

        public byte[] IV
        {
            get
            {
                return aes.IV;
            }
        }

        public DiffieHellman()
        {
            aes = new AesCryptoServiceProvider();

            diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };

            // This is the public key we will send to the other party
            publicKey = diffieHellman.PublicKey.ToByteArray();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (aes != null)
                    aes.Dispose();

                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }
        }

        public byte[] EncryptString(string secretMessage, byte[] publicKey)
        {
            byte[] encryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = diffieHellman.DeriveKeyMaterial(key); // "Common secret"

            aes.Key = derivedKey;

            using (var cipherText = new MemoryStream())
            {
                using (var encryptor = aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] ciphertextMessage = Encoding.UTF8.GetBytes(secretMessage);
                        cryptoStream.Write(ciphertextMessage, 0, ciphertextMessage.Length);
                    }
                }

                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        public string DecryptString(byte[] encryptedMessage, byte[] publicKey, byte[] IV)
        {
            string decryptedMessage;
            var key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            var derivedKey = diffieHellman.DeriveKeyMaterial(key);

            //var sliced = IV.Take(16).ToArray();
            //aes.BlockSize = 192;

            aes.Key = derivedKey;
            aes.IV = IV; // Sliced?

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                var decBytes = decryptor.TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);
                decryptedMessage = Encoding.UTF8.GetString(decBytes);
            }

            return decryptedMessage;
        }
    }
}