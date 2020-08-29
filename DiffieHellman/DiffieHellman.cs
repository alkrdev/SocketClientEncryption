using System;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;

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
                return this.publicKey;
            }
            set { this.publicKey = value; }
        }

        public byte[] IV
        {
            get
            {
                return this.aes.IV;
            }
        }

        public DiffieHellman()
        {
            this.aes = new AesCryptoServiceProvider();

            this.diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };

            // This is the public key we will send to the other party
            this.publicKey = this.diffieHellman.PublicKey.ToByteArray();
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
            var derivedKey = this.diffieHellman.DeriveKeyMaterial(key); // "Common secret"

            this.aes.Key = derivedKey;

            using (var cipherText = new MemoryStream())
            {
                using (var encryptor = this.aes.CreateEncryptor())
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
            var sliced = IV.Take(16).ToArray();

            aes.BlockSize = 192;
            aes.Key = derivedKey;
            aes.IV = sliced;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                var decBytes = decryptor.TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);
                decryptedMessage = Encoding.UTF8.GetString(decBytes);
            }

            return decryptedMessage;
        }
    }
}