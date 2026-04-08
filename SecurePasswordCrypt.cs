using System;
using System.Security.Cryptography;
using System.Text;

namespace SecurePasswordCrypt
{
    public static class CryptoService
    {
        // Version byte embedded in the binary layout for forward compatibility
        private const byte FormatVersion = 1;

        // Configuration constants
        private const int KeySize = 32;               // 256 bits
        private const int SaltSize = 32;              // 256 bits
        private const int NonceSize = 12;             // 96 bits for AES-GCM
        private const int TagSize = 16;               // 128 bits
        private const int Iterations = 600_000;       // PBKDF2-SHA256 (OWASP 2023+)

        // Derive a key from a password and salt using PBKDF2
        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(KeySize);
        }

        // Generate a cryptographically secure random byte array
        private static byte[] GenerateRandomBytes(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        // Encrypt plaintext using AES-GCM with a password
        // Layout: version(1) + salt(32) + nonce(12) + tag(16) + ciphertext
        public static string Encrypt(string plainText, string password)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] nonce = GenerateRandomBytes(NonceSize);
            byte[] key = DeriveKey(password, salt);

            try
            {
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBytes = new byte[plaintextBytes.Length];
                byte[] tag = new byte[TagSize];

                using var aesGcm = new AesGcm(key, TagSize);
                aesGcm.Encrypt(nonce, plaintextBytes, cipherBytes, tag);

                // Assemble output without allocating a MemoryStream
                int totalLength = 1 + SaltSize + NonceSize + TagSize + cipherBytes.Length;
                byte[] output = new byte[totalLength];
                int offset = 0;

                output[offset++] = FormatVersion;
                salt.CopyTo(output, offset);   offset += SaltSize;
                nonce.CopyTo(output, offset);  offset += NonceSize;
                tag.CopyTo(output, offset);    offset += TagSize;
                cipherBytes.CopyTo(output, offset);

                return Convert.ToBase64String(output);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        // Decrypt ciphertext using AES-GCM with a password
        public static string Decrypt(string encryptedText, string password)
        {
            if (string.IsNullOrEmpty(encryptedText))
                throw new ArgumentException("Encrypted text cannot be null or empty.", nameof(encryptedText));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            byte[] fullData;
            try
            {
                fullData = Convert.FromBase64String(encryptedText);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Encrypted text is not valid Base64.", nameof(encryptedText), ex);
            }

            int minLength = 1 + SaltSize + NonceSize + TagSize;
            if (fullData.Length < minLength)
                throw new ArgumentException("Encrypted data is too short or corrupted.", nameof(encryptedText));

            int offset = 0;
            byte version = fullData[offset++];
            if (version != FormatVersion)
                throw new NotSupportedException($"Unsupported format version: {version}.");

            byte[] salt       = new byte[SaltSize];
            byte[] nonce      = new byte[NonceSize];
            byte[] tag        = new byte[TagSize];

            Array.Copy(fullData, offset, salt, 0, SaltSize);   offset += SaltSize;
            Array.Copy(fullData, offset, nonce, 0, NonceSize); offset += NonceSize;
            Array.Copy(fullData, offset, tag, 0, TagSize);     offset += TagSize;

            byte[] cipherBytes = new byte[fullData.Length - offset];
            Array.Copy(fullData, offset, cipherBytes, 0, cipherBytes.Length);

            byte[] key = DeriveKey(password, salt);

            try
            {
                byte[] plaintextBytes = new byte[cipherBytes.Length];

                using var aesGcm = new AesGcm(key, TagSize);
                try
                {
                    aesGcm.Decrypt(nonce, cipherBytes, tag, plaintextBytes);
                }
                catch (AuthenticationTagMismatchException)
                {
                    throw new CryptographicException("Decryption failed: incorrect password or data has been tampered with.");
                }

                return Encoding.UTF8.GetString(plaintextBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        // Hash a password using PBKDF2 (for storage)
        // Layout: version(1) + salt(32) + key(32)
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            byte[] salt = GenerateRandomBytes(SaltSize);
            byte[] key = DeriveKey(password, salt);

            try
            {
                var combined = new byte[1 + salt.Length + key.Length];
                combined[0] = FormatVersion;
                Buffer.BlockCopy(salt, 0, combined, 1, salt.Length);
                Buffer.BlockCopy(key, 0, combined, 1 + salt.Length, key.Length);
                return Convert.ToBase64String(combined);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        // Verify a password against a stored hash
        public static bool VerifyPassword(string password, string storedHash)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (string.IsNullOrEmpty(storedHash))
                throw new ArgumentException("Stored hash cannot be null or empty.", nameof(storedHash));

            byte[] combined;
            try
            {
                combined = Convert.FromBase64String(storedHash);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Stored hash is not valid Base64.", nameof(storedHash), ex);
            }

            if (combined.Length < 1 + SaltSize + KeySize)
                throw new ArgumentException("Stored hash is too short or corrupted.", nameof(storedHash));

            byte version = combined[0];
            if (version != FormatVersion)
                throw new NotSupportedException($"Unsupported hash version: {version}.");

            byte[] salt      = new byte[SaltSize];
            byte[] storedKey = new byte[KeySize];
            Buffer.BlockCopy(combined, 1,           salt,      0, SaltSize);
            Buffer.BlockCopy(combined, 1 + SaltSize, storedKey, 0, KeySize);

            byte[] testKey = DeriveKey(password, salt);
            try
            {
                return CryptographicOperations.FixedTimeEquals(testKey, storedKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(testKey);
            }
        }
    }
}

