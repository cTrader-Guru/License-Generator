using System;
using System.IO;
using cAlgo.API;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;


namespace cAlgo.Robots
{

    [Robot(AccessRights = AccessRights.FullAccess)]
    public class LicenseGenerator : Robot
    {

        #region Identity

        private const string NAME = "License Generator";
        private const string VERSION = "1.073";

        #endregion

        #region Class

        private class LicenseInfo
        {

            public long UserID { get; set; } = 0;

            public string Product { get; set; } = "";          // <-- (Product Name)

            public string Expire { get; set; } = "";           // <-- (*|2022.12.31 23:59:00)

            public bool AllowBackTest { get; set; } = true;

        }

        #endregion

        #region Params

        [Parameter("UserID", DefaultValue = 0, MinValue = 0, Step = 1)]
        public string UserID { get; set; }

        [Parameter("Product", DefaultValue = "")]
        public string Product { get; set; }

        [Parameter("Password", DefaultValue = "")]
        public string Password { get; set; }

        [Parameter("Expire (*|2022.12.31 23:59:00)", DefaultValue = "")]
        public string Expire { get; set; }

        [Parameter("Allow BackTest?", DefaultValue = true)]
        public bool AllowBackTest { get; set; }

        #endregion

        #region Property

        private readonly byte[] IV = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x75, 0x69, 0x0, 0x73, 0x0, 0x0, 0x0, 0x0 };
        private readonly string LocalFileName = "{0}\\cAlgo\\cTraderGuru\\License-{1}.ctg";

        #endregion

        #region cBot Events

        protected override void OnStart()
        {

            Print("{0} : {1}", NAME, VERSION);

            try
            {

                if (long.Parse(UserID) <= 0) { Exit("Please enter a valid 'UserID', greater than zero"); return; }

            }
            catch
            {

                Exit("Please enter a valid 'UserID' like 123456"); return;

            }

            Product = Product.Trim();
            if (Product.Length == 0) { Exit("Please enter a valid 'Product' name"); return; }

            Password = Password.Trim();
            if (Password.Length == 0) { Exit("Please enter a valid 'Password'"); return; }

            Expire = Expire.Trim();
            try
            {

                if (Expire.CompareTo("*") != 0 && DateTime.Parse(Expire).CompareTo(DateTime.Now) < 0) { Exit("Please enter a valid 'Expire' date, greater than now"); return; }

            }
            catch
            {

                Exit("Please enter a valid 'Expire' date (Y.M.D H:m:s)"); return;

            }

            LicenseInfo Info = new LicenseInfo()
            {

                UserID = long.Parse(UserID),
                Product = Product,
                Expire = Expire,
                AllowBackTest = AllowBackTest

            };

            string LicenseFileName = "";
            try
            {

                string EncInfo = Encrypt(JsonSerializer.Serialize<LicenseInfo>(Info));
                string HashName = GetMD5(Product.ToUpper() + UserID);

                LicenseFileName = string.Format(LocalFileName, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), HashName);

                File.WriteAllText(LicenseFileName, EncInfo);

            }
            catch
            {

                Exit("Encryption error"); return;

            }

            Exit($"License created {LicenseFileName}"); return;

        }

        protected override void OnTick()
        {

            // Handle price updates here

        }

        protected override void OnStop()
        {

            // Handle cBot stop here

        }

        #endregion

        #region Private Methods

        private string GetMD5(string input)
        { // <-- https://stackoverflow.com/questions/11454004/calculate-a-md5-hash-from-a-string

            // Use input string to calculate MD5 hash
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }

        }

        private string Encrypt(string PlainText)
        {

            SHA256 mySHA256 = SHA256.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(Password));

            // Instantiate a new Aes object to perform string symmetric encryption
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(key, 0, aesKey, 0, 32);
            encryptor.Key = aesKey;
            encryptor.IV = IV;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesEncryptor = encryptor.CreateEncryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesEncryptor, CryptoStreamMode.Write);

            // Convert the plainText string into a byte array
            byte[] plainBytes = Encoding.ASCII.GetBytes(PlainText);

            // Encrypt the input plaintext string
            cryptoStream.Write(plainBytes, 0, plainBytes.Length);

            // Complete the encryption process
            cryptoStream.FlushFinalBlock();

            // Convert the encrypted data from a MemoryStream to a byte array
            byte[] cipherBytes = memoryStream.ToArray();

            // Close both the MemoryStream and the CryptoStream
            memoryStream.Close();
            cryptoStream.Close();

            // Convert the encrypted byte array to a base64 encoded string
            string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);

            // Return the encrypted data as a string
            return cipherText;

        }

        private string Decrypt(string EncText)
        {

            SHA256 mySHA256 = SHA256.Create();
            byte[] key = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(Password));

            // Instantiate a new Aes object to perform string symmetric encryption
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;

            // Set key and IV
            byte[] aesKey = new byte[32];
            Array.Copy(key, 0, aesKey, 0, 32);
            encryptor.Key = aesKey;
            encryptor.IV = IV;

            // Instantiate a new MemoryStream object to contain the encrypted bytes
            MemoryStream memoryStream = new MemoryStream();

            // Instantiate a new encryptor from our Aes object
            ICryptoTransform aesDecryptor = encryptor.CreateDecryptor();

            // Instantiate a new CryptoStream object to process the data and write it to the 
            // memory stream
            CryptoStream cryptoStream = new CryptoStream(memoryStream, aesDecryptor, CryptoStreamMode.Write);

            // Will contain decrypted plaintext
            string plainText = String.Empty;

            try
            {
                // Convert the ciphertext string into a byte array
                byte[] cipherBytes = Convert.FromBase64String(EncText);

                // Decrypt the input ciphertext string
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);

                // Complete the decryption process
                cryptoStream.FlushFinalBlock();

                // Convert the decrypted data from a MemoryStream to a byte array
                byte[] plainBytes = memoryStream.ToArray();

                // Convert the decrypted byte array to string
                plainText = Encoding.ASCII.GetString(plainBytes, 0, plainBytes.Length);
            }
            finally
            {
                // Close both the MemoryStream and the CryptoStream
                memoryStream.Close();
                cryptoStream.Close();
            }

            // Return the decrypted data as a string
            return plainText;

        }

        private void Exit(string Message)
        {

            Print(Message);
            Stop();

        }

        #endregion

    }

}