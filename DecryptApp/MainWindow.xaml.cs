using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace DecryptApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        string password = "Q0hBSU9wZW5NUlMrTElNUw==";

        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.BlockSize = 128;
            aes.KeySize = 256;

            // It is equal in java 
            /// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");    
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] keyArr = Convert.FromBase64String(password);
            byte[] KeyArrBytes32Value = new byte[16];
            Array.Copy(keyArr, KeyArrBytes32Value, 16);

            // It must be same as in Java
            byte[] ivArr = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
            byte[] IVBytes16Value = new byte[16];
            Array.Copy(ivArr, IVBytes16Value, 16);

            aes.Key = KeyArrBytes32Value;
            aes.IV = IVBytes16Value;

            ICryptoTransform encrypto = aes.CreateEncryptor();

            byte[] plainTextByte = ASCIIEncoding.UTF8.GetBytes(txtInput.Text);
            byte[] CipherText = encrypto.TransformFinalBlock(plainTextByte, 0, plainTextByte.Length);
            txtInput.Text = Convert.ToBase64String(CipherText);
        }

        private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.BlockSize = 128;
            aes.KeySize = 256;

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            byte[] keyArr = Convert.FromBase64String(password);
            byte[] KeyArrBytes32Value = new byte[16];
            Array.Copy(keyArr, KeyArrBytes32Value, 16);

            // It must be same as in Java
            byte[] ivArr = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
            byte[] IVBytes16Value = new byte[16];
            Array.Copy(ivArr, IVBytes16Value, 16);

            aes.Key = KeyArrBytes32Value;
            aes.IV = IVBytes16Value;

            ICryptoTransform decrypto = aes.CreateDecryptor();

            byte[] encryptedBytes = Convert.FromBase64CharArray(txtInput.Text.ToCharArray(), 0, txtInput.Text.Length);
            byte[] decryptedData = decrypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            txtInput.Text = Encoding.UTF8.GetString(decryptedData);            
        }       
    }
}
