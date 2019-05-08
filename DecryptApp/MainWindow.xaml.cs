using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;

namespace DecryptApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        X509Certificate2 cert;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnOpenPrivatekeyFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog();
            dialog.DefaultExt = "*.*";
            dialog.Filter = "All Files|*.*";
            dialog.Multiselect = false;

            if (dialog.ShowDialog() == true)
            {
                var fileName = dialog.FileName;
                
            }
        }

        private void BtnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            var rsa = (RSACryptoServiceProvider)cert.PrivateKey;
            var decryptedData = rsa.Decrypt(Convert.FromBase64String(txtInput.Text), false);
            txtInput.Text = Encoding.UTF8.GetString(decryptedData);
        }
    }
}
