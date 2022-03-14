using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;

namespace Signer
{
    /// <summary>
    /// Interaction logic for CertWindow.xaml
    /// </summary>
    public partial class CertWindow : Window
    {
        private Action<string, string> _callback;
        private string _certificate;

        public CertWindow(Action<string, string> callback)
        {
            InitializeComponent();
            _callback = callback;
        }

        private void buttonSelect_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog();
            dialog.Filter = "Certificate (*.pfx)|*.pfx";
            dialog.Title = "Select Certificate";
            dialog.Multiselect = false;
            if (dialog.ShowDialog() == true)
            {
                textBlockCertificate.Text = Path.GetFileName(dialog.FileName);
                _certificate = dialog.FileName;
            }
        }

        private void buttonApply_Click(object sender, RoutedEventArgs e)
        {
            if (passwordBoxPassphrase.Password == "" || _certificate == null)
                return;
            Close();
            _callback(_certificate, passwordBoxPassphrase.Password);
        }
    }
}