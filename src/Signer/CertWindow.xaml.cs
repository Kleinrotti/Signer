﻿using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Media;

namespace Signer
{
    /// <summary>
    /// Interaction logic for CertWindow.xaml
    /// </summary>
    public partial class CertWindow
    {
        private Action<string, bool, string> _callback;
        private string _certificate;
        private bool _useThumbprint;
        private StoreLocation _store;

        public CertWindow(Action<string, bool, string> callback, StoreLocation storeLocation)
        {
            InitializeComponent();
            _callback = callback;
            _store = storeLocation;
        }

        private void buttonSelect_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Certificate (*.pfx)|*.pfx",
                Title = "Select Certificate",
                Multiselect = false
            };
            if (dialog.ShowDialog() == true)
            {
                textBlockCertificate.Text = Path.GetFileName(dialog.FileName);
                _certificate = dialog.FileName;
                stackPanelPassphrase.Visibility = Visibility.Visible;
                textBlockCertificateStore.Foreground = Brushes.Black;
                textBlockCertificate.Foreground = Brushes.Green;
                _useThumbprint = false;
                buttonApply.IsEnabled = true;
            }
        }

        private void buttonSelectFromStore_Click(object sender, RoutedEventArgs e)
        {
            var t = Helpers.SelectCertFromStore(StoreName.My,
                _store, "Select certificate", "");

            if (t == null)
                return;
            textBlockCertificateStore.Text = t.Subject;
            stackPanelPassphrase.Visibility = Visibility.Hidden;
            textBlockCertificateStore.Foreground = Brushes.Green;
            textBlockCertificate.Foreground = Brushes.Black;
            buttonApply.IsEnabled = true;
            _useThumbprint = true;
            _certificate = t.Thumbprint;
        }

        private void buttonApply_Click(object sender, RoutedEventArgs e)
        {
            if (passwordBoxPassphrase.Password == "" && _useThumbprint == false || _certificate == null)
                return;
            Close();
            if (_useThumbprint)
                _callback(_certificate, true, "");
            else
                _callback(_certificate, false, passwordBoxPassphrase.Password);
        }
    }
}