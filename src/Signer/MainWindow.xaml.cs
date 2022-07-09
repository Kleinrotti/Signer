using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Forms;
using System.Windows.Input;

namespace Signer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        internal FileModel FileModel { get; set; }
        private CancellationTokenSource tokenSource = new CancellationTokenSource();
        private StoreLocation _storeLocation = StoreLocation.CurrentUser;

        public MainWindow()
        {
            InitializeComponent();
            FileModel = new FileModel();
            listViewItems.DataContext = FileModel;
        }

        private async void buttonSelectFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new FolderBrowserDialog();

            if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;
            var folder = dialog.SelectedPath;
            FileModel.Files = new List<FileObject>();
            var po = new ParallelOptions();
            tokenSource = new CancellationTokenSource();
            po.CancellationToken = tokenSource.Token;
            var t = new List<FileObject>();
            changeToProgressUI();
            try
            {
                t = await Helpers.ScanDirectory(folder, po, progressBarSigned);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            finally
            {
                if (t.Count > 0)
                {
                    buttonStartSign.Visibility = Visibility.Visible;
                    checkBoxIncludeSigned.Visibility = Visibility.Visible;
                    listViewItems.IsEnabled = true;
                }
                else
                {
                    buttonStartSign.Visibility = Visibility.Hidden;
                    checkBoxIncludeSigned.Visibility = Visibility.Hidden;
                    listViewItems.IsEnabled = false;
                }
                changeToScanFinishedUI();
                tokenSource.Dispose();
            };
            FileModel.Files = t;
        }

        private async void buttonSelectFile_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "Select a file to sign.",
                Filter = "Script files (*.bat;*.ps1)|*.bat;*.ps1|Binary files (*.exe;*.dll)|*.exe;*.dll"
            };
            if (openFileDialog.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                return;
            var file = openFileDialog.FileName;
            changeToProgressUI();
            var f = await Helpers.ScanFile(file);
            FileModel.Files = new List<FileObject> { f };
            progressBarSigned.Value = 1;
            changeToScanFinishedUI();
            buttonStartSign.Visibility = Visibility.Visible;
            checkBoxIncludeSigned.Visibility = Visibility.Visible;
            listViewItems.IsEnabled = true;
        }

        private void buttonCancel_Click(object sender, RoutedEventArgs e)
        {
            tokenSource.Cancel();
            progressBarSigned.Value = 0;
        }

        private void buttonStartSign_Click(object sender, RoutedEventArgs e)
        {
            var certWindow = new CertWindow(Sign, _storeLocation);
            certWindow.Owner = this;
            certWindow.ShowDialog();
        }

        private async void Sign(string certificate, bool useThumbprint, string passphrase)
        {
            var po = new ParallelOptions();
            tokenSource = new CancellationTokenSource();
            po.CancellationToken = tokenSource.Token;
            changeToProgressUI();
            try
            {
                if (useThumbprint)
                    await Helpers.SignWithStore(certificate, FileModel.Files, checkBoxIncludeSigned.IsChecked.Value, progressBarSigned, po);
                else
                    await Helpers.SignWithCert(certificate, passphrase, FileModel.Files, checkBoxIncludeSigned.IsChecked.Value, progressBarSigned, po);
                System.Windows.MessageBox.Show($"Finished {FileModel.Files.Count} files.");
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(ex.Message);
            }
            finally
            {
                Mouse.OverrideCursor = System.Windows.Input.Cursors.Arrow;
                progressBarSigned.Visibility = Visibility.Hidden;
                buttonCancel.Visibility = Visibility.Collapsed;
                wrapPanelSelect.Visibility = Visibility.Visible;
                checkBoxIncludeSigned.Visibility = Visibility.Collapsed;
                buttonStartSign.Visibility = Visibility.Collapsed;
                tokenSource.Dispose();
                FileModel.Files = new List<FileObject>();
                progressBarSigned.Value = 0;
            }
        }

        private void changeToProgressUI()
        {
            Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            wrapPanelSelect.Visibility = Visibility.Collapsed;
            buttonStartSign.Visibility = Visibility.Collapsed;
            checkBoxIncludeSigned.Visibility = Visibility.Collapsed;
            buttonCancel.Visibility = Visibility.Visible;
            progressBarSigned.Value = 0;
            progressBarSigned.Visibility = Visibility.Visible;
        }

        private void changeToScanFinishedUI()
        {
            buttonCancel.Visibility = Visibility.Collapsed;
            wrapPanelSelect.Visibility = Visibility.Visible;
            progressBarSigned.Visibility = Visibility.Hidden;
            Mouse.OverrideCursor = System.Windows.Input.Cursors.Arrow;
        }

        private void MenuItemExit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void RadioButtonUser_Click(object sender, RoutedEventArgs e)
        {
            _storeLocation = StoreLocation.CurrentUser;
        }

        private void RadioButtonComputer_Click_1(object sender, RoutedEventArgs e)
        {
            _storeLocation = StoreLocation.LocalMachine;
        }

        private void MenuItemTimestamp_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new DialogBox("Timestamp server to use");
            dialog.ResponseText = Helpers.TimestampUrl;
            if (dialog.ShowDialog() == true)
            {
                Helpers.TimestampUrl = dialog.ResponseText;
            }
        }
    }
}