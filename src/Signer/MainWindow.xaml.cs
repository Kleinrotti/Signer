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
    public partial class MainWindow
    {
        internal FileModel FileModel { get; set; }
        public Hash HashAlgorithm { get; set; } = Hash.SHA256;
        public TimestampType TimestampType { get; set; } = TimestampType.RFC3161;
        public TimestampHash TimestampHashAlgorithm { get; set; } = TimestampHash.SHA256;
        public StoreLocation Store { get; set; } = StoreLocation.CurrentUser;

        private CancellationTokenSource tokenSource = new CancellationTokenSource();

        public MainWindow()
        {
            InitializeComponent();
            FileModel = new FileModel();
            listViewItems.DataContext = FileModel;
            menuItemHash.DataContext = this;
            menuItemTimestampStandard.DataContext = this;
            menuItemTimestampHash.DataContext = this;
            menuItemCertstore.DataContext = this;
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
                t = await Helpers.ScanDirectory(folder, po, progressChanged);

                void progressChanged(int total, int current)
                {
                    progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Maximum = total; }));
                    progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Value = current; }));
                }
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
                Filter = "Script|*.ps1|Binary files|*.exe;*.dll;*.appx|Archive|*.cab|Catalog|*.cat|All |*.*"
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
            var certWindow = new CertWindow(Sign, Store);
            certWindow.Owner = this;
            certWindow.ShowDialog();
        }

        private async void Sign(string certificate, bool useThumbprint, string passphrase)
        {
            var po = new ParallelOptions();
            tokenSource = new CancellationTokenSource();
            po.CancellationToken = tokenSource.Token;
            changeToProgressUI();
            Tuple<int, int, int> count;
            try
            {
                if (useThumbprint)
                    count = await Helpers.SignWithStore(certificate, FileModel.Files, progressChanged, po, checkBoxIncludeSigned.IsChecked.Value,
                        HashAlgorithm, TimestampHashAlgorithm, TimestampType);
                else
                    count = await Helpers.SignWithCert(certificate, passphrase, FileModel.Files, progressChanged, po, checkBoxIncludeSigned.IsChecked.Value,
                        HashAlgorithm, TimestampHashAlgorithm, TimestampType);

                void progressChanged(int total, int current)
                {
                    progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Maximum = total; }));
                    progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Value = current; }));
                }
                System.Windows.MessageBox.Show($"Signed {count.Item1} files\nSkipped {count.Item2} files\nFailed {count.Item3} files");
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(ex.InnerException.Message);
            }
            finally
            {
                changeToScanFinishedUI();
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
            gridProgress.Visibility = Visibility.Visible;
        }

        private void changeToScanFinishedUI()
        {
            buttonCancel.Visibility = Visibility.Collapsed;
            wrapPanelSelect.Visibility = Visibility.Visible;
            gridProgress.Visibility = Visibility.Hidden;
            Mouse.OverrideCursor = System.Windows.Input.Cursors.Arrow;
        }

        private void MenuItemExit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void MenuItemTimestampServer_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new DialogBox("Timestamp server to use");
            dialog.Owner = this;
            dialog.ResponseText = Helpers.TimestampUrl;
            if (dialog.ShowDialog() == true)
            {
                Helpers.TimestampUrl = dialog.ResponseText;
            }
        }

        private void MenuItemAbout_Click(object sender, RoutedEventArgs e)
        {
            var about = new About();
            about.Owner = this;
            about.ShowDialog();
        }

        private void MenuItemPattern_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new DialogBox("Search pattern for folder search");
            dialog.Owner = this;
            string pattern = "";
            foreach (var item in Helpers.FileSearchPattern)
            {
                pattern += item + ",";
            }
            dialog.ResponseText = pattern;
            if (dialog.ShowDialog() == true)
            {
                var tmp = dialog.ResponseText.Split(',');
                Helpers.FileSearchPattern = tmp;
            }
        }
    }
}