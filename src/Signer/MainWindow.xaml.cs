using AuthenticodeExaminer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
        private const string _timestampUrl = "http://timestamp.digicert.com";

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
            FileModel.Files = new List<FileObject>();
            Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
            buttonSelectFolder.Visibility = Visibility.Collapsed;
            buttonStartSign.Visibility = Visibility.Collapsed;
            checkBoxIncludeSigned.Visibility = Visibility.Collapsed;
            buttonCancel.Visibility = Visibility.Visible;
            progressBarSigned.Value = 0;
            progressBarSigned.Visibility = Visibility.Visible;
            var folder = dialog.SelectedPath;
            tokenSource = new CancellationTokenSource();
            var ct = tokenSource.Token;
            List<FileObject> t;
            try
            {
                t = await ScanDirectory(folder, ct);
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
            }
            catch (OperationCanceledException)
            {
                return;
            }
            finally
            {
                buttonCancel.Visibility = Visibility.Collapsed;
                buttonSelectFolder.Visibility = Visibility.Visible;
                progressBarSigned.Visibility = Visibility.Hidden;
                Mouse.OverrideCursor = System.Windows.Input.Cursors.Arrow;
            };
            FileModel.Files = t;
        }

        private async Task<List<FileObject>> ScanDirectory(string folder, CancellationToken cancellationToken)
        {
            var fileObjects = new List<FileObject>();
            var task = Task.Run(() =>
            {
                string[] filesExecutables = null;
                string[] filesLibraries = null;
                try
                {
                    filesExecutables = Directory.GetFiles(folder, "*.exe", SearchOption.AllDirectories);
                    filesLibraries = Directory.GetFiles(folder, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException ex)
                {
                    System.Windows.MessageBox.Show(ex.Message);
                }

                var files = new List<string>();
                files.AddRange(filesExecutables);
                files.AddRange(filesLibraries);
                progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Maximum = files.Count; }));
                foreach (var file in files)
                {

                    progressBarSigned.Dispatcher.Invoke(new Action(() => { progressBarSigned.Value++; }));
                    if (cancellationToken.IsCancellationRequested)
                        cancellationToken.ThrowIfCancellationRequested();
                    var obj = new FileObject();
                    obj.Name = Path.GetFileName(file);
                    obj.Path = Path.GetDirectoryName(file);
                    obj.Signed = Signed(file, ref obj);
                    fileObjects.Add(obj);
                }
            });
            await task;
            return fileObjects;
        }

        private bool Signed(string path, ref FileObject fileObject)
        {
            var inspector = new FileInspector(path);
            var result = inspector.Validate();
            if (result == SignatureCheckResult.Valid || result == SignatureCheckResult.UntrustedRoot)
            {
                fileObject.Signatures = inspector.GetSignatures();
                if (result == SignatureCheckResult.UntrustedRoot)
                    fileObject.Trusted = false;
                else
                    fileObject.Trusted = true;
                return true;
            }
            else
                return false;
        }

        private void buttonCancel_Click(object sender, RoutedEventArgs e)
        {
            tokenSource.Cancel();
        }

        private void buttonStartSign_Click(object sender, RoutedEventArgs e)
        {
            var certWindow = new CertWindow(Sign);
            certWindow.Owner = this;
            certWindow.ShowDialog();
        }

        private async void Sign(string path, string passphrase)
        {
            var collection = new X509Certificate2Collection();
            try
            {
                panelMain.IsEnabled = false;
                progressBarSigned.Maximum = FileModel.Files.Count;
                progressBarSigned.Value = 0;
                progressBarSigned.Visibility = Visibility.Visible;
                //try to import certificate for verification
                collection.Import(path, passphrase, X509KeyStorageFlags.PersistKeySet);
                Mouse.OverrideCursor = System.Windows.Input.Cursors.Wait;
                foreach (var v in FileModel.Files)
                {
                    progressBarSigned.Value++;
                    if (checkBoxIncludeSigned.IsChecked == false && v.Signed == true)
                        continue;
                    await Task.Run(() => SignTool.SignWithCert(v.FullPath, path, passphrase, _timestampUrl));
                }
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
                panelMain.IsEnabled = true;
            }
        }
    }
}