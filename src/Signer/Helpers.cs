using AuthenticodeExaminer;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace Signer
{
    internal static class Helpers
    {
        public static string TimestampUrl { get; set; } = "http://timestamp.digicert.com";

        internal static async Task<List<FileObject>> ScanDirectory(string folder, ParallelOptions parallelOptions, ProgressBar progressBar)
        {
            var fileObjects = new ConcurrentBag<FileObject>();
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
                    return;
                }

                var files = new List<string>();
                files.AddRange(filesExecutables);
                files.AddRange(filesLibraries);
                progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Maximum = files.Count; }));
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Value++; }));
                    fileObjects.Add(InspectFile(file));
                });
            });
            await task;
            return fileObjects.ToList();
        }

        internal static async Task<FileObject> ScanFile(string file)
        {
            return await Task.Run(() =>
            {
                return InspectFile(file);
            });
        }

        private static FileObject InspectFile(string file)
        {
            var obj = new FileObject
            {
                Name = Path.GetFileName(file),
                Path = Path.GetDirectoryName(file)
            };
            obj.Signed = Signed(file, ref obj);
            return obj;
        }

        private static bool Signed(string path, ref FileObject fileObject)
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

        internal static async Task SignWithCert(string certPath, string passphrase, List<FileObject> files, bool includeSigned, ProgressBar progressBar, ParallelOptions parallelOptions)
        {
            var collection = new X509Certificate2Collection();

            //try to import certificate for verification
            collection.Import(certPath, passphrase, X509KeyStorageFlags.PersistKeySet);
            var task = Task.Run(() =>
            {
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    if (includeSigned == false && file.Signed == true)
                    {
                        progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Value++; }));
                        return;
                    }
                    try
                    {
                        SignTool.SignWithCert(file.FullPath, certPath, passphrase, TimestampUrl);
                    }
                    catch (Exception) { throw; }
                    progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Value++; }));
                });
            });
            await task;
        }

        internal static async Task SignWithStore(string thumbprint, List<FileObject> files, bool includeSigned, ProgressBar progressBar, ParallelOptions parallelOptions)
        {
            var task = Task.Run(() =>
            {
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    if (includeSigned == false && file.Signed == true)
                    {
                        progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Value++; }));
                        return;
                    }
                    try
                    {
                        SignTool.SignWithThumbprint(file.FullPath, thumbprint, TimestampUrl);
                    }
                    catch (Exception) { throw; }
                    progressBar.Dispatcher.Invoke(new Action(() => { progressBar.Value++; }));
                });
            });
            await task;
        }

        internal static X509Certificate2 SelectCertFromStore(StoreName store, StoreLocation location, string windowTitle, string windowMsg)
        {
            X509Certificate2 certSelected = null;
            X509Store x509Store = new X509Store(store, location);
            x509Store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection col = x509Store.Certificates;
            X509Certificate2Collection sel = X509Certificate2UI.SelectFromCollection(col, windowTitle, windowMsg, X509SelectionFlag.SingleSelection);

            if (sel.Count > 0)
            {
                X509Certificate2Enumerator en = sel.GetEnumerator();
                en.MoveNext();
                certSelected = en.Current;
            }

            x509Store.Close();

            return certSelected;
        }
    }
}