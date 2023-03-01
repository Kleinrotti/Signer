using AuthenticodeExaminer;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Signer
{
    internal static class Helpers
    {
        /// <summary>
        /// Timestamp url/server
        /// </summary>
        public static string TimestampUrl { get; set; } = "http://timestamp.digicert.com";

        private static IEnumerable<string> _pattern = new List<string> { "exe", "dll", "ps1", "cat", "cab", "appx", "msi", "msix", "sys" };

        /// <summary>
        /// Get or set the current file search pattern for folder search.
        /// </summary>
        public static IEnumerable<string> FileSearchPattern
        {
            get
            {
                //filter out empty entries
                return _pattern.Where(x => !x.Equals(""));
            }
            set { _pattern = value; }
        }

        /// <summary>
        /// Scan a directory and sub directories for files which support signing.
        /// </summary>
        /// <param name="folder">Folder path</param>
        /// <param name="parallelOptions"><see cref="ParallelOptions"/> set your cancellation token here.</param>
        /// <param name="progressCallback">Callback function to obtain the current process progress. Set to <see cref="null"/> if you don't want a callback.</param>
        /// <returns></returns>
        public static async Task<List<FileObject>> ScanDirectory(string folder, ParallelOptions parallelOptions, Action<int, int> progressCallback)
        {
            var fileObjects = new ConcurrentBag<FileObject>();
            var task = Task.Run(() =>
            {
                IEnumerable<string> files = null;
                try
                {
                    files = SearchFiles(folder, FileSearchPattern);
                }
                catch (UnauthorizedAccessException ex)
                {
                    System.Windows.MessageBox.Show(ex.Message);
                    return;
                }
                var fileCount = files.Count();
                var progressCount = 0;
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    fileObjects.Add(InspectFile(file));
                    if (progressCallback != null)
                        progressCallback(fileCount, progressCount++);
                });
            });
            await task;
            return fileObjects.ToList();
        }

        /// <summary>
        /// Scan a single file if it's signed.
        /// </summary>
        /// <param name="file">Path to your file.</param>
        /// <returns>Return the <see cref="FileObject"/></returns>
        public static async Task<FileObject> ScanFile(string file)
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

        private static IEnumerable<string> SearchFiles(string path, IEnumerable<string> extensions)
        {
            return
                extensions.Select(x => "*." + x) // turn into globs
                .SelectMany(x =>
                    Directory.EnumerateFiles(path, x, SearchOption.AllDirectories)
                    );
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

        /// <summary>
        /// Sign a list of files with a certificate file.
        /// </summary>
        /// <param name="certPath">Full path to the certificate.</param>
        /// <param name="passphrase">Passphrase of the certificate.</param>
        /// <param name="files"></param>
        /// <param name="progressCallback">Callback function to obtain the current process progress. Set to <see cref="null"/> if you don't want a callback.</param>
        /// <param name="parallelOptions"><see cref="ParallelOptions"/> set your cancellation token here.</param>
        /// <param name="includeSigned">Deteremine wether you want to override a signature of an already signed file.</param>
        /// <param name="hash">Hash algorithm to use.</param>
        /// <param name="timestampHash">Hash algorithm to use for the timestamp signiture. Keep in mind, not all servers support all signature types.</param>
        /// <param name="timestampType"></param>
        /// <returns>Returns a <see cref="Tuple"/> which contains successfull files, skipped files and failed files.</returns>
        public static async Task<Tuple<int, int, int>> SignWithFile(string certPath, string passphrase, List<FileObject> files, Action<int, int> progressCallback, ParallelOptions parallelOptions, bool includeSigned = false, Hash hash = Hash.SHA256,
            TimestampHash timestampHash = TimestampHash.SHA256, TimestampType timestampType = TimestampType.RFC3161)
        {
            int count = 0;
            int success = 0;
            int skipped = 0;
            int failed = 0;

            var task = Task.Run(() =>
            {
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    if (includeSigned == false && file.Signed == true)
                    {
                        skipped++;
                        return;
                    }
                    try
                    {
                        SignTool.SignWithCert(file.FullPath, certPath, passphrase, TimestampUrl, hash, timestampHash, timestampType);
                        success++;
                    }
                    catch (Exception) { failed++; }
                    finally
                    {
                        if (progressCallback != null)
                            progressCallback(files.Count, count++);
                    }
                });
            });
            await task;
            return new Tuple<int, int, int>(success, skipped, failed);
        }

        /// <summary>
        /// Sign a list of files with a certificate which is in your operating system certificate store.
        /// </summary>
        /// <param name="thumbprint">Thumbprint from your certificate in your operating system store.</param>
        /// <param name="files"></param>
        /// <param name="progressCallback">Callback function to obtain the current process progress. Set to <see cref="null"/> if you don't want a callback.</param>
        /// <param name="parallelOptions"><see cref="ParallelOptions"/> set your cancellation token here.</param>
        /// <param name="includeSigned">Deteremine wether you want to override a signature of an already signed file.</param>
        /// <param name="hash">Hash algorithm to use.</param>
        /// <param name="timestampHash">Hash algorithm to use for the timestamp signiture. Keep in mind, not all servers support all signature types.</param>
        /// <param name="timestampType"></param>
        /// <returns></returns>
        public static async Task<Tuple<int, int, int>> SignWithStore(string thumbprint, List<FileObject> files, Action<int, int> progressCallback, ParallelOptions parallelOptions, bool includeSigned = false, Hash hash = Hash.SHA256,
            TimestampHash timestampHash = TimestampHash.SHA256, TimestampType timestampType = TimestampType.RFC3161)
        {
            int count = 0;
            int success = 0;
            int skipped = 0;
            int failed = 0;

            var task = Task.Run(() =>
            {
                Parallel.ForEach(files, parallelOptions, file =>
                {
                    if (includeSigned == false && file.Signed == true)
                    {
                        skipped++;
                        return;
                    }
                    try
                    {
                        SignTool.SignWithThumbprint(file.FullPath, thumbprint, TimestampUrl, hash, timestampHash, timestampType);
                        success++;
                    }
                    catch (Exception) { failed++; }
                    finally
                    {
                        if (progressCallback != null)
                            progressCallback(files.Count, count++);
                    }
                });
            });
            await task;
            return new Tuple<int, int, int>(success, skipped, failed);
        }

        /// <summary>
        /// Opens the Windows dialog window to select a certificate from user or operating system store.
        /// </summary>
        /// <param name="store">Display certificates from this store.</param>
        /// <param name="location">Display certificates from this store location.</param>
        /// <param name="windowTitle">Title of the opening window.</param>
        /// <param name="windowMsg">Message of the opening window.</param>
        /// <returns></returns>
        public static X509Certificate2 SelectCertFromStore(StoreName store, StoreLocation location, string windowTitle = "", string windowMsg = "")
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