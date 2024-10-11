using AuthenticodeExaminer;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Xunit;

namespace Signer.Tests
{
    public class SigningTest : IDisposable
    {
        private static string _currentDir = Directory.GetParent("..\\..\\..\\..\\..\\").FullName;
        public SigningTest()
        {
            File.WriteAllText(_currentDir + "\\test_signed_file.ps1", "Test");
        }

        [Theory]
        [InlineData(Hash.SHA1, "SHA1")]
        [InlineData(Hash.SHA256, "SHA256")]
        [InlineData(Hash.SHA384, "SHA384")]
        [InlineData(Hash.SHA512, "SHA512")]
        public async Task SignWithStoreHashTest(Hash hash, string expectedHash)
        {
            var fileList = new List<FileObject>() { await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1") };
            Assert.NotEmpty(fileList);
            var result = await Helpers.SignWithStore("7174e534f146c1e21a2d2171fca803511c9a0481", fileList, null, new ParallelOptions(), true, hash);
            Assert.Equal(new Tuple<int, int, int>(1, 0, 0), result);

            var file = await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1");
            Assert.Equal(expectedHash, file.Signatures.First().DigestAlgorithmName.Name);
        }

        [Theory]
        [InlineData(Hash.SHA1, "SHA1")]
        [InlineData(Hash.SHA256, "SHA256")]
        [InlineData(Hash.SHA384, "SHA384")]
        [InlineData(Hash.SHA512, "SHA512")]
        public async Task SignWithFileHashTest(Hash hash, string expectedHash)
        {
            var fileList = await GetFile();
            var result = await Helpers.SignWithFile(_currentDir + "\\Signer_TemporaryKey.pfx", "12345", fileList, null, new ParallelOptions(), true, hash);
            Assert.Equal(new Tuple<int, int, int>(1, 0, 0), result);

            var file = await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1");
            Assert.Equal(expectedHash, file.Signatures.First().DigestAlgorithmName.Name);
        }

        [Theory]
        [InlineData(TimestampHash.SHA256, "SHA256")]
        [InlineData(TimestampHash.SHA384, "SHA384")]
        [InlineData(TimestampHash.SHA512, "SHA512")]
        public async Task SignWithTimestampHashTest(TimestampHash timestampHash, string expectedHash)
        {
            var fileList = await GetFile();
            var result = await Helpers.SignWithFile(_currentDir + "\\Signer_TemporaryKey.pfx", "12345", fileList, null, new ParallelOptions(), true, Hash.SHA256, timestampHash);
            Assert.Equal(new Tuple<int, int, int>(1, 0, 0), result);

            var file = await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1");
            Assert.Equal(expectedHash, file.Signatures.First().TimestampSignatures.First().DigestAlgorithmName.Name);
        }

        [Theory]
        [InlineData(TimestampType.Authenticode, SignatureKind.AuthenticodeTimestamp)]
        [InlineData(TimestampType.RFC3161, SignatureKind.Rfc3161Timestamp)]
        public async Task SignWithTimestampTypeTest(TimestampType timestampType, SignatureKind expectedType)
        {
            var fileList = await GetFile();
            var result = await Helpers.SignWithFile(_currentDir + "\\Signer_TemporaryKey.pfx", "12345", fileList, null, new ParallelOptions(), true, Hash.SHA256, TimestampHash.SHA256, timestampType);
            Assert.Equal(new Tuple<int, int, int>(1, 0, 0), result);

            var file = await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1");

            var sig = file.Signatures.First().TimestampSignatures.First();
            var value = typeof(TimestampSignature).GetField("_cmsSignature", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(sig) as ICmsSignature;

            Assert.Equal(expectedType, value.Kind);
        }

        private async Task<IEnumerable<FileObject>> GetFile()
        {
            var fileList = new List<FileObject>() { await Helpers.ScanFile(_currentDir + "\\test_signed_file.ps1") };
            Assert.NotEmpty(fileList);
            return fileList;
        }

        public void Dispose()
        {
            File.Delete(_currentDir + "\\test_signed_file.ps1");
        }
    }
}