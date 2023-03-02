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
    public class SigningTest
    {
        private static string _currentDir = Directory.GetParent("..\\..\\..\\..\\..\\").FullName;

        [Theory]
        [InlineData(Hash.SHA1, "SHA1")]
        [InlineData(Hash.SHA256, "SHA256")]
        [InlineData(Hash.SHA384, "SHA384")]
        [InlineData(Hash.SHA512, "SHA512")]
        public async void SignWithStoreHashTest(Hash hash, string expectedHash)
        {
            var currentDir = Directory.GetParent("..\\..\\..\\..\\..\\").FullName;
            var fileList = new List<FileObject>() { await Helpers.ScanFile(currentDir + "\\test_signed_file.ps1") };
            Assert.NotEmpty(fileList);
            var result = await Helpers.SignWithStore("49167e096028b922f326d5c098a19d914cf5d8f0", fileList, null, new ParallelOptions(), true, hash);
            Assert.Equal(new Tuple<int, int, int>(1, 0, 0), result);

            var file = await Helpers.ScanFile(currentDir + "\\test_signed_file.ps1");
            Assert.Equal(expectedHash, file.Signatures.First().DigestAlgorithmName.Name);
        }

        [Theory]
        [InlineData(Hash.SHA1, "SHA1")]
        [InlineData(Hash.SHA256, "SHA256")]
        [InlineData(Hash.SHA384, "SHA384")]
        [InlineData(Hash.SHA512, "SHA512")]
        public async void SignWithFileHashTest(Hash hash, string expectedHash)
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
        public async void SignWithTimestampHashTest(TimestampHash timestampHash, string expectedHash)
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
        public async void SignWithTimestampTypeTest(TimestampType timestampType, SignatureKind expectedType)
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
    }
}