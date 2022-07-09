using AuthenticodeExaminer;
using System.Collections.Generic;

namespace Signer
{
    internal class FileObject
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public bool Trusted { get; set; }

        public string FullPath
        {
            get
            {
                return Path + "\\" + Name;
            }
        }

        public bool Signed { get; set; }
        public IEnumerable<AuthenticodeSignature> Signatures { get; set; }
    }
}