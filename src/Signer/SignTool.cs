using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Signer
{
    internal static class SignTool
    {
        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_SUBJECT_INFO
        {
            public uint cbSize;
            public IntPtr pdwIndex;
            public uint dwSubjectChoice;
            public SubjectChoiceUnion Union1;

            [StructLayout(LayoutKind.Explicit)]
            internal struct SubjectChoiceUnion
            {
                [FieldOffsetAttribute(0)]
                public IntPtr pSignerFileInfo;

                [FieldOffsetAttribute(0)]
                public IntPtr pSignerBlobInfo;
            };
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_CERT
        {
            public uint cbSize;
            public uint dwCertChoice;
            public SignerCertUnion Union1;

            [StructLayout(LayoutKind.Explicit)]
            internal struct SignerCertUnion
            {
                [FieldOffset(0)]
                public IntPtr pwszSpcFile;

                [FieldOffset(0)]
                public IntPtr pCertStoreInfo;

                [FieldOffset(0)]
                public IntPtr pSpcChainInfo;
            };

            public IntPtr hwnd;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_SIGNATURE_INFO
        {
            public uint cbSize;
            public uint algidHash; // ALG_ID
            public uint dwAttrChoice;
            public IntPtr pAttrAuthCode;
            public IntPtr psAuthenticated; // PCRYPT_ATTRIBUTES
            public IntPtr psUnauthenticated; // PCRYPT_ATTRIBUTES
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_FILE_INFO
        {
            public uint cbSize;
            public IntPtr pwszFileName;
            public IntPtr hFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_CERT_STORE_INFO
        {
            public uint cbSize;
            public IntPtr pSigningCert; // CERT_CONTEXT
            public uint dwCertPolicy;
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_CONTEXT
        {
            public uint cbSize;
            public uint cbBlob;
            public IntPtr pbBlob;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SIGNER_PROVIDER_INFO
        {
            public uint cbSize;
            public IntPtr pwszProviderName;
            public uint dwProviderType;
            public uint dwKeySpec;
            public uint dwPvkChoice;
            public SignerProviderUnion Union1;

            [StructLayout(LayoutKind.Explicit)]
            internal struct SignerProviderUnion
            {
                [FieldOffset(0)]
                public IntPtr pwszPvkFileName;

                [FieldOffset(0)]
                public IntPtr pwszKeyContainer;
            };
        }

        #endregion Structures

        #region Imports

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSignEx(
            uint dwFlags,               // DWORD
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            IntPtr pSignerCert,         // SIGNER_CERT
            IntPtr pSignatureInfo,      // SIGNER_SIGNATURE_INFO
            IntPtr pProviderInfo,       // SIGNER_PROVIDER_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData,            // LPVOID
            out SIGNER_CONTEXT ppSignerContext  // SIGNER_CONTEXT
            );

        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx2(
            uint dwFlags,               // DWORD
            IntPtr pSubjectInfo,        // SIGNER_SUBJECT_INFO
            string pwszHttpTimeStamp,   // LPCWSTR
            IntPtr dwAlgId,               // ALG_ID
            IntPtr psRequest,           // PCRYPT_ATTRIBUTES
            IntPtr pSipData,            // LPVOID
            out SIGNER_CONTEXT ppSignerContext  // SIGNER_CONTEXT
            );

        [DllImport("Crypt32.dll", EntryPoint = "CertCreateCertificateContext", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = false, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr CertCreateCertificateContext(
            int dwCertEncodingType,
            byte[] pbCertEncoded,
            int cbCertEncoded);

        #endregion Imports

        #region public methods

        /// <summary>
        /// Call SignerSignEx and SignerTimeStampEx2 for a given .pfx
        /// </summary>
        /// <param name="appPath"></param>
        /// <param name="certPath"></param>
        /// <param name="certPassword"></param>
        /// <param name="timestampUrl"></param>
        /// <param name="hash"></param>
        /// <param name="timestampHash"></param>
        /// <param name="timestampType"></param>
        public static void SignWithCert(string appPath, string certPath, string certPassword,
            string timestampUrl, Hash hash, TimestampHash timestampHash, TimestampType timestampType)
        {
            Sign(new X509Certificate2(certPath, certPassword), appPath, hash, timestampUrl, timestampHash, timestampType);
        }

        /// <summary>
        /// Call SignerSignEx and SignerTimeStampEx2 for a given thumbprint.
        /// </summary>
        /// <param name="appPath"></param>
        /// <param name="thumbprint"></param>
        /// <param name="timestampUrl"></param>
        /// <param name="hash"></param>
        /// <param name="timestampHash"></param>
        /// <param name="timestampType"></param>
        public static void SignWithThumbprint(string appPath, string thumbprint, string timestampUrl,
            Hash hash, TimestampHash timestampHash, TimestampType timestampType)
        {
            Sign(FindCertByThumbprint(thumbprint), appPath, hash, timestampUrl, timestampHash, timestampType);
        }

        #endregion public methods

        #region private methods

        private static IntPtr CreateSignerSubjectInfo(string pathToAssembly)
        {
            SIGNER_SUBJECT_INFO info = new SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_SUBJECT_INFO)),
                pdwIndex = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint)))
            };
            var index = 0;
            Marshal.StructureToPtr(index, info.pdwIndex, false);

            info.dwSubjectChoice = 0x1; //SIGNER_SUBJECT_FILE
            IntPtr assemblyFilePtr = Marshal.StringToHGlobalUni(pathToAssembly);

            SIGNER_FILE_INFO fileInfo = new SIGNER_FILE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_FILE_INFO)),
                pwszFileName = assemblyFilePtr,
                hFile = IntPtr.Zero
            };

            info.Union1 = new SIGNER_SUBJECT_INFO.SubjectChoiceUnion
            {
                pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SIGNER_FILE_INFO)))
            };

            Marshal.StructureToPtr(fileInfo, info.Union1.pSignerFileInfo, false);

            IntPtr pSubjectInfo = Marshal.AllocHGlobal(Marshal.SizeOf(info));
            Marshal.StructureToPtr(info, pSubjectInfo, false);

            return pSubjectInfo;
        }

        private static X509Certificate2 FindCertByThumbprint(string thumbprint)
        {
            try
            {
                // Remove spaces convert to upper.  Windows 10 (preview) and Windows 8 will not return a cert
                // unless it is a perfect match with no spaces and all uppercase characters.
                string thumbprintFixed = thumbprint.Replace(" ", string.Empty).ToUpperInvariant();

                // Check common store locations for the corresponding code-signing cert.
                X509Store[] stores = new X509Store[4] { new X509Store(StoreName.My, StoreLocation.CurrentUser),
                                                        new X509Store(StoreName.My, StoreLocation.LocalMachine),
                                                        new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser),
                                                        new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine) };

                foreach (X509Store store in stores)
                {
                    store.Open(OpenFlags.ReadOnly);

                    // Find the cert!
                    X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprintFixed, false);

                    store.Close();

                    // If we didn't find the cert, try the next store.
                    if (certs.Count < 1)
                    {
                        continue;
                    }

                    // Return the cert (first one if there is more than one identical cert in the collection).
                    return certs[0];
                }

                // No cert was found.  Return null.
                throw new Exception(string.Format(@"A certificate matching the thumbprint: ""{0}"" could not be found.  Make sure that a valid certificate matching the provided thumbprint is installed.", thumbprint));
            }
            catch (Exception e)
            {
                throw new Exception(string.Format("{0}", e.Message));
            }
        }

        private static IntPtr CreateSignerCert(X509Certificate2 cert)
        {
            SIGNER_CERT signerCert = new SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT)),
                dwCertChoice = 0x2,
                Union1 = new SIGNER_CERT.SignerCertUnion
                {
                    pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)))
                },
                hwnd = IntPtr.Zero
            };

            const int X509_ASN_ENCODING = 0x00000001;
            const int PKCS_7_ASN_ENCODING = 0x00010000;

            IntPtr pCertContext = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cert.GetRawCertData(),
                cert.GetRawCertData().Length);

            SIGNER_CERT_STORE_INFO certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_CERT_STORE_INFO)),
                pSigningCert = pCertContext,
                dwCertPolicy = 0x2, // SIGNER_CERT_POLICY_CHAIN
                hCertStore = IntPtr.Zero
            };

            Marshal.StructureToPtr(certStoreInfo, signerCert.Union1.pCertStoreInfo, false);

            IntPtr pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf(signerCert));
            Marshal.StructureToPtr(signerCert, pSignerCert, false);

            return pSignerCert;
        }

        private static IntPtr CreateSignerSignatureInfo(Hash hash)
        {
            SIGNER_SIGNATURE_INFO signatureInfo = new SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_SIGNATURE_INFO)),
                algidHash = (uint)hash, // Hash
                dwAttrChoice = 0x0, // SIGNER_NO_ATTR
                pAttrAuthCode = IntPtr.Zero,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero
            };

            IntPtr pSignatureInfo = Marshal.AllocHGlobal(Marshal.SizeOf(signatureInfo));
            Marshal.StructureToPtr(signatureInfo, pSignatureInfo, false);

            return pSignatureInfo;
        }

        private static IntPtr GetProviderInfo(X509Certificate2 cert)
        {
            if (cert == null || !cert.HasPrivateKey)
            {
                return IntPtr.Zero;
            }

            ICspAsymmetricAlgorithm key = (ICspAsymmetricAlgorithm)cert.PrivateKey;
            const int PVK_TYPE_KEYCONTAINER = 2;

            if (key == null)
            {
                return IntPtr.Zero;
            }

            SIGNER_PROVIDER_INFO providerInfo = new SIGNER_PROVIDER_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(SIGNER_PROVIDER_INFO)),
                pwszProviderName = Marshal.StringToHGlobalUni(key.CspKeyContainerInfo.ProviderName),
                dwProviderType = (uint)key.CspKeyContainerInfo.ProviderType,
                dwPvkChoice = PVK_TYPE_KEYCONTAINER,
                Union1 = new SIGNER_PROVIDER_INFO.SignerProviderUnion
                {
                    pwszKeyContainer = Marshal.StringToHGlobalUni(key.CspKeyContainerInfo.KeyContainerName)
                },
            };

            IntPtr pProviderInfo = Marshal.AllocHGlobal(Marshal.SizeOf(providerInfo));
            Marshal.StructureToPtr(providerInfo, pProviderInfo, false);

            return pProviderInfo;
        }

        private static void Sign(X509Certificate2 cert, string appPath, Hash hash, string timestampUrl, TimestampHash timestampHash, TimestampType timestampType)
        {
            IntPtr pSignerCert = IntPtr.Zero;
            IntPtr pSubjectInfo = IntPtr.Zero;
            IntPtr pSignatureInfo = IntPtr.Zero;
            IntPtr pProviderInfo = IntPtr.Zero;

            try
            {
                pSignerCert = CreateSignerCert(cert);
                pSubjectInfo = CreateSignerSubjectInfo(appPath);
                pSignatureInfo = CreateSignerSignatureInfo(hash);
                pProviderInfo = GetProviderInfo(cert);

                SIGNER_CONTEXT signerContext;
                SignCode(0x0, pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, out signerContext);

                // Only attempt to timestamp if we've got a timestampUrl.
                if (!string.IsNullOrEmpty(timestampUrl))
                {
                    TimeStampSignedCode(pSubjectInfo, timestampUrl, out signerContext, timestampHash.GetEnumMemberValue(), timestampType);
                }
            }
            catch (CryptographicException ce)
            {
                string exception = string.Format(@"An error occurred while attempting to load the signing certificate.  {0}", ce.Message);
                throw new CryptographicException(exception);
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (pSignerCert != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pSignerCert, typeof(SIGNER_CERT));
                }
                if (pSubjectInfo != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pSubjectInfo, typeof(SIGNER_SUBJECT_INFO));
                }
                if (pSignatureInfo != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pSignatureInfo, typeof(SIGNER_SIGNATURE_INFO));
                }
                if (pProviderInfo != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(pProviderInfo, typeof(SIGNER_PROVIDER_INFO));
                }
            }
        }

        // Use SignerSignEx
        private static void SignCode(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert,
            IntPtr pSignatureInfo, IntPtr pProviderInfo, out SIGNER_CONTEXT signerContext)
        {
            int hResult = SignerSignEx(
                dwFlags,
                pSubjectInfo,
                pSignerCert,
                pSignatureInfo,
                pProviderInfo,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                out signerContext
                );

            if (hResult != 0)
            {
                // See if we can get anything useful.  Jury's still out on this one.
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }

        // Use SignerTimeStampEx2
        private static void TimeStampSignedCode(IntPtr pSubjectInfo, string timestampUrl, out SIGNER_CONTEXT signerContext, string timestampHashOid, TimestampType dwFlags)
        {
            int hResult = SignerTimeStampEx2(
                (uint)dwFlags,
                pSubjectInfo,
                timestampUrl,
                Marshal.StringToHGlobalAnsi(timestampHashOid),
                IntPtr.Zero,
                IntPtr.Zero,
                out signerContext
                );

            if (hResult != 0)
            {
                // We can't get anything useful from GetHRForLastWin32Error, so let's throw our own.
                //Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                throw new Exception(string.Format(@"""{0}"" could not be used at this time.  If necessary, check the timestampUrl, internet connection, and try again.", timestampUrl));
            }
        }

        #endregion private methods
    }
}