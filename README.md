# Signer

Utility to bulk sign files with a certificate (pfx) or with a certificate which is in the certificate store.

![alt text](https://github.com/Kleinrotti/Signer/blob/main/img.JPG)

## Features

- High performance folder scan for bulk signing in large projects
- Adjustable search pattern to include only specific files in folder scan
- Inspect signature of scanned files
- Support for SHA1, SHA256, SHA384, SHA512
- Set timestamp server
- Choose between Authenticode or RFC3161 timestamping
- Certificate can be PFX or in Windows Certificate Store

## Supported file types

- .CAB, PE formats (.EXE, .DLL, etc) , .CAT, .MSI,.OCX, .PS1, .PSM1, .PSD1, .PS1XML, .PSC1

## Requirements

- Windows 8/Server 2012 or higher
- .NET 6 runtime


### Possible new features in the future

- Support for other files like .pdf or .jar
