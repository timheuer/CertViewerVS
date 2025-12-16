# Cert Viewer for VS

A Visual Studio extension that provides a certificate metadata viewer for PFX, P12, PEM, CRT, DER, and CER files.

## Features

- View certificate details directly within Visual Studio
- Support for multiple certificate formats:
  - **PFX/P12** - Password-protected certificate bundles
  - **PEM** - Base64 encoded certificates
  - **CRT/CER** - Certificate files (DER or PEM encoded)
  - **DER** - Binary encoded certificates
- View certificate chain information
- Password prompt for protected certificate files

## Requirements

- Visual Studio 2022 (version 17.14 or later)
- .NET Framework 4.8.1

## Installation

1. Download the VSIX package
2. Double-click to install, or install via Extensions > Manage Extensions in Visual Studio

## Usage

Open any supported certificate file (`.pfx`, `.p12`, `.pem`, `.crt`, `.cer`, `.der`) in Visual Studio to view its metadata and certificate chain information.

## License

See [LICENSE](LICENSE) for details.