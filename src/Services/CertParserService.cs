using CertViewerVS.Models;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace CertViewerVS.Services;

/// <summary>
/// Service for parsing certificate files (PFX, P12, PEM, CRT, DER, CER).
/// </summary>
public class CertParserService
{
    /// <summary>
    /// Supported certificate file extensions.
    /// </summary>
    public static readonly string[] SupportedExtensions = { ".pfx", ".p12", ".pem", ".crt", ".der", ".cer" };

    /// <summary>
    /// Parses any supported certificate file and extracts certificate information.
    /// </summary>
    /// <param name="filePath">Path to the certificate file.</param>
    /// <param name="password">Password for the file (only used for PFX/P12).</param>
    /// <returns>CertFileData containing certificate information.</returns>
    public CertFileData ParseCertificateFile(string filePath, string? password)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => ParsePfxFile(filePath, password),
            ".pem" => ParsePemFile(filePath),
            ".crt" or ".cer" => ParseCrtOrCerFile(filePath),
            ".der" => ParseDerFile(filePath),
            _ => new CertFileData { FilePath = filePath, ErrorMessage = $"Unsupported file extension: {extension}" }
        };
    }

    /// <summary>
    /// Parses a PFX/P12 file and extracts certificate information.
    /// </summary>
    /// <param name="filePath">Path to the PFX/P12 file.</param>
    /// <param name="password">Password for the file (can be null or empty).</param>
    /// <returns>CertFileData containing certificate information.</returns>
    public CertFileData ParsePfxFile(string filePath, string? password)
    {
        var result = new CertFileData { FilePath = filePath };

        try
        {
            var certificates = new X509Certificate2Collection();
            certificates.Import(filePath, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            foreach (var cert in certificates)
            {
                var certInfo = ExtractCertificateInfo(cert);
                result.CertificateChain.Add(certInfo);
            }

            // The first certificate with a private key is typically the primary certificate
            var primaryCert = certificates.Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey)
                ?? certificates.Cast<X509Certificate2>().FirstOrDefault();

            if (primaryCert != null)
            {
                result.PrimaryCertificate = ExtractCertificateInfo(primaryCert);
            }
        }
        catch (CryptographicException ex) when (ex.HResult == -2147024810) // ERROR_INVALID_PASSWORD
        {
            result.ErrorMessage = "Invalid password. Please try again with the correct password.";
        }
        catch (CryptographicException ex)
        {
            result.ErrorMessage = $"Cryptographic error: {ex.Message}";
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error loading certificate: {ex.Message}";
        }

        return result;
    }


    /// <summary>
    /// Parses a PEM file (Base64 encoded certificate).
    /// </summary>
    private CertFileData ParsePemFile(string filePath)
    {
        var result = new CertFileData { FilePath = filePath };

        try
        {
            var pemContent = File.ReadAllText(filePath);
            
            // Check if PEM contains a private key
            var hasPrivateKey = ContainsPrivateKey(pemContent);
            
            // Try to load certificate with private key if present
            if (hasPrivateKey)
            {
                var certWithKey = LoadCertificateWithPrivateKeyFromPem(pemContent);
                if (certWithKey != null)
                {
                    var certInfo = ExtractCertificateInfo(certWithKey);
                    result.CertificateChain.Add(certInfo);
                    result.PrimaryCertificate = certInfo;
                    return result;
                }
            }
            
            // Fall back to extracting certificates without private key association
            var certificates = ExtractCertificatesFromPem(pemContent);

            if (certificates.Count == 0)
            {
                result.ErrorMessage = "No certificates found in PEM file.";
                return result;
            }

            foreach (var cert in certificates)
            {
                var certInfo = ExtractCertificateInfo(cert);
                result.CertificateChain.Add(certInfo);
            }

            result.PrimaryCertificate = result.CertificateChain.FirstOrDefault();
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error loading PEM file: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Checks if PEM content contains a private key.
    /// </summary>
    private bool ContainsPrivateKey(string pemContent)
    {
        return pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
               pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
               pemContent.Contains("-----BEGIN EC PRIVATE KEY-----") ||
               pemContent.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----");
    }

    /// <summary>
    /// Loads a certificate with its private key from PEM content.
    /// </summary>
    private X509Certificate2? LoadCertificateWithPrivateKeyFromPem(string pemContent)
    {
        try
        {
            // Extract the certificate
            var certRegex = new Regex(
                @"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
                RegexOptions.Singleline);
            var certMatch = certRegex.Match(pemContent);
            if (!certMatch.Success) return null;

            var certBase64 = certMatch.Groups[1].Value.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            var certBytes = Convert.FromBase64String(certBase64);
            var cert = new X509Certificate2(certBytes);

            // Try to extract RSA private key (PKCS#1 format)
            var rsaKeyRegex = new Regex(
                @"-----BEGIN RSA PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END RSA PRIVATE KEY-----",
                RegexOptions.Singleline);
            var rsaKeyMatch = rsaKeyRegex.Match(pemContent);
            if (rsaKeyMatch.Success)
            {
                var keyBase64 = rsaKeyMatch.Groups[1].Value.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                var keyBytes = Convert.FromBase64String(keyBase64);
                
                var rsa = DecodeRsaPrivateKey(keyBytes);
                if (rsa != null)
                {
                    // Combine cert and private key by exporting to PFX and reimporting
                    return CombineCertificateWithKey(cert, rsa);
                }
            }

            // Try PKCS#8 format
            var pkcs8KeyRegex = new Regex(
                @"-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PRIVATE KEY-----",
                RegexOptions.Singleline);
            var pkcs8KeyMatch = pkcs8KeyRegex.Match(pemContent);
            if (pkcs8KeyMatch.Success)
            {
                var keyBase64 = pkcs8KeyMatch.Groups[1].Value.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                var keyBytes = Convert.FromBase64String(keyBase64);
                
                var rsa = DecodePkcs8PrivateKey(keyBytes);
                if (rsa != null)
                {
                    return CombineCertificateWithKey(cert, rsa);
                }
            }

            return cert;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Combines a certificate with an RSA private key.
    /// </summary>
    private X509Certificate2? CombineCertificateWithKey(X509Certificate2 cert, RSACryptoServiceProvider rsa)
    {
        try
        {
            // Export to PFX with the private key and reimport
            var certWithKey = new X509Certificate2(cert.RawData);
            
            // Use CspParameters to create an exportable key
            var cspParams = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore
            };

            // Export cert and key to PFX format, then reimport
            var pfxBytes = ExportToPfx(cert, rsa, string.Empty);
            if (pfxBytes != null)
            {
                return new X509Certificate2(pfxBytes, string.Empty, 
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            }

            return cert;
        }
        catch
        {
            return cert;
        }
    }

    /// <summary>
    /// Exports certificate and private key to PFX format.
    /// </summary>
    private byte[]? ExportToPfx(X509Certificate2 cert, RSACryptoServiceProvider rsa, string password)
    {
        try
        {
            // Create a temporary certificate with the private key
            var tempCert = new X509Certificate2(cert.RawData);
            
            // We need to use a workaround for .NET Framework
            // Create a new RSACryptoServiceProvider and copy the key
            var csp = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            
            var persistentRsa = new RSACryptoServiceProvider(csp);
            persistentRsa.ImportParameters(rsa.ExportParameters(true));
            
            // Set the private key on the certificate
            tempCert.PrivateKey = persistentRsa;
            
            // Export to PFX
            return tempCert.Export(X509ContentType.Pfx, password);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Decodes an RSA private key from PKCS#1 DER format.
    /// </summary>
    private RSACryptoServiceProvider? DecodeRsaPrivateKey(byte[] privateKeyBytes)
    {
        try
        {
            // PKCS#1 RSAPrivateKey structure:
            // RSAPrivateKey ::= SEQUENCE {
            //   version           Version,
            //   modulus           INTEGER,  -- n
            //   publicExponent    INTEGER,  -- e
            //   privateExponent   INTEGER,  -- d
            //   prime1            INTEGER,  -- p
            //   prime2            INTEGER,  -- q
            //   exponent1         INTEGER,  -- d mod (p-1)
            //   exponent2         INTEGER,  -- d mod (q-1)
            //   coefficient       INTEGER,  -- (inverse of q) mod p
            // }

            using (var ms = new MemoryStream(privateKeyBytes))
            using (var reader = new BinaryReader(ms))
            {
                // Read SEQUENCE
                if (reader.ReadByte() != 0x30)
                    return null;

                ReadLength(reader); // sequence length

                // Read version (should be 0)
                if (reader.ReadByte() != 0x02)
                    return null;
                var versionLength = ReadLength(reader);
                reader.ReadBytes(versionLength);

                var rsaParams = new RSAParameters
                {
                    Modulus = ReadInteger(reader),
                    Exponent = ReadInteger(reader),
                    D = ReadInteger(reader),
                    P = ReadInteger(reader),
                    Q = ReadInteger(reader),
                    DP = ReadInteger(reader),
                    DQ = ReadInteger(reader),
                    InverseQ = ReadInteger(reader)
                };

                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParams);
                return rsa;
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Decodes an RSA private key from PKCS#8 DER format.
    /// </summary>
    private RSACryptoServiceProvider? DecodePkcs8PrivateKey(byte[] privateKeyBytes)
    {
        try
        {
            // PKCS#8 PrivateKeyInfo structure:
            // PrivateKeyInfo ::= SEQUENCE {
            //   version         Version,
            //   algorithm       AlgorithmIdentifier,
            //   privateKey      OCTET STRING (contains PKCS#1 RSAPrivateKey)
            // }

            using (var ms = new MemoryStream(privateKeyBytes))
            using (var reader = new BinaryReader(ms))
            {
                // Read outer SEQUENCE
                if (reader.ReadByte() != 0x30)
                    return null;

                ReadLength(reader);

                // Read version
                if (reader.ReadByte() != 0x02)
                    return null;
                var versionLength = ReadLength(reader);
                reader.ReadBytes(versionLength);

                // Read AlgorithmIdentifier SEQUENCE
                if (reader.ReadByte() != 0x30)
                    return null;
                var algLength = ReadLength(reader);
                reader.ReadBytes(algLength);

                // Read OCTET STRING containing the private key
                if (reader.ReadByte() != 0x04)
                    return null;
                var keyLength = ReadLength(reader);
                var pkcs1Key = reader.ReadBytes(keyLength);

                // The OCTET STRING contains a PKCS#1 RSAPrivateKey
                return DecodeRsaPrivateKey(pkcs1Key);
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Reads a DER length value.
    /// </summary>
    private int ReadLength(BinaryReader reader)
    {
        var length = (int)reader.ReadByte();
        if ((length & 0x80) != 0)
        {
            var numBytes = length & 0x7F;
            length = 0;
            for (int i = 0; i < numBytes; i++)
            {
                length = (length << 8) | reader.ReadByte();
            }
        }
        return length;
    }

    /// <summary>
    /// Reads a DER INTEGER value.
    /// </summary>
    private byte[] ReadInteger(BinaryReader reader)
    {
        if (reader.ReadByte() != 0x02)
            throw new InvalidDataException("Expected INTEGER");

        var length = ReadLength(reader);
        var data = reader.ReadBytes(length);

        // Remove leading zero if present (used for positive numbers)
        if (data.Length > 1 && data[0] == 0x00)
        {
            var trimmed = new byte[data.Length - 1];
            Array.Copy(data, 1, trimmed, 0, trimmed.Length);
            return trimmed;
        }

        return data;
    }

    /// <summary>
    /// Parses a CRT or CER file (can be PEM or DER encoded).
    /// </summary>
    private CertFileData ParseCrtOrCerFile(string filePath)
    {
        var result = new CertFileData { FilePath = filePath };

        try
        {
            var fileBytes = File.ReadAllBytes(filePath);

            // Check if it's PEM encoded (starts with "-----BEGIN")
            if (IsPemEncoded(fileBytes))
            {
                return ParsePemFile(filePath);
            }

            // Otherwise treat as DER encoded
            return ParseDerFile(filePath);
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error loading certificate file: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Parses a DER file (binary encoded certificate).
    /// </summary>
    private CertFileData ParseDerFile(string filePath)
    {
        var result = new CertFileData { FilePath = filePath };

        try
        {
            var cert = new X509Certificate2(filePath);
            var certInfo = ExtractCertificateInfo(cert);
            result.CertificateChain.Add(certInfo);
            result.PrimaryCertificate = certInfo;
        }
        catch (CryptographicException ex)
        {
            result.ErrorMessage = $"Cryptographic error: {ex.Message}";
        }
        catch (Exception ex)
        {
            result.ErrorMessage = $"Error loading DER file: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Extracts all certificates from PEM content.
    /// </summary>
    private List<X509Certificate2> ExtractCertificatesFromPem(string pemContent)
    {
        var certificates = new List<X509Certificate2>();
        var certRegex = new Regex(
            @"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----",
            RegexOptions.Singleline);

        var matches = certRegex.Matches(pemContent);
        foreach (Match match in matches)
        {
            try
            {
                var base64 = match.Groups[1].Value.Replace("\r", "").Replace("\n", "").Replace(" ", "");
                var certBytes = Convert.FromBase64String(base64);
                var cert = new X509Certificate2(certBytes);
                certificates.Add(cert);
            }
            catch
            {
                // Skip invalid certificates
            }
        }

        return certificates;
    }

    /// <summary>
    /// Checks if file content is PEM encoded.
    /// </summary>
    private bool IsPemEncoded(byte[] fileBytes)
    {
        if (fileBytes.Length < 11) return false;

        // Check for "-----BEGIN" at the start
        var header = Encoding.ASCII.GetString(fileBytes, 0, Math.Min(20, fileBytes.Length));
        return header.StartsWith("-----BEGIN");
    }

    /// <summary>
    /// Attempts to parse a PFX file without a password.
    /// </summary>
    /// <param name="filePath">Path to the PFX/P12 file.</param>
    /// <returns>True if password is required, false otherwise.</returns>
    public bool RequiresPassword(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        
        // Only PFX/P12 files can have passwords
        if (extension != ".pfx" && extension != ".p12")
        {
            return false;
        }

        try
        {
            var certificates = new X509Certificate2Collection();
            certificates.Import(filePath, string.Empty, X509KeyStorageFlags.DefaultKeySet);
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    private CertificateInfo ExtractCertificateInfo(X509Certificate2 cert)
    {
        var info = new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "Unknown",
            Version = $"V{cert.Version}",
            FriendlyName = cert.FriendlyName ?? string.Empty,
            HasPrivateKey = cert.HasPrivateKey
        };

        // Extract public key information
        try
        {
            var publicKey = cert.PublicKey;
            info.PublicKeyAlgorithm = publicKey.Oid.FriendlyName ?? publicKey.Oid.Value ?? "Unknown";
            info.PublicKeyLength = GetKeyLength(cert);
        }
        catch
        {
            info.PublicKeyAlgorithm = "Unknown";
        }

        // Extract Key Usage
        info.KeyUsage = GetKeyUsage(cert);

        // Extract Enhanced Key Usage
        info.EnhancedKeyUsage = GetEnhancedKeyUsage(cert);

        // Extract Subject Alternative Names
        info.SubjectAlternativeNames = GetSubjectAlternativeNames(cert);

        return info;
    }

    private int GetKeyLength(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return rsa.KeySize;

            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null) return ecdsa.KeySize;

            using var dsa = cert.GetDSAPublicKey();
            if (dsa != null) return dsa.KeySize;

            return 0;
        }
        catch
        {
            return 0;
        }
    }

    private string GetKeyUsage(X509Certificate2 cert)
    {
        var keyUsageExtension = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsageExtension == null) return "Not specified";

        var usages = new List<string>();
        var flags = keyUsageExtension.KeyUsages;

        if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature)) usages.Add("Digital Signature");
        if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation)) usages.Add("Non-Repudiation");
        if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment)) usages.Add("Key Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment)) usages.Add("Data Encipherment");
        if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement)) usages.Add("Key Agreement");
        if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign)) usages.Add("Certificate Signing");
        if (flags.HasFlag(X509KeyUsageFlags.CrlSign)) usages.Add("CRL Signing");
        if (flags.HasFlag(X509KeyUsageFlags.EncipherOnly)) usages.Add("Encipher Only");
        if (flags.HasFlag(X509KeyUsageFlags.DecipherOnly)) usages.Add("Decipher Only");

        return usages.Count > 0 ? string.Join(", ", usages) : "None";
    }

    private string GetEnhancedKeyUsage(X509Certificate2 cert)
    {
        var ekuExtension = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ekuExtension == null) return "Not specified";

        var usages = ekuExtension.EnhancedKeyUsages
            .Cast<Oid>()
            .Select(oid => oid.FriendlyName ?? oid.Value ?? "Unknown")
            .ToList();

        return usages.Count > 0 ? string.Join(", ", usages) : "None";
    }

    private string GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        // OID for Subject Alternative Name is 2.5.29.17
        var sanExtension = cert.Extensions.Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExtension == null) return "Not specified";

        try
        {
            var asnData = new AsnEncodedData(sanExtension.Oid!, sanExtension.RawData);
            return asnData.Format(true);
        }
        catch
        {
            return "Unable to parse";
        }
    }
}
