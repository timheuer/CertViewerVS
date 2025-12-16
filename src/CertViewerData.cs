using CertViewerVS.Models;
using Microsoft.VisualStudio.Extensibility.UI;
using System.Collections.ObjectModel;
using System.Runtime.Serialization;

namespace CertViewerVS;

/// <summary>
/// Represents a single certificate's display data for Remote UI.
/// </summary>
[DataContract]
internal class CertificateDisplayData : NotifyPropertyChangedObject
{
    private string _displayName = string.Empty;
    private string _validityStatus = string.Empty;
    private string _validityColor = "Gray";
    private string _validFrom = string.Empty;
    private string _validTo = string.Empty;
    private string _subject = string.Empty;
    private string _issuer = string.Empty;
    private string _version = string.Empty;
    private string _serialNumber = string.Empty;
    private string _thumbprint = string.Empty;
    private string _signatureAlgorithm = string.Empty;
    private string _publicKey = string.Empty;
    private string _hasPrivateKey = string.Empty;
    private string _hasPrivateKeyColor = "Gray";
    private string _friendlyName = string.Empty;
    private string _keyUsage = string.Empty;
    private string _enhancedKeyUsage = string.Empty;
    private string _subjectAltNames = string.Empty;
    private bool _isExpanded = true;
    private string _certIndex = string.Empty;

    [DataMember]
    public string DisplayName
    {
        get => _displayName;
        set => SetProperty(ref _displayName, value);
    }

    [DataMember]
    public string CertIndex
    {
        get => _certIndex;
        set => SetProperty(ref _certIndex, value);
    }

    [DataMember]
    public string ValidityStatus
    {
        get => _validityStatus;
        set => SetProperty(ref _validityStatus, value);
    }

    [DataMember]
    public string ValidityColor
    {
        get => _validityColor;
        set => SetProperty(ref _validityColor, value);
    }

    [DataMember]
    public string ValidFrom
    {
        get => _validFrom;
        set => SetProperty(ref _validFrom, value);
    }

    [DataMember]
    public string ValidTo
    {
        get => _validTo;
        set => SetProperty(ref _validTo, value);
    }

    [DataMember]
    public string Subject
    {
        get => _subject;
        set => SetProperty(ref _subject, value);
    }

    [DataMember]
    public string Issuer
    {
        get => _issuer;
        set => SetProperty(ref _issuer, value);
    }

    [DataMember]
    public string Version
    {
        get => _version;
        set => SetProperty(ref _version, value);
    }

    [DataMember]
    public string SerialNumber
    {
        get => _serialNumber;
        set => SetProperty(ref _serialNumber, value);
    }

    [DataMember]
    public string Thumbprint
    {
        get => _thumbprint;
        set => SetProperty(ref _thumbprint, value);
    }

    [DataMember]
    public string SignatureAlgorithm
    {
        get => _signatureAlgorithm;
        set => SetProperty(ref _signatureAlgorithm, value);
    }

    [DataMember]
    public string PublicKey
    {
        get => _publicKey;
        set => SetProperty(ref _publicKey, value);
    }

    [DataMember]
    public string HasPrivateKey
    {
        get => _hasPrivateKey;
        set => SetProperty(ref _hasPrivateKey, value);
    }

    [DataMember]
    public string HasPrivateKeyColor
    {
        get => _hasPrivateKeyColor;
        set => SetProperty(ref _hasPrivateKeyColor, value);
    }

    [DataMember]
    public string FriendlyName
    {
        get => _friendlyName;
        set => SetProperty(ref _friendlyName, value);
    }

    [DataMember]
    public string KeyUsage
    {
        get => _keyUsage;
        set => SetProperty(ref _keyUsage, value);
    }

    [DataMember]
    public string EnhancedKeyUsage
    {
        get => _enhancedKeyUsage;
        set => SetProperty(ref _enhancedKeyUsage, value);
    }

    [DataMember]
    public string SubjectAltNames
    {
        get => _subjectAltNames;
        set => SetProperty(ref _subjectAltNames, value);
    }

    [DataMember]
    public bool IsExpanded
    {
        get => _isExpanded;
        set => SetProperty(ref _isExpanded, value);
    }

    public static CertificateDisplayData FromCertInfo(CertificateInfo cert, int index, int totalCount)
    {
        var cn = ExtractCommonName(cert.Subject);
        var displayName = string.IsNullOrEmpty(cn) ? $"Certificate {index + 1}" : cn;
        if (cert.HasPrivateKey)
        {
            displayName = "🔐 " + displayName;
        }
        else
        {
            displayName = "📜 " + displayName;
        }

        return new CertificateDisplayData
        {
            DisplayName = displayName,
            CertIndex = $"Certificate {index + 1} of {totalCount}",
            ValidityStatus = cert.ValidityStatus,
            ValidityColor = cert.IsExpired ? "Red" : cert.IsNotYetValid ? "Orange" : "Green",
            ValidFrom = cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss UTC"),
            ValidTo = cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss UTC"),
            Subject = cert.Subject.Replace(", ", "\n"),
            Issuer = cert.Issuer.Replace(", ", "\n"),
            Version = cert.Version,
            SerialNumber = FormatSerialNumber(cert.SerialNumber),
            Thumbprint = FormatThumbprint(cert.Thumbprint),
            SignatureAlgorithm = cert.SignatureAlgorithm,
            PublicKey = $"{cert.PublicKeyAlgorithm} ({cert.PublicKeyLength} bits)",
            HasPrivateKey = cert.HasPrivateKey ? "Yes ✓" : "No",
            HasPrivateKeyColor = cert.HasPrivateKey ? "Green" : "Gray",
            FriendlyName = string.IsNullOrEmpty(cert.FriendlyName) ? "(Not set)" : cert.FriendlyName,
            KeyUsage = cert.KeyUsage,
            EnhancedKeyUsage = cert.EnhancedKeyUsage,
            SubjectAltNames = cert.SubjectAlternativeNames,
            IsExpanded = totalCount == 1 // Auto-expand if only one certificate
        };
    }

    private static string ExtractCommonName(string subject)
    {
        var parts = subject.Split(',');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed.Substring(3);
            }
        }
        return string.Empty;
    }

    private static string FormatSerialNumber(string serialNumber)
    {
        if (string.IsNullOrEmpty(serialNumber)) return "(Not available)";
        var formatted = new System.Text.StringBuilder();
        for (int i = 0; i < serialNumber.Length; i += 2)
        {
            if (i > 0) formatted.Append(' ');
            formatted.Append(serialNumber.Substring(i, Math.Min(2, serialNumber.Length - i)));
        }
        return formatted.ToString();
    }

    private static string FormatThumbprint(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint)) return "(Not available)";
        var formatted = new System.Text.StringBuilder();
        for (int i = 0; i < thumbprint.Length; i += 2)
        {
            if (i > 0) formatted.Append(':');
            formatted.Append(thumbprint.Substring(i, Math.Min(2, thumbprint.Length - i)));
        }
        return formatted.ToString();
    }
}

/// <summary>
/// Data context for the PFX Viewer tool window Remote UI.
/// </summary>
[DataContract]
internal class CertViewerData : NotifyPropertyChangedObject
{
    private string _fileName = string.Empty;
    private string _errorMessage = string.Empty;
    private bool _hasError;
    private bool _hasData;
    private bool _isLoading;
    private string _loadingMessage = string.Empty;
    private string _certificateCountText = string.Empty;

    [DataMember]
    public string FileName
    {
        get => _fileName;
        set => SetProperty(ref _fileName, value);
    }

    [DataMember]
    public string ErrorMessage
    {
        get => _errorMessage;
        set
        {
            SetProperty(ref _errorMessage, value);
            HasError = !string.IsNullOrEmpty(value);
        }
    }

    [DataMember]
    public bool HasError
    {
        get => _hasError;
        set => SetProperty(ref _hasError, value);
    }

    [DataMember]
    public bool HasData
    {
        get => _hasData;
        set => SetProperty(ref _hasData, value);
    }

    [DataMember]
    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    [DataMember]
    public string LoadingMessage
    {
        get => _loadingMessage;
        set => SetProperty(ref _loadingMessage, value);
    }

    [DataMember]
    public string CertificateCountText
    {
        get => _certificateCountText;
        set => SetProperty(ref _certificateCountText, value);
    }

    [DataMember]
    public ObservableCollection<CertificateDisplayData> Certificates { get; } = new();

    /// <summary>
    /// Sets the loading state with a message.
    /// </summary>
    public void SetLoading(string fileName)
    {
        IsLoading = true;
        LoadingMessage = $"Loading {fileName}...";
        HasData = false;
        HasError = false;
        ErrorMessage = string.Empty;
        Certificates.Clear();
    }

    /// <summary>
    /// Updates the data context from CertFileData.
    /// </summary>
    public void UpdateFrom(CertFileData data)
    {
        IsLoading = false;
        LoadingMessage = string.Empty;
        FileName = data.FileName;
        ErrorMessage = data.ErrorMessage;
        Certificates.Clear();

        if (data.HasError || data.CertificateChain.Count == 0)
        {
            HasData = false;
            return;
        }

        HasData = true;
        var count = data.CertificateChain.Count;
        CertificateCountText = count == 1 
            ? "1 certificate found" 
            : $"{count} certificates found";

        for (int i = 0; i < count; i++)
        {
            var certData = CertificateDisplayData.FromCertInfo(data.CertificateChain[i], i, count);
            Certificates.Add(certData);
        }
    }
}
