using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace CertViewerVS.Models;

/// <summary>
/// Represents certificate information extracted from a PFX/P12 file.
/// </summary>
public class CertificateInfo : INotifyPropertyChanged
{
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public string PublicKeyAlgorithm { get; set; } = string.Empty;
    public int PublicKeyLength { get; set; }
    public string Version { get; set; } = string.Empty;
    public string FriendlyName { get; set; } = string.Empty;
    public bool HasPrivateKey { get; set; }
    public string KeyUsage { get; set; } = string.Empty;
    public string EnhancedKeyUsage { get; set; } = string.Empty;
    public string SubjectAlternativeNames { get; set; } = string.Empty;
    public bool IsExpired => DateTime.Now > NotAfter;
    public bool IsNotYetValid => DateTime.Now < NotBefore;
    public string ValidityStatus => IsExpired ? "Expired" : IsNotYetValid ? "Not Yet Valid" : "Valid";

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Represents the complete certificate data from a PFX/P12 file.
/// </summary>
public class CertFileData : INotifyPropertyChanged
{
    private string _filePath = string.Empty;
    private CertificateInfo? _primaryCertificate;
    private string _errorMessage = string.Empty;
    private bool _hasError;

    public string FilePath
    {
        get => _filePath;
        set { _filePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(FileName)); }
    }

    public string FileName => System.IO.Path.GetFileName(FilePath);

    public CertificateInfo? PrimaryCertificate
    {
        get => _primaryCertificate;
        set { _primaryCertificate = value; OnPropertyChanged(); }
    }

    public ObservableCollection<CertificateInfo> CertificateChain { get; } = new();

    public string ErrorMessage
    {
        get => _errorMessage;
        set { _errorMessage = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasError)); }
    }

    public bool HasError
    {
        get => !string.IsNullOrEmpty(_errorMessage);
        set { _hasError = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
