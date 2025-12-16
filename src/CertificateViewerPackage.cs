using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.Shell;

namespace CertViewerVS;

/// <summary>
/// VS Package that registers the CertificateEditorFactory for certificate file extensions.
/// </summary>
[PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
[Guid(PackageGuid)]
[ProvideEditorFactory(typeof(CertificateEditorFactory), 110)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".pfx", 100)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".p12", 100)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".pem", 100)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".crt", 100)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".der", 100)]
[ProvideEditorExtension(typeof(CertificateEditorFactory), ".cer", 100)]
public sealed class CertificateViewerPackage : AsyncPackage
{
    public const string PackageGuid = "B2C3D4E5-F6A7-8901-BCDE-F23456789012";

    private CertificateEditorFactory? _editorFactory;

    protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
        await base.InitializeAsync(cancellationToken, progress);

        await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

        // Register the editor factory
        _editorFactory = new CertificateEditorFactory();
        RegisterEditorFactory(_editorFactory);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _editorFactory = null;
        }
        base.Dispose(disposing);
    }
}
