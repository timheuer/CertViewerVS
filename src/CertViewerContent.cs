using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.Extensibility.UI;

namespace CertViewerVS;

/// <summary>
/// Remote UI control for displaying PFX certificate information.
/// </summary>
internal class CertViewerContent : RemoteUserControl
{
    private const string XamlResourceName = "CertViewerVS.UI.CertViewerContent.xaml";

    public CertViewerContent(CertViewerData dataContext)
        : base(dataContext)
    {
    }

    /// <inheritdoc />
    public override async Task<string> GetXamlAsync(CancellationToken cancellationToken)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(XamlResourceName);
        
        if (stream == null)
        {
            throw new InvalidOperationException($"Could not find embedded resource: {XamlResourceName}");
        }

        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync();
    }
}
