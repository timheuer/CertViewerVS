using CertViewerVS.Models;
using Microsoft.VisualStudio.Extensibility;
using Microsoft.VisualStudio.Extensibility.ToolWindows;
using Microsoft.VisualStudio.RpcContracts.RemoteUI;
using System.Runtime.InteropServices;

namespace CertViewerVS;

/// <summary>
/// Tool window for viewing certificate files (PFX, P12, PEM, CRT, DER, CER).
/// </summary>
[VisualStudioContribution]
[Guid(ToolWindowGuid)]
internal class CertViewerToolWindow : ToolWindow
{
    public const string ToolWindowGuid = "C6E3D26F-1F6A-4BCE-87D2-9E4A8B5C6D7E";
    
    private readonly CertViewerData _dataContext = new();
    private static CertViewerToolWindow? _instance;
    private static TaskCompletionSource<CertViewerToolWindow>? _instanceReady;
    private static readonly object _lock = new();

    public CertViewerToolWindow()
    {
        Title = "Certificate Viewer";
        lock (_lock)
        {
            _instance = this;
            _instanceReady?.TrySetResult(this);
        }
    }

    /// <inheritdoc />
    public override ToolWindowConfiguration ToolWindowConfiguration => new()
    {
        Placement = ToolWindowPlacement.DocumentWell,
        AllowAutoCreation = true,
    };

    /// <inheritdoc />
    public override Task<IRemoteUserControl> GetContentAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult<IRemoteUserControl>(new CertViewerContent(_dataContext));
    }

    /// <summary>
    /// Sets the loading state in the tool window.
    /// Waits for the tool window instance to be ready if needed.
    /// </summary>
    /// <param name="fileName">The name of the file being loaded.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task SetLoadingAsync(string fileName, CancellationToken cancellationToken)
    {
        var instance = await GetInstanceAsync(cancellationToken);
        instance._dataContext.SetLoading(fileName);
    }

    /// <summary>
    /// Displays certificate data in the tool window.
    /// Waits for the tool window instance to be ready if needed.
    /// </summary>
    /// <param name="data">The certificate data to display.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task DisplayCertificateDataAsync(CertFileData data, CancellationToken cancellationToken)
    {
        var instance = await GetInstanceAsync(cancellationToken);
        instance._dataContext.UpdateFrom(data);
    }

    private static async Task<CertViewerToolWindow> GetInstanceAsync(CancellationToken cancellationToken)
    {
        TaskCompletionSource<CertViewerToolWindow>? tcs = null;
        
        lock (_lock)
        {
            if (_instance != null)
            {
                return _instance;
            }
            
            _instanceReady ??= new TaskCompletionSource<CertViewerToolWindow>();
            tcs = _instanceReady;
        }

        using var registration = cancellationToken.Register(() => tcs.TrySetCanceled());
        return await tcs.Task;
    }
}
