using System.ComponentModel.Composition;
using System.IO;
using System.Runtime.InteropServices;
using CertViewerVS.Services;
using CertViewerVS.UI;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace CertViewerVS;

/// <summary>
/// Editor factory for certificate files (PFX, P12, PEM, CRT, DER, CER).
/// This factory intercepts file opens and displays them in the certificate viewer.
/// </summary>
[Guid(EditorFactoryGuid)]
public class CertificateEditorFactory : IVsEditorFactory
{
    public const string EditorFactoryGuid = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890";

    private ServiceProvider? _serviceProvider;
    private readonly CertParserService _parserService = new();

    public int SetSite(Microsoft.VisualStudio.OLE.Interop.IServiceProvider psp)
    {
        _serviceProvider = new ServiceProvider(psp);
        return VSConstants.S_OK;
    }

    public int Close()
    {
        _serviceProvider?.Dispose();
        _serviceProvider = null;
        return VSConstants.S_OK;
    }

    public int MapLogicalView(ref Guid rguidLogicalView, out string? pbstrPhysicalView)
    {
        pbstrPhysicalView = null;

        // Support the primary view
        if (rguidLogicalView == VSConstants.LOGVIEWID_Primary ||
            rguidLogicalView == VSConstants.LOGVIEWID_Any ||
            rguidLogicalView == Guid.Empty)
        {
            return VSConstants.S_OK;
        }

        return VSConstants.E_NOTIMPL;
    }

    public int CreateEditorInstance(
        uint grfCreateDoc,
        string pszMkDocument,
        string pszPhysicalView,
        IVsHierarchy pvHier,
        uint itemid,
        IntPtr punkDocDataExisting,
        out IntPtr ppunkDocView,
        out IntPtr ppunkDocData,
        out string pbstrEditorCaption,
        out Guid pguidCmdUI,
        out int pgrfCDW)
    {
        ppunkDocView = IntPtr.Zero;
        ppunkDocData = IntPtr.Zero;
        pbstrEditorCaption = string.Empty;
        pguidCmdUI = Guid.Empty;
        pgrfCDW = 0;

        // Get the file path and open it in the certificate viewer
        ThreadHelper.JoinableTaskFactory.Run(async () =>
        {
            await OpenCertificateFileAsync(pszMkDocument);
        });

        // Return E_ABORT to tell VS we handled the file ourselves
        // and it shouldn't try to open it in a regular editor
        return VSConstants.E_ABORT;
    }

    private async Task OpenCertificateFileAsync(string filePath)
    {
        try
        {
            // Show the tool window with loading state first
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            
            var shell = _serviceProvider?.GetService(typeof(SVsUIShell)) as IVsUIShell;
            if (shell != null)
            {
                var toolWindowGuid = new Guid("C6E3D26F-1F6A-4BCE-87D2-9E4A8B5C6D7E"); // CertViewerToolWindow GUID
                shell.FindToolWindow((uint)__VSFINDTOOLWIN.FTW_fForceCreate, ref toolWindowGuid, out var frame);
                frame?.Show();
            }

            await CertViewerToolWindow.SetLoadingAsync(Path.GetFileName(filePath), CancellationToken.None);

            // Check if password is required (only for PFX/P12 files)
            string? password = null;
            var extension = Path.GetExtension(filePath).ToLowerInvariant();
            
            if (extension == ".pfx" || extension == ".p12")
            {
                if (_parserService.RequiresPassword(filePath))
                {
                    password = await PromptForPasswordAsync();
                    if (password == null)
                    {
                        return; // User cancelled
                    }
                }
            }

            // Parse the certificate file
            var result = _parserService.ParseCertificateFile(filePath, password);

            // If password was wrong, allow retry
            while (result.HasError && result.ErrorMessage?.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var retry = System.Windows.MessageBox.Show(
                    "The password was incorrect. Would you like to try again?",
                    "Invalid Password",
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Question);

                if (retry != System.Windows.MessageBoxResult.Yes)
                {
                    return;
                }

                password = await PromptForPasswordAsync();
                if (password == null)
                {
                    return;
                }

                result = _parserService.ParseCertificateFile(filePath, password);
            }

            // Display the certificate data (waits for tool window instance to be ready)
            await CertViewerToolWindow.DisplayCertificateDataAsync(result, CancellationToken.None);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                $"Error opening certificate file: {ex.Message}",
                "Certificate Viewer Error",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Error);
        }
    }

    private Task<string?> PromptForPasswordAsync()
    {
        return System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
        {
            var dialog = new PasswordInputDialog();
            return dialog.ShowDialog() == true ? dialog.Password : null;
        }).Task;
    }
}

