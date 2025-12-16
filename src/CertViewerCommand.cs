using System.Diagnostics;
using System.IO;
using System.Windows;
using CertViewerVS.Resources;
using CertViewerVS.Services;
using CertViewerVS.UI;
using Microsoft;
using Microsoft.VisualStudio.Extensibility;
using Microsoft.VisualStudio.Extensibility.Commands;
using Microsoft.VisualStudio.Extensibility.Shell;
using Microsoft.Win32;

namespace CertViewerVS;

/// <summary>
/// Command to open and view PFX/P12 certificate files.
/// </summary>
[VisualStudioContribution]
internal class CertViewerCommand : Command
{
    private readonly TraceSource _logger;
    private readonly CertParserService _parserService;

    public CertViewerCommand(TraceSource traceSource)
    {
        _logger = Requires.NotNull(traceSource, nameof(traceSource));
        _parserService = new CertParserService();
    }

    /// <inheritdoc />
    public override CommandConfiguration CommandConfiguration => new("%CertViewerVS.CertViewerCommand.DisplayName%")
    {
        Icon = new(ImageMoniker.KnownValues.Certificate, IconSettings.IconAndText),
        Placements = [CommandPlacement.KnownPlacements.ToolsMenu],
        TooltipText = "%CertViewerVS.CertViewerCommand.TooltipText%",
        Shortcuts = [new CommandShortcutConfiguration(ModifierKey.ControlShift, Key.Q)],
    };

    /// <inheritdoc />
    public override async Task ExecuteCommandAsync(IClientContext context, CancellationToken cancellationToken)
    {
        try
        {
            // Show file open dialog on UI thread
            var filePath = await Application.Current.Dispatcher.InvokeAsync(() =>
            {
                var dialog = new OpenFileDialog
                {
                    Title = Strings.DialogTitle_OpenCertificateFile,
                    Filter = $"{Strings.Filter_CertificateFiles} (*.pfx;*.p12;*.pem;*.crt;*.der;*.cer)|*.pfx;*.p12;*.pem;*.crt;*.der;*.cer|{Strings.Filter_AllFiles} (*.*)|*.*",
                    FilterIndex = 1,
                    Multiselect = false
                };

                return dialog.ShowDialog() == true ? dialog.FileName : null;
            });

            if (string.IsNullOrEmpty(filePath))
            {
                return; // User cancelled
            }

            _logger.TraceInformation($"Opening certificate file: {filePath}");

            // Show the tool window with loading state
            await this.Extensibility.Shell().ShowToolWindowAsync<CertViewerToolWindow>(activate: true, cancellationToken);
            await CertViewerToolWindow.SetLoadingAsync(Path.GetFileName(filePath), cancellationToken);

            // Check if password is required (only for PFX/P12)
            string? password = null;
            if (_parserService.RequiresPassword(filePath))
            {
                password = await PromptForPasswordAsync(cancellationToken);
                if (password == null)
                {
                    return; // User cancelled password prompt
                }
            }

            // Parse the certificate file
            var result = _parserService.ParseCertificateFile(filePath, password);

            // If password was wrong, allow retry
            while (result.HasError && result.ErrorMessage.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var retry = await this.Extensibility.Shell().ShowPromptAsync(
                    Strings.Prompt_IncorrectPasswordRetry,
                    PromptOptions.OKCancel,
                    cancellationToken);

                if (retry != true)
                {
                    return;
                }

                password = await PromptForPasswordAsync(cancellationToken);
                if (password == null)
                {
                    return;
                }

                result = _parserService.ParseCertificateFile(filePath, password);
            }

            // Display the certificate data
            await CertViewerToolWindow.DisplayCertificateDataAsync(result, cancellationToken);

            if (result.HasError)
            {
                _logger.TraceEvent(TraceEventType.Warning, 0, $"Error loading certificate: {result.ErrorMessage}");
            }
            else
            {
                _logger.TraceInformation($"Successfully loaded certificate with {result.CertificateChain.Count} certificate(s)");
            }
        }
        catch (Exception ex)
        {
            _logger.TraceEvent(TraceEventType.Error, 0, $"Error in CertViewerCommand: {ex}");
            await this.Extensibility.Shell().ShowPromptAsync(
                string.Format(Strings.Error_Occurred, ex.Message),
                PromptOptions.OK,
                cancellationToken);
        }
    }

    private async Task<string?> PromptForPasswordAsync(CancellationToken cancellationToken)
    {
        // Use VS extensibility prompt for password input
        // Note: This is a simplified approach - in production you might want a proper password dialog
        var result = await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            var dialog = new PasswordInputDialog();
            return dialog.ShowDialog() == true ? dialog.Password : null;
        });

        return result;
    }
}
