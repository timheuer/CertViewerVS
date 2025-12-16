using System.Windows;

namespace CertViewerVS.UI;

/// <summary>
/// Dialog for entering a password for PFX/P12 files.
/// </summary>
public partial class PasswordInputDialog : Window
{
    public string Password => PasswordInput.Password;

    public PasswordInputDialog()
    {
        InitializeComponent();
        PasswordInput.Focus();
    }

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
