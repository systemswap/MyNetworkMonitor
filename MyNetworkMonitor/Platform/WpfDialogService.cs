using System.Windows;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>WPF-Implementierung von <see cref="IDialogService"/> über MessageBox.</summary>
    public sealed class WpfDialogService : IDialogService
    {
        public void ShowInfo(string message, string title = "Information")
            => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);

        public void ShowError(string message, string title = "Fehler")
            => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);

        public bool Confirm(string message, string title = "Bestätigen")
            => MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
    }
}
