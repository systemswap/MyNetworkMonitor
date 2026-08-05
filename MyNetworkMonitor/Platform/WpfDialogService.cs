using System.Threading.Tasks;
using System.Windows;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>WPF-Implementierung von <see cref="IDialogService"/> über MessageBox (synchron, als Task gekapselt).</summary>
    public sealed class WpfDialogService : IDialogService
    {
        public Task ShowInfoAsync(string message, string title = "Information")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
            return Task.CompletedTask;
        }

        public Task ShowErrorAsync(string message, string title = "Fehler")
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
            return Task.CompletedTask;
        }

        public Task<bool> ConfirmAsync(string message, string title = "Bestätigen")
        {
            bool result = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
            return Task.FromResult(result);
        }
    }
}
