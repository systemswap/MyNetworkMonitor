namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformunabhängige Abstraktion für einfache Dialoge (in WPF via MessageBox,
    /// später in Avalonia via eigenem Dialog). ViewModels dürfen keine UI-Frameworks
    /// direkt referenzieren – sie hängen nur von diesem Interface ab.
    /// </summary>
    public interface IDialogService
    {
        void ShowInfo(string message, string title = "Information");

        void ShowError(string message, string title = "Fehler");

        /// <summary>Ja/Nein-Rückfrage. true = bestätigt.</summary>
        bool Confirm(string message, string title = "Bestätigen");
    }
}
