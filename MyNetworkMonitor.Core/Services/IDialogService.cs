namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Plattformunabhängige Abstraktion für einfache Dialoge. Bewusst asynchron,
    /// da moderne UI-Frameworks (Avalonia) Dialoge nur asynchron modal anzeigen;
    /// WPF setzt die synchrone MessageBox trivial als abgeschlossenen Task um.
    /// ViewModels dürfen keine UI-Frameworks direkt referenzieren – sie hängen nur
    /// von diesem Interface ab.
    /// </summary>
    public interface IDialogService
    {
        Task ShowInfoAsync(string message, string title = "Information");

        Task ShowErrorAsync(string message, string title = "Error");

        /// <summary>Ja/Nein-Rückfrage. true = bestätigt.</summary>
        Task<bool> ConfirmAsync(string message, string title = "Please confirm");

        /// <summary>
        /// Ja/Nein/Abbrechen-Rückfrage – gebraucht vom Export, der zwischen
        /// „ganze Tabelle“, „nur Auswahl“ und „doch nicht“ unterscheidet.
        /// </summary>
        Task<YesNoCancel> AskYesNoCancelAsync(string message, string title = "Question");
    }

    public enum YesNoCancel
    {
        Yes,
        No,
        Cancel
    }
}
